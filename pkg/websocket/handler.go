package websocket

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	gorilla "github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
)

// ═══════════════════════════════════════════════════════════════
// GLOBALS
// ═══════════════════════════════════════════════════════════════
var (
	upgrader = gorilla.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	// connections maps username → active WebSocket connection.
	// Protected by mu (RWMutex) — readers hold RLock, writers hold Lock.
	connections = make(map[string]*gorilla.Conn)
	mu          sync.RWMutex
	// dbMu serialises writes to prevent race conditions on INSERT.
	dbMu sync.Mutex
	db   *sql.DB
)

// ═══════════════════════════════════════════════════════════════
// DATABASE INIT
// ═══════════════════════════════════════════════════════════════
func InitDB() {
	log.Println("Initializing database...")
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://audit_db_dyhx_user:UKaGYfaMuffMA4Pu9JZoToFAxlzlzQc9@dpg-d69h9qjnv86c73eug1tg-a.oregon-postgres.render.com:5432/audit_db_dyhx?sslmode=require"
	}
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(3 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	log.Println("Connecting to PostgreSQL (up to 30s)...")
	if err = db.PingContext(ctx); err != nil {
		log.Fatal("Failed to ping database:", err)
	}
	schema := `
CREATE TABLE IF NOT EXISTS users (
id SERIAL PRIMARY KEY,
username VARCHAR(255) UNIQUE NOT NULL,
email VARCHAR(255) UNIQUE NOT NULL,
full_name VARCHAR(255) NOT NULL,
password_hash VARCHAR(255) NOT NULL,
created_at TIMESTAMP DEFAULT NOW(),
last_login TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
id SERIAL PRIMARY KEY,
target VARCHAR(255) NOT NULL,
sender VARCHAR(255) NOT NULL,
message TEXT NOT NULL,
reply_to INTEGER DEFAULT NULL,
timestamp TIMESTAMP DEFAULT NOW(),
delivered BOOLEAN DEFAULT FALSE,
read BOOLEAN DEFAULT FALSE,
FOREIGN KEY (target) REFERENCES users(username) ON DELETE CASCADE,
FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
FOREIGN KEY (reply_to) REFERENCES notifications(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS feedback (
id SERIAL PRIMARY KEY,
username VARCHAR(255) NOT NULL,
subject VARCHAR(255) NOT NULL,
message TEXT NOT NULL,
type VARCHAR(50) NOT NULL,
status VARCHAR(50) DEFAULT 'pending',
timestamp TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS password_resets (
id SERIAL PRIMARY KEY,
email VARCHAR(255) NOT NULL,
token_hash VARCHAR(255) UNIQUE NOT NULL,
expires_at TIMESTAMP NOT NULL,
used BOOLEAN DEFAULT FALSE,
created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notif_target ON notifications(target, delivered);
CREATE INDEX IF NOT EXISTS idx_users_uname ON users(username);
CREATE INDEX IF NOT EXISTS idx_notif_reply ON notifications(reply_to);
CREATE INDEX IF NOT EXISTS idx_reset_token ON password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_reset_email ON password_resets(email);
`
	if _, err = db.Exec(schema); err != nil {
		log.Fatal("Failed to create tables:", err)
	}
	log.Println("PostgreSQL initialized successfully")
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
func hashPassword(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

// hashToken hashes a raw reset token for safe DB storage.
func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// generateToken creates a cryptographically secure 32-byte random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func userExists(username string) bool {
	var ok bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", username).Scan(&ok)
	return ok
}

// isAdmin enforces backend role check — not just a frontend flag.
func isAdmin(r *http.Request) bool {
	return r.Header.Get("X-Admin-User") == "admin"
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-User")
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// deliver sends a JSON payload to a connected user via WebSocket.
// Returns true only if the message was written successfully.
func deliver(username string, payload map[string]interface{}) bool {
	mu.RLock()
	conn, ok := connections[username]
	mu.RUnlock()
	if !ok {
		return false
	}
	b, _ := json.Marshal(payload)
	return conn.WriteMessage(gorilla.TextMessage, b) == nil
}

// queue persists an undelivered notification so the user receives it on next connect.
func queue(target, sender, message string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db.Exec("INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3)", target, sender, message)
}

// getEnv returns the env value or falls back to the provided default.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ═══════════════════════════════════════════════════════════════
// EMAIL
// Required env vars: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
// Optional: SMTP_FROM, APP_URL
// ═══════════════════════════════════════════════════════════════
// sendEmail sends HTML email via SMTP with proper error handling.
// For Mailtrap: SMTP_FROM must end in @demomailtrap.com (their shared sending domain).
// For Gmail/others: SMTP_FROM can be any verified sender address.
func sendEmail(to, subject, htmlBody string) error {
	host := getEnv("SMTP_HOST", "")
	port := getEnv("SMTP_PORT", "587")
	user := getEnv("SMTP_USER", "")
	pass := getEnv("SMTP_PASS", "")
	from := getEnv("SMTP_FROM", "")

	if host == "" || user == "" || pass == "" || from == "" {
		log.Printf("SMTP not configured properly — email skipped")
		return nil
	}

	// Basic header injection protection
	if strings.Contains(to, "\n") || strings.Contains(subject, "\n") {
		return fmt.Errorf("invalid email headers")
	}

	msg := fmt.Sprintf(
		"From: Nexus Audit <%s>\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, htmlBody,
	)

	auth := smtp.PlainAuth("", user, pass, host)
	addr := host + ":" + port

	err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("SMTP error: %v", err)
		return err
	}

	log.Printf("Email sent successfully to %s", to)
	return nil
}

func buildResetEmail(resetURL string, expiresAt time.Time) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:32px 16px;font-family:'Segoe UI',Arial,sans-serif;background:#0f1923;color:#e8f0fe">
  <div style="max-width:500px;margin:0 auto;background:#1a2535;border-radius:16px;padding:40px;border:1px solid #243050">
    <div style="margin-bottom:28px">
      <div style="display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;background:linear-gradient(135deg,#1eb8d0,#2563c4);border-radius:12px;margin-bottom:16px">
        <span style="font-size:24px">🔐</span>
      </div>
      <h1 style="margin:0 0 8px;font-size:1.4rem;color:#e8f0fe;font-weight:700">Password Reset</h1>
      <p style="margin:0;color:#8fa3c8;font-size:.9375rem;line-height:1.6">
        You requested a password reset for your Nexus Audit account.
      </p>
    </div>
    <div style="margin-bottom:28px">
      <p style="margin:0 0 20px;color:#a0b4cc;font-size:.875rem;line-height:1.6">
        Click the button below to choose a new password. This link expires at
        <strong style="color:#1eb8d0">%s UTC</strong>.
      </p>
      <a href="%s"
         style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#1eb8d0,#2563c4);
                color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:.9375rem;
                letter-spacing:-.01em">
        Reset My Password
      </a>
    </div>
    <div style="font-size:.8rem;color:#5a7096;border-top:1px solid #243050;padding-top:20px;line-height:1.6">
      If you did not request this, you can safely ignore this email — your password will not change.<br><br>
      This link will expire in <strong>1 hour</strong> and can only be used once.
    </div>
  </div>
</body>
</html>`, expiresAt.Format("2006-01-02 15:04"), resetURL)
}

func buildWelcomeEmail(fullName, appURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
</head>
<body style="margin:0;padding:32px 16px;font-family:'Segoe UI',Arial,sans-serif;background:#0f1923;color:#e8f0fe">
  <div style="max-width:500px;margin:0 auto;background:#1a2535;border-radius:16px;padding:40px;border:1px solid #243050">
    <div style="margin-bottom:28px">
      <div style="display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;background:linear-gradient(135deg,#1eb8d0,#2563c4);border-radius:12px;margin-bottom:16px">
        <span style="font-size:24px">🚀</span>
      </div>
      <h1 style="margin:0 0 8px;font-size:1.4rem;font-weight:700">Welcome to Nexus Audit</h1>
      <p style="margin:0;color:#8fa3c8;font-size:.9375rem;line-height:1.6">
        Hello %s,<br><br>
        Your account has been successfully created.
        You can now securely access your dashboard.
      </p>
    </div>

    <a href="%s"
       style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#1eb8d0,#2563c4);
              color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:.9375rem;">
        Access Dashboard
    </a>

    <div style="margin-top:30px;font-size:.8rem;color:#5a7096;border-top:1px solid #243050;padding-top:20px">
      If you did not create this account, please ignore this email.
    </div>
  </div>
</body>
</html>`, fullName, appURL)
}

// ═══════════════════════════════════════════════════════════════
// AUTH — REGISTER
// ═══════════════════════════════════════════════════════════════
type registerReq struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	Password  string `json:"password"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FullName = strings.TrimSpace(req.FullName)
	if req.Username == "" || req.Email == "" || req.FullName == "" || req.Password == "" {
		jsonErr(w, 400, "All fields required")
		return
	}
	if len(req.Password) < 6 {
		jsonErr(w, 400, "Password must be at least 6 characters")
		return
	}
	if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
		jsonErr(w, 400, "Invalid email address")
		return
	}
	var id int
	dbMu.Lock()
	err := db.QueryRow(
		"INSERT INTO users(username,email,full_name,password_hash) VALUES($1,$2,$3,$4) RETURNING id",
		req.Username, req.Email, req.FullName, hashPassword(req.Password),
	).Scan(&id)
	dbMu.Unlock()
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			if strings.Contains(err.Error(), "username") {
				jsonErr(w, 409, "Username already exists")
				return
			}
			jsonErr(w, 409, "Email already registered")
			return
		}
		log.Printf("Register error: %v", err)
		jsonErr(w, 500, "Registration failed")
		return
	}
	go func(email, fullName string) {
		appURL := getEnv("APP_URL", "https://audit-notification.onrender.com")
		err := sendEmail(
			email,
			"Welcome to Nexus Audit",
			buildWelcomeEmail(fullName, appURL),
		)
		if err != nil {
			log.Printf("Failed to send welcome email to %s: %v", email, err)
		}
	}(req.Email, req.FullName)
	log.Printf("Registered: %s", req.Username)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Registration successful",
		"user": map[string]interface{}{
			"id":        id,
			"username":  req.Username,
			"email":     req.Email,
			"full_name": req.FullName,
		},
	})
}

// ═══════════════════════════════════════════════════════════════
// AUTH — LOGIN
// ═══════════════════════════════════════════════════════════════
type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "Username and password required")
		return
	}
	var (
		id           int
		email        string
		fullName     string
		passwordHash string
		createdAt    time.Time
		lastLogin    sql.NullTime
	)
	err := db.QueryRow(
		"SELECT id,email,full_name,password_hash,created_at,last_login FROM users WHERE username=$1",
		req.Username,
	).Scan(&id, &email, &fullName, &passwordHash, &createdAt, &lastLogin)
	// Constant-time comparison: never reveal whether user exists vs wrong password
	if err != nil || hashPassword(req.Password) != passwordHash {
		jsonErr(w, 401, "Invalid username or password")
		return
	}
	db.Exec("UPDATE users SET last_login=$1 WHERE id=$2", time.Now(), id)
	log.Printf("Login: %s", req.Username)
	jsonOK(w, map[string]interface{}{
		"success": true,
		"message": "Login successful",
		"user": map[string]interface{}{
			"id":         id,
			"username":   req.Username,
			"email":      email,
			"full_name":  fullName,
			"created_at": createdAt,
		},
	})
}

// ═══════════════════════════════════════════════════════════════
// AUTH — FORGOT PASSWORD
// Sends a secure, expiring, single-use reset link via email.
// Always returns 200 to prevent email enumeration attacks.
// ═══════════════════════════════════════════════════════════════
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" {
		jsonErr(w, 400, "Email is required")
		return
	}
	// Respond immediately — do the work in background to prevent timing attacks
	jsonOK(w, map[string]string{
		"message": "If that email is registered, a password reset link has been sent.",
	})
	go func() {
		// Check if user exists
		var username string
		err := db.QueryRow("SELECT username FROM users WHERE email=$1", email).Scan(&username)
		if err != nil {
			return // User not found — silently exit
		}
		// Generate a secure random token
		token, err := generateToken()
		if err != nil {
			log.Printf("Token generation failed: %v", err)
			return
		}
		tokenHash := hashToken(token)
		expiresAt := time.Now().UTC().Add(time.Hour)
		// Invalidate any existing unused tokens for this email
		db.Exec("UPDATE password_resets SET used=TRUE WHERE email=$1 AND used=FALSE", email)
		// Store hashed token (never store raw token)
		dbMu.Lock()
		_, insertErr := db.Exec(
			"INSERT INTO password_resets(email,token_hash,expires_at) VALUES($1,$2,$3)",
			email, tokenHash, expiresAt,
		)
		dbMu.Unlock()
		if insertErr != nil {
			log.Printf("Failed to store reset token: %v", insertErr)
			return
		}
		appURL := getEnv("APP_URL", "https://audit-notification.onrender.com")
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", appURL, token)
		if err := sendEmail(email, "Reset your Nexus Audit password", buildResetEmail(resetURL, expiresAt)); err != nil {
			log.Printf("Failed to send reset email to %s: %v", email, err)
		}
	}()
}

// ═══════════════════════════════════════════════════════════════
// AUTH — RESET PASSWORD
// Validates token, updates password, marks token used.
// ═══════════════════════════════════════════════════════════════
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	if body.Token == "" || body.Password == "" {
		jsonErr(w, 400, "Token and new password are required")
		return
	}
	if len(body.Password) < 6 {
		jsonErr(w, 400, "Password must be at least 6 characters")
		return
	}
	tokenHash := hashToken(body.Token)
	var (
		resetID   int
		email     string
		expiresAt time.Time
		used      bool
	)
	err := db.QueryRow(
		"SELECT id,email,expires_at,used FROM password_resets WHERE token_hash=$1",
		tokenHash,
	).Scan(&resetID, &email, &expiresAt, &used)
	switch {
	case err == sql.ErrNoRows:
		jsonErr(w, 400, "Invalid or expired reset link")
		return
	case err != nil:
		log.Printf("Reset token lookup error: %v", err)
		jsonErr(w, 500, "Server error")
		return
	case used:
		jsonErr(w, 400, "This reset link has already been used")
		return
	case time.Now().UTC().After(expiresAt):
		jsonErr(w, 400, "This reset link has expired. Please request a new one.")
		return
	}
	// Update password and consume token atomically
	dbMu.Lock()
	defer dbMu.Unlock()
	if _, err = db.Exec(
		"UPDATE users SET password_hash=$1 WHERE email=$2",
		hashPassword(body.Password), email,
	); err != nil {
		log.Printf("Password update error: %v", err)
		jsonErr(w, 500, "Failed to update password")
		return
	}
	db.Exec("UPDATE password_resets SET used=TRUE WHERE id=$1", resetID)
	log.Printf("Password reset complete for email: %s", email)
	jsonOK(w, map[string]string{"message": "Password updated successfully. You can now log in."})
}

// ═══════════════════════════════════════════════════════════════
// WEBSOCKET
// FIX: connections map is the authoritative source of online status.
// Users are added on connect (mu.Lock) and removed on disconnect (mu.Lock).
// The ping/pong mechanism detects dead connections within 70s.
// ═══════════════════════════════════════════════════════════════
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		jsonErr(w, 400, "Missing user parameter")
		return
	}
	if !userExists(username) {
		jsonErr(w, 401, "User not registered")
		return
	}
	// Reject duplicate connections — check-then-set under write lock
	mu.Lock()
	if _, already := connections[username]; already {
		mu.Unlock()
		jsonErr(w, 409, "User already connected")
		return
	}
	mu.Unlock()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	// Register under write lock — this is what makes the user "Online"
	mu.Lock()
	connections[username] = conn
	onlineCount := len(connections)
	mu.Unlock()
	log.Printf("WS connected: %s (%d online)", username, onlineCount)
	// Deregister under write lock on any exit path — this makes the user "Offline"
	defer func() {
		mu.Lock()
		delete(connections, username)
		offlineCount := len(connections)
		mu.Unlock()
		conn.Close()
		log.Printf("WS disconnected: %s (%d online)", username, offlineCount)
	}()
	// 70s read deadline, reset on every pong — detects dead connections
	conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})
	// Ping goroutine — keeps connection alive, detects dropouts
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteControl(gorilla.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	// Deliver any notifications queued while user was offline
	sendQueued(conn, username)
	// Read loop — messages are echo'd back (keep-alive compatibility)
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if gorilla.IsUnexpectedCloseError(err, gorilla.CloseGoingAway, gorilla.CloseNormalClosure) {
				log.Printf("WS unexpected close for %s: %v", username, err)
			}
			return
		}
		conn.WriteMessage(msgType, msg)
	}
}

func sendQueued(conn *gorilla.Conn, username string) {
	rows, err := db.Query(
		`SELECT id, sender, message, reply_to
 FROM notifications
 WHERE target=$1 AND delivered=FALSE
 ORDER BY timestamp ASC`,
		username,
	)
	if err != nil {
		return
	}
	defer rows.Close()
	type queued struct {
		id      int64
		sender  string
		message string
		replyTo sql.NullInt64
	}
	var items []queued
	for rows.Next() {
		var q queued
		if rows.Scan(&q.id, &q.sender, &q.message, &q.replyTo) == nil {
			items = append(items, q)
		}
	}
	for _, it := range items {
		p := map[string]interface{}{
			"id":       it.id,
			"message":  it.message,
			"sender":   it.sender,
			"canReply": !it.replyTo.Valid,
			"isReply":  it.replyTo.Valid,
		}
		if it.replyTo.Valid {
			p["replyTo"] = it.replyTo.Int64
		}
		b, _ := json.Marshal(p)
		if conn.WriteMessage(gorilla.TextMessage, b) != nil {
			break
		}
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", it.id)
	}
	if len(items) > 0 {
		log.Printf("Delivered %d queued notifications to %s", len(items), username)
	}
}

// ═══════════════════════════════════════════════════════════════
// AUDIT
// ═══════════════════════════════════════════════════════════════
type auditReq struct {
	TargetUser string `json:"targetUser"`
	Requester  string `json:"requester"`
	Details    string `json:"details"`
}

func AuditHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req auditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	req.TargetUser = strings.TrimSpace(req.TargetUser)
	req.Requester = strings.TrimSpace(req.Requester)
	req.Details = strings.TrimSpace(req.Details)
	if req.TargetUser == "" || req.Requester == "" || req.Details == "" {
		jsonErr(w, 400, "All fields required")
		return
	}
	if !userExists(req.TargetUser) {
		jsonErr(w, 400, "Target user not found")
		return
	}
	msg := fmt.Sprintf("@%s: %s", req.Requester, req.Details)
	var nid int64
	dbMu.Lock()
	db.QueryRow(
		"INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3) RETURNING id",
		req.TargetUser, req.Requester, msg,
	).Scan(&nid)
	dbMu.Unlock()
	sent := deliver(req.TargetUser, map[string]interface{}{
		"id":       nid,
		"message":  msg,
		"sender":   req.Requester,
		"canReply": true,
	})
	if sent {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", nid)
	}
	status := "queued"
	if sent {
		status = "delivered"
	}
	log.Printf("Audit %s->%s (%s)", req.Requester, req.TargetUser, status)
	jsonOK(w, map[string]string{"status": status, "message": "Notification sent successfully"})
}

// ═══════════════════════════════════════════════════════════════
// REPLY
// ═══════════════════════════════════════════════════════════════
type replyReq struct {
	NotificationID  int64  `json:"notificationId"`
	ReplyMessage    string `json:"replyMessage"`
	ReplierUsername string `json:"replierUsername"`
}

func ReplyHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req replyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	if req.NotificationID == 0 || req.ReplyMessage == "" || req.ReplierUsername == "" {
		jsonErr(w, 400, "Missing required fields")
		return
	}
	// Find the original sender to route the reply to them
	var origSender string
	if err := db.QueryRow(
		"SELECT sender FROM notifications WHERE id=$1", req.NotificationID,
	).Scan(&origSender); err != nil {
		jsonErr(w, 404, "Notification not found")
		return
	}
	msg := fmt.Sprintf("@%s replied: %s", req.ReplierUsername, req.ReplyMessage)
	var rid int64
	dbMu.Lock()
	db.QueryRow(
		"INSERT INTO notifications(target,sender,message,reply_to) VALUES($1,$2,$3,$4) RETURNING id",
		origSender, req.ReplierUsername, msg, req.NotificationID,
	).Scan(&rid)
	dbMu.Unlock()
	sent := deliver(origSender, map[string]interface{}{
		"id":      rid,
		"message": msg,
		"sender":  req.ReplierUsername,
		"replyTo": req.NotificationID,
		"isReply": true,
	})
	if sent {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", rid)
	}
	log.Printf("Reply %s->%s", req.ReplierUsername, origSender)
	jsonOK(w, map[string]string{"status": "sent", "message": "Reply sent"})
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST
// ═══════════════════════════════════════════════════════════════
type broadcastReq struct {
	Message    string `json:"message"`
	Sender     string `json:"sender"`
	TargetType string `json:"targetType"`
}

func BroadcastHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req broadcastReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	if req.Message == "" || req.Sender == "" || req.TargetType == "" {
		jsonErr(w, 400, "Missing required fields")
		return
	}
	if req.Sender != "admin" {
		jsonErr(w, 403, "Only admin can broadcast")
		return
	}
	msg := fmt.Sprintf("[Broadcast] @%s: %s", req.Sender, req.Message)
	delivered, queued := 0, 0
	if req.TargetType == "online" {
		mu.RLock()
		for username, conn := range connections {
			if username == req.Sender {
				continue
			}
			b, _ := json.Marshal(map[string]interface{}{
				"id":        time.Now().UnixNano(),
				"message":   msg,
				"sender":    req.Sender,
				"canReply":  false,
				"broadcast": true,
			})
			if conn.WriteMessage(gorilla.TextMessage, b) == nil {
				delivered++
			}
		}
		mu.RUnlock()
	} else {
		rows, err := db.Query("SELECT username FROM users WHERE username!=$1", req.Sender)
		if err != nil {
			jsonErr(w, 500, "Database error")
			return
		}
		defer rows.Close()
		var allUsers []string
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				allUsers = append(allUsers, u)
			}
		}
		for _, u := range allUsers {
			ok := deliver(u, map[string]interface{}{
				"id":        time.Now().UnixNano(),
				"message":   msg,
				"sender":    req.Sender,
				"canReply":  false,
				"broadcast": true,
			})
			if ok {
				delivered++
			} else {
				queue(u, req.Sender, msg)
				queued++
			}
		}
	}
	log.Printf("Broadcast: %d delivered, %d queued", delivered, queued)
	jsonOK(w, map[string]interface{}{
		"status":    "sent",
		"delivered": delivered,
		"queued":    queued,
		"message":   fmt.Sprintf("Sent to %d users, queued for %d offline", delivered, queued),
	})
}

// ═══════════════════════════════════════════════════════════════
// FEEDBACK
// ═══════════════════════════════════════════════════════════════
type feedbackReq struct {
	Username string `json:"username"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	Type     string `json:"type"`
}

func FeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	var req feedbackReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	if req.Username == "" || req.Subject == "" || req.Message == "" || req.Type == "" {
		jsonErr(w, 400, "All fields required")
		return
	}
	dbMu.Lock()
	db.Exec("INSERT INTO feedback(username,subject,message,type) VALUES($1,$2,$3,$4)",
		req.Username, req.Subject, req.Message, req.Type)
	dbMu.Unlock()
	adminMsg := fmt.Sprintf("[%s] @%s: %s", strings.ToUpper(req.Type), req.Username, req.Subject)
	var nid int64
	dbMu.Lock()
	db.QueryRow(
		"INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3) RETURNING id",
		"admin", req.Username, adminMsg,
	).Scan(&nid)
	dbMu.Unlock()
	if deliver("admin", map[string]interface{}{
		"id":       nid,
		"message":  adminMsg,
		"sender":   req.Username,
		"canReply": true,
		"feedback": true,
	}) {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", nid)
	}
	log.Printf("Feedback from %s", req.Username)
	jsonOK(w, map[string]string{"status": "sent", "message": "Feedback submitted successfully"})
}

// ═══════════════════════════════════════════════════════════════
// ONLINE USERS
// FIX: Reads directly from the connections map — always accurate.
// Total user count is backend-gated to admin only.
// ═══════════════════════════════════════════════════════════════
func OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")
	// Read online users from the authoritative in-memory map
	mu.RLock()
	list := make([]string, 0, len(connections))
	for u := range connections {
		list = append(list, u)
	}
	mu.RUnlock()
	resp := map[string]interface{}{
		"online": list,
		"count":  len(list),
	}
	// Only expose total registered count to admin — backend enforced
	if isAdmin(r) {
		var total int
		db.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)
		resp["total"] = total
	}
	json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════
// SEARCH
// ═══════════════════════════════════════════════════════════════
func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	rows, err := db.Query(
		"SELECT username,full_name FROM users WHERE username ILIKE $1 OR full_name ILIKE $1 LIMIT 10",
		"%"+q+"%",
	)
	if err != nil {
		jsonErr(w, 500, "Search failed")
		return
	}
	defer rows.Close()
	var results []map[string]string
	for rows.Next() {
		var username, fullName string
		if rows.Scan(&username, &fullName) == nil {
			results = append(results, map[string]string{"username": username, "fullName": fullName})
		}
	}
	if results == nil {
		results = []map[string]string{}
	}
	json.NewEncoder(w).Encode(results)
}

// ═══════════════════════════════════════════════════════════════
// ADMIN — GET ALL USERS
// FIX: online field now populated from connections map, not DB.
// ═══════════════════════════════════════════════════════════════
func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if !isAdmin(r) {
		jsonErr(w, 403, "Admin access required")
		return
	}
	rows, err := db.Query(
		"SELECT id,username,email,full_name,created_at,last_login FROM users ORDER BY created_at DESC",
	)
	if err != nil {
		jsonErr(w, 500, "Database error")
		return
	}
	defer rows.Close()
	// Snapshot the online set once under read lock
	mu.RLock()
	onlineSet := make(map[string]bool, len(connections))
	for u := range connections {
		onlineSet[u] = true
	}
	mu.RUnlock()
	type userRow struct {
		ID        int        `json:"id"`
		Username  string     `json:"username"`
		Email     string     `json:"email"`
		FullName  string     `json:"full_name"`
		CreatedAt time.Time  `json:"created_at"`
		LastLogin *time.Time `json:"last_login"`
		Online    bool       `json:"online"` // ← populated from live connections map
	}
	var users []userRow
	for rows.Next() {
		var u userRow
		var ll sql.NullTime
		if rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.CreatedAt, &ll) == nil {
			if ll.Valid {
				u.LastLogin = &ll.Time
			}
			u.Online = onlineSet[u.Username]
			users = append(users, u)
		}
	}
	if users == nil {
		users = []userRow{}
	}
	jsonOK(w, map[string]interface{}{"success": true, "users": users})
}

// ═══════════════════════════════════════════════════════════════
// ADMIN — FEEDBACK
// ═══════════════════════════════════════════════════════════════
func GetFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if !isAdmin(r) {
		jsonErr(w, 403, "Admin access required")
		return
	}
	fbType := r.URL.Query().Get("type")
	var rows *sql.Rows
	var err error
	if fbType != "" && fbType != "all" {
		rows, err = db.Query(
			"SELECT id,username,subject,message,type,status,timestamp FROM feedback WHERE type=$1 ORDER BY timestamp DESC",
			fbType)
	} else {
		rows, err = db.Query(
			"SELECT id,username,subject,message,type,status,timestamp FROM feedback ORDER BY timestamp DESC")
	}
	if err != nil {
		jsonErr(w, 500, "Database error")
		return
	}
	defer rows.Close()
	type fbRow struct {
		ID        int       `json:"id"`
		Username  string    `json:"username"`
		Subject   string    `json:"subject"`
		Message   string    `json:"message"`
		Type      string    `json:"type"`
		Status    string    `json:"status"`
		Timestamp time.Time `json:"timestamp"`
	}
	var items []fbRow
	for rows.Next() {
		var f fbRow
		if rows.Scan(&f.ID, &f.Username, &f.Subject, &f.Message, &f.Type, &f.Status, &f.Timestamp) == nil {
			items = append(items, f)
		}
	}
	if items == nil {
		items = []fbRow{}
	}
	jsonOK(w, map[string]interface{}{"success": true, "feedback": items})
}

func UpdateFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	if !isAdmin(r) {
		jsonErr(w, 403, "Admin access required")
		return
	}
	var body struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}
	dbMu.Lock()
	db.Exec("UPDATE feedback SET status=$1 WHERE id=$2", body.Status, body.ID)
	dbMu.Unlock()
	jsonOK(w, map[string]string{"status": "updated"})
}

// ═══════════════════════════════════════════════════════════════
// ADMIN — SYSTEM STATS (backend-enforced admin-only)
// ═══════════════════════════════════════════════════════════════
func SystemStatsHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !isAdmin(r) {
		jsonErr(w, 403, "Admin access required")
		return
	}
	var totalUsers, totalAudits, totalFeedback, pendingFeedback, newToday int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	db.QueryRow("SELECT COUNT(*) FROM notifications").Scan(&totalAudits)
	db.QueryRow("SELECT COUNT(*) FROM feedback").Scan(&totalFeedback)
	db.QueryRow("SELECT COUNT(*) FROM feedback WHERE status='pending'").Scan(&pendingFeedback)
	db.QueryRow("SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE").Scan(&newToday)
	mu.RLock()
	online := len(connections)
	mu.RUnlock()
	jsonOK(w, map[string]interface{}{
		"total_users":       totalUsers,
		"online_users":      online,
		"new_today":         newToday,
		"total_audits":      totalAudits,
		"total_feedback":    totalFeedback,
		"pending_feedback":  pendingFeedback,
	})
}

// ═══════════════════════════════════════════════════════════════
// IMPORT USERS
// Excel column layout (0-indexed):
// 0 = First_name
// 1 = Last_name
// 2 = Gitea_Username → stored as username
// 3 = Nickname → IGNORED
// 4 = Floor → stored in response for unregistered users
// 5 = WhatsApp → stored in response for unregistered users
// 6 = Email → used as account email if present & valid
// 7 = Notes → IGNORED
// ═══════════════════════════════════════════════════════════════
type unregisteredUser struct {
	Name     string `json:"name"`
	Floor    string `json:"floor"`
	WhatsApp string `json:"phone"`
}

func ImportUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "Method not allowed")
		return
	}
	if r.URL.Query().Get("admin") != "admin" {
		jsonErr(w, 403, "Admin only")
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		jsonErr(w, 400, "File too large (max 10MB)")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, 400, "No file attached")
		return
	}
	defer file.Close()
	f, err := excelize.OpenReader(file)
	if err != nil {
		jsonErr(w, 400, "Invalid Excel file")
		return
	}
	defer f.Close()
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		jsonErr(w, 400, "No sheets found in file")
		return
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		jsonErr(w, 500, "Failed to read worksheet")
		return
	}
	imported, skipped := 0, 0
	var unregistered []unregisteredUser
	for i, row := range rows {
		if i == 0 {
			continue
		} // Skip header row
		// Safe cell reader — returns "" for missing columns
		cell := func(idx int) string {
			if idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}
		firstName := cell(0)
		lastName := cell(1)
		username := cell(2)
		// cell(3) = Nickname — explicitly ignored
		floor := cell(4)
		whatsapp := cell(5)
		email := cell(6)
		// cell(7) = Notes — explicitly ignored
		fullName := strings.TrimSpace(firstName + " " + lastName)
		// Skip completely empty rows
		if firstName == "" && lastName == "" && username == "" {
			continue
		}
		// No Gitea username → unregistered, collect for WhatsApp panel
		if username == "" {
			if fullName != "" {
				unregistered = append(unregistered, unregisteredUser{
					Name:     fullName,
					Floor:    floor,
					WhatsApp: whatsapp,
				})
			}
			skipped++
			continue
		}
		// Skip if already registered
		var exists bool
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", username).Scan(&exists)
		if exists {
			skipped++
			continue
		}
		// Build valid email
		if email == "" || !strings.Contains(email, "@") {
			email = fmt.Sprintf("%s@local.system", strings.ToLower(username))
		}
		email = strings.ToLower(email)
		// Avoid email collision from a different user
		var emailTaken bool
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&emailTaken)
		if emailTaken {
			email = fmt.Sprintf("%s@local.system", strings.ToLower(username))
		}
		dbMu.Lock()
		_, insertErr := db.Exec(
			"INSERT INTO users(username,email,full_name,password_hash) VALUES($1,$2,$3,$4)",
			username, email, fullName, hashPassword("changeme123"),
		)
		dbMu.Unlock()
		if insertErr != nil {
			log.Printf("Import skip %s: %v", username, insertErr)
			skipped++
			continue
		}
		imported++
	}
	if unregistered == nil {
		unregistered = []unregisteredUser{}
	}
	log.Printf("Import complete: %d imported, %d skipped, %d unregistered", imported, skipped, len(unregistered))
	jsonOK(w, map[string]interface{}{
		"success":       true,
		"imported":      imported,
		"skipped":        skipped,
		"unregistered":  unregistered,
	})
}