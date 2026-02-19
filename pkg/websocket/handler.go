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
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

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

	// passcodeLimiter tracks failed passcode attempts (username → timestamps).
	// Max 5 attempts per hour. Auto-cleanup runs every 10 minutes.
	passcodeLimiter = make(map[string][]time.Time)
	limiterMu       sync.RWMutex
)

const (
	bcryptCost           = 12  // bcrypt work factor
	maxPasscodeAttempts  = 5   // max attempts per hour
	passcodeCooldown     = time.Hour
)

// ═══════════════════════════════════════════════════════════════
// DATABASE INIT
// ═══════════════════════════════════════════════════════════════

func InitDB() {
	log.Println("🔧 Initializing database...")

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://audit_db_dyhx_user:UKaGYfaMuffMA4Pu9JZoToFAxlzlzQc9@dpg-d69h9qjnv86c73eug1tg-a.oregon-postgres.render.com:5432/audit_db_dyhx?sslmode=require"
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("❌ Failed to open database:", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(3 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("📡 Connecting to PostgreSQL (up to 30s)...")
	if err = db.PingContext(ctx); err != nil {
		log.Fatal("❌ Failed to ping database:", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id                   SERIAL PRIMARY KEY,
		username             VARCHAR(255) UNIQUE NOT NULL,
		email                VARCHAR(255) UNIQUE NOT NULL,
		full_name            VARCHAR(255) NOT NULL,
		password_hash        VARCHAR(255) NOT NULL,
		reset_passcode_hash  VARCHAR(255),
		created_at           TIMESTAMP DEFAULT NOW(),
		last_login           TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS notifications (
		id          SERIAL PRIMARY KEY,
		target      VARCHAR(255) NOT NULL,
		sender      VARCHAR(255) NOT NULL,
		message     TEXT NOT NULL,
		reply_to    INTEGER DEFAULT NULL,
		timestamp   TIMESTAMP DEFAULT NOW(),
		delivered   BOOLEAN DEFAULT FALSE,
		read        BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (target)   REFERENCES users(username) ON DELETE CASCADE,
		FOREIGN KEY (sender)   REFERENCES users(username) ON DELETE CASCADE,
		FOREIGN KEY (reply_to) REFERENCES notifications(id) ON DELETE SET NULL
	);
	CREATE TABLE IF NOT EXISTS feedback (
		id        SERIAL PRIMARY KEY,
		username  VARCHAR(255) NOT NULL,
		subject   VARCHAR(255) NOT NULL,
		message   TEXT NOT NULL,
		type      VARCHAR(50)  NOT NULL,
		status    VARCHAR(50)  DEFAULT 'pending',
		timestamp TIMESTAMP    DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS password_resets (
		id         SERIAL PRIMARY KEY,
		email      VARCHAR(255) NOT NULL,
		token_hash VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP   NOT NULL,
		used       BOOLEAN     DEFAULT FALSE,
		created_at TIMESTAMP   DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS imported_users (
		id                 SERIAL PRIMARY KEY,
		first_name         VARCHAR(255) NOT NULL,
		last_name          VARCHAR(255) NOT NULL,
		gitea_username     VARCHAR(255) UNIQUE NOT NULL,
		floor              VARCHAR(100),
		whatsapp           VARCHAR(50),
		email              VARCHAR(255),
		imported_at        TIMESTAMP DEFAULT NOW(),
		is_registered      BOOLEAN DEFAULT FALSE,
		registered_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
	);
	CREATE INDEX IF NOT EXISTS idx_notif_target     ON notifications(target, delivered);
	CREATE INDEX IF NOT EXISTS idx_users_uname      ON users(username);
	CREATE INDEX IF NOT EXISTS idx_notif_reply      ON notifications(reply_to);
	CREATE INDEX IF NOT EXISTS idx_reset_token      ON password_resets(token_hash);
	CREATE INDEX IF NOT EXISTS idx_reset_email      ON password_resets(email);
	CREATE INDEX IF NOT EXISTS idx_users_passcode   ON users(reset_passcode_hash);
	CREATE INDEX IF NOT EXISTS idx_imported_gitea   ON imported_users(gitea_username);
	CREATE INDEX IF NOT EXISTS idx_imported_reg     ON imported_users(is_registered);
	`

	if _, err = db.Exec(schema); err != nil {
		log.Fatal("❌ Failed to create tables:", err)
	}

	log.Println("✅ PostgreSQL initialized successfully")

	// Start cleanup goroutines
	go cleanupRateLimiter()
	go monitorSystem()
}

// monitorSystem provides health checks and prevents memory leaks
func monitorSystem() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mu.RLock()
		connCount := len(connections)
		mu.RUnlock()

		limiterMu.RLock()
		limiterCount := len(passcodeLimiter)
		limiterMu.RUnlock()

		log.Printf("🔍 Health Check — WebSocket connections: %d, Rate limiter entries: %d", connCount, limiterCount)
	}
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

// hashPasswordBcrypt hashes a password using bcrypt cost 12.
func hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPasswordBcrypt checks if a password matches its bcrypt hash.
func verifyPasswordBcrypt(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// hashPasswordSHA256 (legacy) — used for detecting old passwords.
func hashPasswordSHA256(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

// isSHA256Hash detects if a hash is SHA256 (64 hex chars).
func isSHA256Hash(hash string) bool {
	return len(hash) == 64 && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hash)
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
// ENHANCED: Better error logging for notification tracking.
func deliver(username string, payload map[string]interface{}) bool {
	mu.RLock()
	conn, ok := connections[username]
	mu.RUnlock()
	
	if !ok {
		return false
	}
	
	b, _ := json.Marshal(payload)
	err := conn.WriteMessage(gorilla.TextMessage, b)
	
	if err != nil {
		// Connection dead but not yet cleaned up — mark as queued
		log.Printf("⚠️ Failed to deliver notification to %s: %v", username, err)
		return false
	}
	
	log.Printf("✅ Delivered notification ID %v to %s", payload["id"], username)
	return true
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
// RATE LIMITING
// Tracks passcode verification attempts. Max 5 per hour per username.
// Auto-cleanup runs every 10 minutes to prevent memory bloat.
// ═══════════════════════════════════════════════════════════════

func recordPasscodeAttempt(username string) {
	limiterMu.Lock()
	defer limiterMu.Unlock()

	now := time.Now()
	attempts := passcodeLimiter[username]

	// Filter out attempts older than 1 hour
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < passcodeCooldown {
			recent = append(recent, t)
		}
	}

	recent = append(recent, now)
	passcodeLimiter[username] = recent
}

func isRateLimited(username string) bool {
	limiterMu.RLock()
	defer limiterMu.RUnlock()

	attempts := passcodeLimiter[username]
	now := time.Now()

	var count int
	for _, t := range attempts {
		if now.Sub(t) < passcodeCooldown {
			count++
		}
	}

	return count >= maxPasscodeAttempts
}

func cleanupRateLimiter() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		limiterMu.Lock()
		now := time.Now()
		for username, attempts := range passcodeLimiter {
			var recent []time.Time
			for _, t := range attempts {
				if now.Sub(t) < passcodeCooldown {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(passcodeLimiter, username)
			} else {
				passcodeLimiter[username] = recent
			}
		}
		limiterMu.Unlock()
		log.Println("🧹 Rate limiter cleanup completed")
	}
}

// ═══════════════════════════════════════════════════════════════
// AUTH — REGISTER
// Now includes optional 6-digit recovery passcode (bcrypt hashed).
// ═══════════════════════════════════════════════════════════════

type registerReq struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	FullName       string `json:"full_name"`
	Password       string `json:"password"`
	ResetPasscode  string `json:"reset_passcode"` // 6 digits, optional
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
	req.ResetPasscode = strings.TrimSpace(req.ResetPasscode)

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

	// Validate recovery passcode (must be exactly 6 digits if provided)
	if req.ResetPasscode != "" {
		if !regexp.MustCompile(`^\d{6}$`).MatchString(req.ResetPasscode) {
			jsonErr(w, 400, "Recovery passcode must be exactly 6 digits")
			return
		}
	}

	// Hash password with bcrypt
	passwordHash, err := hashPasswordBcrypt(req.Password)
	if err != nil {
		log.Printf("❌ Bcrypt error: %v", err)
		jsonErr(w, 500, "Password hashing failed")
		return
	}

	// Hash passcode with bcrypt (if provided)
	var passcodeHash sql.NullString
	if req.ResetPasscode != "" {
		hash, err := hashPasswordBcrypt(req.ResetPasscode)
		if err != nil {
			log.Printf("❌ Passcode bcrypt error: %v", err)
			jsonErr(w, 500, "Passcode hashing failed")
			return
		}
		passcodeHash = sql.NullString{String: hash, Valid: true}
	}

	var id int
	dbMu.Lock()
	err = db.QueryRow(
		"INSERT INTO users(username,email,full_name,password_hash,reset_passcode_hash) VALUES($1,$2,$3,$4,$5) RETURNING id",
		req.Username, req.Email, req.FullName, passwordHash, passcodeHash,
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
		log.Printf("❌ Register error: %v", err)
		jsonErr(w, 500, "Registration failed")
		return
	}

	// Auto-sync imported_users table if this username was imported
	go func() {
		db.Exec(`
			UPDATE imported_users 
			SET is_registered = TRUE, registered_user_id = $1 
			WHERE gitea_username = $2 AND is_registered = FALSE
		`, id, req.Username)
	}()

	log.Printf("✅ Registered: %s", req.Username)
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
// Auto-migrates SHA256 passwords to bcrypt on successful login.
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

	if err != nil {
		jsonErr(w, 401, "Invalid username or password")
		return
	}

	// Check if password is SHA256 (legacy) or bcrypt
	var passwordValid bool
	var needsMigration bool

	if isSHA256Hash(passwordHash) {
		// Legacy SHA256 password
		if hashPasswordSHA256(req.Password) == passwordHash {
			passwordValid = true
			needsMigration = true
		}
	} else {
		// Bcrypt password
		passwordValid = verifyPasswordBcrypt(req.Password, passwordHash)
	}

	if !passwordValid {
		jsonErr(w, 401, "Invalid username or password")
		return
	}

	// Auto-migrate SHA256 → bcrypt on successful login
	if needsMigration {
		newHash, err := hashPasswordBcrypt(req.Password)
		if err == nil {
			go db.Exec("UPDATE users SET password_hash=$1 WHERE id=$2", newHash, id)
			log.Printf("🔄 Auto-migrated password to bcrypt for user: %s", req.Username)
		}
	}

	db.Exec("UPDATE users SET last_login=$1 WHERE id=$2", time.Now(), id)
	log.Printf("✅ Login: %s", req.Username)

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
// AUTH — VERIFY PASSCODE (Step 1 of passcode-based reset)
// Validates username + 6-digit passcode, returns short-lived token.
// Rate limited: max 5 attempts per hour per username.
// ═══════════════════════════════════════════════════════════════

func VerifyPasscodeHandler(w http.ResponseWriter, r *http.Request) {
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
		Username string `json:"username"`
		Passcode string `json:"passcode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}

	body.Username = strings.TrimSpace(body.Username)
	body.Passcode = strings.TrimSpace(body.Passcode)

	if body.Username == "" || body.Passcode == "" {
		jsonErr(w, 400, "Username and passcode required")
		return
	}

	if !regexp.MustCompile(`^\d{6}$`).MatchString(body.Passcode) {
		jsonErr(w, 400, "Passcode must be 6 digits")
		return
	}

	// Rate limiting check
	if isRateLimited(body.Username) {
		jsonErr(w, 429, "Too many attempts. Please try again in 1 hour.")
		return
	}

	// Fetch user
	var (
		userID        int
		email         string
		passcodeHash  sql.NullString
	)

	err := db.QueryRow(
		"SELECT id, email, reset_passcode_hash FROM users WHERE username=$1",
		body.Username,
	).Scan(&userID, &email, &passcodeHash)

	if err != nil {
		recordPasscodeAttempt(body.Username)
		jsonErr(w, 401, "Invalid username or passcode")
		return
	}

	if !passcodeHash.Valid || passcodeHash.String == "" {
		recordPasscodeAttempt(body.Username)
		jsonErr(w, 401, "No recovery passcode set for this account")
		return
	}

	// Verify passcode (constant-time via bcrypt)
	if !verifyPasswordBcrypt(body.Passcode, passcodeHash.String) {
		recordPasscodeAttempt(body.Username)
		jsonErr(w, 401, "Invalid username or passcode")
		return
	}

	// Generate short-lived token (15 minutes)
	token, err := generateToken()
	if err != nil {
		log.Printf("❌ Token generation failed: %v", err)
		jsonErr(w, 500, "Server error")
		return
	}

	tokenHash := hashToken(token)
	expiresAt := time.Now().UTC().Add(15 * time.Minute)

	// Invalidate old tokens for this email
	db.Exec("UPDATE password_resets SET used=TRUE WHERE email=$1 AND used=FALSE", email)

	// Store token
	dbMu.Lock()
	_, insertErr := db.Exec(
		"INSERT INTO password_resets(email,token_hash,expires_at) VALUES($1,$2,$3)",
		email, tokenHash, expiresAt,
	)
	dbMu.Unlock()

	if insertErr != nil {
		log.Printf("❌ Failed to store passcode token: %v", insertErr)
		jsonErr(w, 500, "Server error")
		return
	}

	log.Printf("✅ Passcode verified for user: %s", body.Username)

	jsonOK(w, map[string]interface{}{
		"success": true,
		"token":   token,
		"message": "Passcode verified. You can now reset your password.",
	})
}

// ═══════════════════════════════════════════════════════════════
// AUTH — RESET PASSWORD VIA PASSCODE (Step 2)
// Uses the token from VerifyPasscodeHandler to update password.
// ═══════════════════════════════════════════════════════════════

func ResetPasswordPasscodeHandler(w http.ResponseWriter, r *http.Request) {
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
		jsonErr(w, 400, "Token and new password required")
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
		jsonErr(w, 400, "Invalid or expired token")
		return
	case err != nil:
		log.Printf("❌ Token lookup error: %v", err)
		jsonErr(w, 500, "Server error")
		return
	case used:
		jsonErr(w, 400, "This token has already been used")
		return
	case time.Now().UTC().After(expiresAt):
		jsonErr(w, 400, "This token has expired")
		return
	}

	// Hash new password with bcrypt
	newHash, err := hashPasswordBcrypt(body.Password)
	if err != nil {
		log.Printf("❌ Bcrypt error: %v", err)
		jsonErr(w, 500, "Password hashing failed")
		return
	}

	// Update password and mark token used
	dbMu.Lock()
	defer dbMu.Unlock()

	if _, err = db.Exec("UPDATE users SET password_hash=$1 WHERE email=$2", newHash, email); err != nil {
		log.Printf("❌ Password update error: %v", err)
		jsonErr(w, 500, "Failed to update password")
		return
	}

	db.Exec("UPDATE password_resets SET used=TRUE WHERE id=$1", resetID)

	log.Printf("✅ Password reset via passcode complete for: %s", email)
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
		log.Printf("❌ WebSocket upgrade failed: %v", err)
		return
	}

	// Register under write lock — this is what makes the user "Online"
	mu.Lock()
	connections[username] = conn
	onlineCount := len(connections)
	mu.Unlock()
	log.Printf("🔌 WS connected: %s (%d online)", username, onlineCount)

	// Deregister under write lock on any exit path — this makes the user "Offline"
	defer func() {
		mu.Lock()
		delete(connections, username)
		offlineCount := len(connections)
		mu.Unlock()
		conn.Close()
		log.Printf("🔌 WS disconnected: %s (%d online)", username, offlineCount)
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
				log.Printf("⚠️ WS unexpected close for %s: %v", username, err)
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
		log.Printf("📬 Delivered %d queued notifications to %s", len(items), username)
	}
}

// ═══════════════════════════════════════════════════════════════
// SYNC NOTIFICATIONS (NEW - FIX FOR ISSUE #1)
// Polling fallback for idle tabs. Returns undelivered notifications.
// ═══════════════════════════════════════════════════════════════

func SyncNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	username := r.URL.Query().Get("user")
	if username == "" || !userExists(username) {
		jsonErr(w, 400, "Invalid user")
		return
	}

	// Return all undelivered notifications for this user
	rows, err := db.Query(`
		SELECT id, sender, message, reply_to, timestamp
		FROM notifications
		WHERE target=$1 AND delivered=FALSE
		ORDER BY timestamp ASC
		LIMIT 50
	`, username)

	if err != nil {
		jsonErr(w, 500, "Database error")
		return
	}
	defer rows.Close()

	type notif struct {
		ID       int64     `json:"id"`
		Sender   string    `json:"sender"`
		Message  string    `json:"message"`
		ReplyTo  *int64    `json:"replyTo"`
		Time     time.Time `json:"timestamp"`
	}

	var items []notif
	for rows.Next() {
		var n notif
		var replyTo sql.NullInt64
		if rows.Scan(&n.ID, &n.Sender, &n.Message, &replyTo, &n.Time) == nil {
			if replyTo.Valid {
				n.ReplyTo = &replyTo.Int64
			}
			items = append(items, n)
		}
	}

	if items == nil {
		items = []notif{}
	}

	jsonOK(w, map[string]interface{}{
		"notifications": items,
		"count":         len(items),
	})
}

// ═══════════════════════════════════════════════════════════════
// MARK DELIVERED (NEW - FIX FOR ISSUE #1)
// Marks notifications as delivered after sync fetch.
// ═══════════════════════════════════════════════════════════════

func MarkDeliveredHandler(w http.ResponseWriter, r *http.Request) {
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
		IDs  []int64 `json:"ids"`
		User string  `json:"user"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON")
		return
	}

	if len(body.IDs) == 0 || body.User == "" {
		jsonErr(w, 400, "Missing required fields")
		return
	}

	// Build query with placeholders
	for _, id := range body.IDs {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1 AND target=$2", id, body.User)
	}

	log.Printf("✅ Marked %d notifications as delivered for %s", len(body.IDs), body.User)
	jsonOK(w, map[string]string{"status": "ok"})
}

// ═══════════════════════════════════════════════════════════════
// AUDIT
// Enhanced to check imported_users table for unregistered users.
// Returns WhatsApp info if user is unregistered but in import list.
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

	// Check if user is registered
	if !userExists(req.TargetUser) {
		// Check if in imported_users (unregistered but in Excel)
		var firstName, lastName, floor, whatsapp string
		err := db.QueryRow(`
			SELECT first_name, last_name, floor, whatsapp
			FROM imported_users
			WHERE gitea_username = $1 AND is_registered = FALSE
		`, req.TargetUser).Scan(&firstName, &lastName, &floor, &whatsapp)

		if err == nil {
			// User is in Excel but not registered
			fullName := strings.TrimSpace(firstName + " " + lastName)

			// Build WhatsApp URL
			phone := strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, whatsapp)

			var waURL string
			if phone != "" {
				senderName := "Admin"
				// Try to get requester's full name
				var reqFullName string
				db.QueryRow("SELECT full_name FROM users WHERE username=$1", req.Requester).Scan(&reqFullName)
				if reqFullName != "" {
					senderName = reqFullName
				}

				locationInfo := ""
				if floor != "" {
					locationInfo = fmt.Sprintf(" (%s)", floor)
				}

				waText := fmt.Sprintf(
					"Hi %s%s,\n\n"+
						"This is %s reaching out from Nexus Audit.\n\n"+
						"You have been requested for an audit. Please register on the Nexus Audit platform to receive real-time notifications:\n"+
						"https://audit-notification.onrender.com\n\n"+
						"Your registration details:\n"+
						"- Use your Gitea username: %s\n\n"+
						"Please confirm receipt of this message.\n\n"+
						"Thank you.",
					fullName, locationInfo, senderName, req.TargetUser,
				)

				waURL = fmt.Sprintf("https://wa.me/%s?text=%s", phone, strings.ReplaceAll(waText, " ", "%20"))
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "user_not_registered",
				"user_info": map[string]string{
					"name":         fullName,
					"floor":        floor,
					"phone":        whatsapp,
					"whatsapp_url": waURL,
				},
			})
			return
		}

		// Not in Excel at all
		jsonErr(w, 404, "Target user not found")
		return
	}

	// User is registered → send audit normally
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

	log.Printf("📤 Audit %s->%s (%s)", req.Requester, req.TargetUser, status)
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

	log.Printf("↩️ Reply %s->%s", req.ReplierUsername, origSender)
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

	log.Printf("📡 Broadcast: %d delivered, %d queued", delivered, queued)
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

	log.Printf("📝 Feedback from %s", req.Username)
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
// Enhanced to return BOTH registered AND unregistered users.
// Unregistered users come from imported_users table.
// ═══════════════════════════════════════════════════════════════

func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	type searchResult struct {
		Username string `json:"username"`
		FullName string `json:"fullName"`
		Status   string `json:"status"` // "registered" or "unregistered"
		Floor    string `json:"floor,omitempty"`
		WhatsApp string `json:"whatsapp,omitempty"`
	}

	var results []searchResult

	// Search registered users
	rows, err := db.Query(
		"SELECT username, full_name FROM users WHERE username ILIKE $1 OR full_name ILIKE $1 LIMIT 10",
		"%"+q+"%",
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var username, fullName string
			if rows.Scan(&username, &fullName) == nil {
				results = append(results, searchResult{
					Username: username,
					FullName: fullName,
					Status:   "registered",
				})
			}
		}
	}

	// Search unregistered users (imported but not registered)
	rows2, err2 := db.Query(`
		SELECT gitea_username, first_name || ' ' || last_name as full_name, floor, whatsapp
		FROM imported_users
		WHERE is_registered = FALSE
		  AND (gitea_username ILIKE $1 OR first_name || ' ' || last_name ILIKE $1)
		LIMIT 5
	`, "%"+q+"%")

	if err2 == nil {
		defer rows2.Close()
		for rows2.Next() {
			var username, fullName string
			var floor, whatsapp sql.NullString
			if rows2.Scan(&username, &fullName, &floor, &whatsapp) == nil {
				result := searchResult{
					Username: username,
					FullName: fullName,
					Status:   "unregistered",
				}
				if floor.Valid {
					result.Floor = floor.String
				}
				if whatsapp.Valid {
					result.WhatsApp = whatsapp.String
				}
				results = append(results, result)
			}
		}
	}

	if results == nil {
		results = []searchResult{}
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
		"total_users":      totalUsers,
		"online_users":     online,
		"new_today":        newToday,
		"total_audits":     totalAudits,
		"total_feedback":   totalFeedback,
		"pending_feedback": pendingFeedback,
	})
}

// ═══════════════════════════════════════════════════════════════
// IMPORT USERS
// Enhanced to store ALL users in imported_users table.
// Auto-syncs is_registered when user signs up.
// Excel column layout (0-indexed):
//   0 = First_name
//   1 = Last_name
//   2 = Gitea_Username → stored as username
//   3 = Nickname → IGNORED
//   4 = Floor
//   5 = WhatsApp
//   6 = Email → used as account email if present & valid
//   7 = Notes → IGNORED
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
			continue // Skip header row
		}

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

		// Store in imported_users table (upsert)
		dbMu.Lock()
		db.Exec(`
			INSERT INTO imported_users (first_name, last_name, gitea_username, floor, whatsapp, email)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (gitea_username) DO UPDATE SET
				first_name = EXCLUDED.first_name,
				last_name = EXCLUDED.last_name,
				floor = EXCLUDED.floor,
				whatsapp = EXCLUDED.whatsapp,
				email = EXCLUDED.email,
				imported_at = NOW()
		`, firstName, lastName, username, floor, whatsapp, email)
		dbMu.Unlock()

		// Check if already registered
		var userID int
		var exists bool
		err := db.QueryRow("SELECT id FROM users WHERE username=$1", username).Scan(&userID)
		exists = (err == nil)

		if exists {
			// Mark as registered in imported_users
			db.Exec(`
				UPDATE imported_users
				SET is_registered = TRUE, registered_user_id = $1
				WHERE gitea_username = $2
			`, userID, username)
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

		// Create user account with bcrypt
		passwordHash, err := hashPasswordBcrypt("changeme123")
		if err != nil {
			log.Printf("❌ Bcrypt error for %s: %v", username, err)
			skipped++
			continue
		}

		dbMu.Lock()
		var newUserID int
		insertErr := db.QueryRow(
			"INSERT INTO users(username,email,full_name,password_hash) VALUES($1,$2,$3,$4) RETURNING id",
			username, email, fullName, passwordHash,
		).Scan(&newUserID)
		dbMu.Unlock()

		if insertErr != nil {
			log.Printf("❌ Import skip %s: %v", username, insertErr)
			skipped++
			continue
		}

		// Mark as registered in imported_users
		db.Exec(`
			UPDATE imported_users
			SET is_registered = TRUE, registered_user_id = $1
			WHERE gitea_username = $2
		`, newUserID, username)

		imported++
	}

	if unregistered == nil {
		unregistered = []unregisteredUser{}
	}

	log.Printf("📊 Import complete: %d imported, %d skipped, %d unregistered", imported, skipped, len(unregistered))
	jsonOK(w, map[string]interface{}{
		"success":      true,
		"imported":     imported,
		"skipped":      skipped,
		"unregistered": unregistered,
	})
}
