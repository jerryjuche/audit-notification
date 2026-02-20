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
	bcryptCost          = 12 // bcrypt work factor
	maxPasscodeAttempts = 5  // max attempts per hour
	passcodeCooldown    = time.Hour
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

	// ── MIGRATIONS ────────────────────────────────────────────────
	// FIX: Add whatsapp column to users table if it doesn't exist.
	// This enriches registered users with contact info from imported_users.
	runMigrations()

	log.Println("✅ PostgreSQL initialized successfully")

	// Start cleanup goroutines
	go cleanupRateLimiter()
	go monitorSystem()
	go startDeliveryRetry()
}

// runMigrations applies any schema changes needed for new features.
// All migrations are idempotent — safe to run on every startup.
func runMigrations() {
	migrations := []struct {
		name string
		sql  string
	}{
		{
			name: "add_whatsapp_to_users",
			sql:  `ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp VARCHAR(50)`,
		},
		{
			name: "add_floor_to_users",
			sql:  `ALTER TABLE users ADD COLUMN IF NOT EXISTS floor VARCHAR(100)`,
		},
	}

	for _, m := range migrations {
		if _, err := db.Exec(m.sql); err != nil {
			log.Printf("⚠️ Migration '%s' warning: %v", m.name, err)
		} else {
			log.Printf("✅ Migration '%s' applied", m.name)
		}
	}

	// Backfill: sync floor + whatsapp from imported_users into users table
	// for any users who registered after being imported.
	_, err := db.Exec(`
		UPDATE users u
		SET 
			floor    = COALESCE(u.floor,    i.floor),
			whatsapp = COALESCE(u.whatsapp, i.whatsapp)
		FROM imported_users i
		WHERE i.gitea_username = u.username
		  AND (u.floor IS NULL OR u.whatsapp IS NULL)
		  AND (i.floor IS NOT NULL OR i.whatsapp IS NOT NULL)
	`)
	if err != nil {
		log.Printf("⚠️ Backfill migration warning: %v", err)
	} else {
		log.Println("✅ Backfill floor/whatsapp from imported_users complete")
	}
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

func hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPasswordBcrypt(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func hashPasswordSHA256(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

func isSHA256Hash(hash string) bool {
	return len(hash) == 64 && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hash)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

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
		log.Printf("⚠️ Failed to deliver notification to %s: %v", username, err)
		return false
	}

	log.Printf("✅ Delivered notification ID %v to %s", payload["id"], username)
	return true
}

func queue(target, sender, message string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db.Exec("INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3)", target, sender, message)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════════════════════════

func recordPasscodeAttempt(username string) {
	limiterMu.Lock()
	defer limiterMu.Unlock()

	now := time.Now()
	attempts := passcodeLimiter[username]

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
// ═══════════════════════════════════════════════════════════════

type registerReq struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	FullName      string `json:"full_name"`
	Password      string `json:"password"`
	ResetPasscode string `json:"reset_passcode"`
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

	if req.ResetPasscode != "" {
		if !regexp.MustCompile(`^\d{6}$`).MatchString(req.ResetPasscode) {
			jsonErr(w, 400, "Recovery passcode must be exactly 6 digits")
			return
		}
	}

	passwordHash, err := hashPasswordBcrypt(req.Password)
	if err != nil {
		log.Printf("❌ Bcrypt error: %v", err)
		jsonErr(w, 500, "Password hashing failed")
		return
	}

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

	// Auto-sync: pull floor + whatsapp from imported_users into users table on registration
	go func() {
		db.Exec(`
			UPDATE imported_users 
			SET is_registered = TRUE, registered_user_id = $1 
			WHERE gitea_username = $2 AND is_registered = FALSE
		`, id, req.Username)

		// Backfill contact info from imported_users into the new user record
		db.Exec(`
			UPDATE users u
			SET 
				floor    = COALESCE(u.floor,    i.floor),
				whatsapp = COALESCE(u.whatsapp, i.whatsapp)
			FROM imported_users i
			WHERE i.gitea_username = u.username
			  AND u.username = $1
		`, req.Username)
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

	var passwordValid bool
	var needsMigration bool

	if isSHA256Hash(passwordHash) {
		if hashPasswordSHA256(req.Password) == passwordHash {
			passwordValid = true
			needsMigration = true
		}
	} else {
		passwordValid = verifyPasswordBcrypt(req.Password, passwordHash)
	}

	if !passwordValid {
		jsonErr(w, 401, "Invalid username or password")
		return
	}

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
// AUTH — VERIFY PASSCODE
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

	if isRateLimited(body.Username) {
		jsonErr(w, 429, "Too many attempts. Please try again in 1 hour.")
		return
	}

	var (
		userID       int
		email        string
		passcodeHash sql.NullString
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

	if !verifyPasswordBcrypt(body.Passcode, passcodeHash.String) {
		recordPasscodeAttempt(body.Username)
		jsonErr(w, 401, "Invalid username or passcode")
		return
	}

	token, err := generateToken()
	if err != nil {
		log.Printf("❌ Token generation failed: %v", err)
		jsonErr(w, 500, "Server error")
		return
	}

	tokenHash := hashToken(token)
	expiresAt := time.Now().UTC().Add(15 * time.Minute)

	db.Exec("UPDATE password_resets SET used=TRUE WHERE email=$1 AND used=FALSE", email)

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
// AUTH — RESET PASSWORD VIA PASSCODE
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

	newHash, err := hashPasswordBcrypt(body.Password)
	if err != nil {
		log.Printf("❌ Bcrypt error: %v", err)
		jsonErr(w, 500, "Password hashing failed")
		return
	}

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

	mu.Lock()
	connections[username] = conn
	onlineCount := len(connections)
	mu.Unlock()
	log.Printf("🔌 WS connected: %s (%d online)", username, onlineCount)

	defer func() {
		mu.Lock()
		delete(connections, username)
		offlineCount := len(connections)
		mu.Unlock()
		conn.Close()
		log.Printf("🔌 WS disconnected: %s (%d online)", username, offlineCount)
	}()

	conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})

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

	sendQueued(conn, username)

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
// SYNC NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════

func SyncNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	username := r.URL.Query().Get("user")
	if username == "" || !userExists(username) {
		jsonErr(w, 400, "Invalid user")
		return
	}

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
		ID      int64     `json:"id"`
		Sender  string    `json:"sender"`
		Message string    `json:"message"`
		ReplyTo *int64    `json:"replyTo"`
		Time    time.Time `json:"timestamp"`
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
// MARK DELIVERED
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

	for _, id := range body.IDs {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1 AND target=$2", id, body.User)
	}

	log.Printf("✅ Marked %d notifications as delivered for %s", len(body.IDs), body.User)
	jsonOK(w, map[string]string{"status": "ok"})
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
		var firstName, lastName, floor, whatsapp string
		err := db.QueryRow(`
			SELECT first_name, last_name, COALESCE(floor,''), COALESCE(whatsapp,'')
			FROM imported_users
			WHERE gitea_username = $1 AND is_registered = FALSE
		`, req.TargetUser).Scan(&firstName, &lastName, &floor, &whatsapp)

		if err == nil {
			fullName := strings.TrimSpace(firstName + " " + lastName)

			phone := strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, whatsapp)

			var waURL string
			if phone != "" {
				senderName := "Admin"
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

		jsonErr(w, 404, "Target user not found")
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
// ═══════════════════════════════════════════════════════════════

func OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")

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

	if isAdmin(r) {
		var total int
		db.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)
		resp["total"] = total
	}

	json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════
// SEARCH
// FIX: Now returns floor + whatsapp for BOTH registered and
// unregistered users by joining/querying imported_users.
// Registered users get contact info from users table (which is
// backfilled from imported_users on registration/migration).
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

	// FIX: LEFT JOIN imported_users so registered users also get floor + whatsapp.
	// Priority: users.floor/whatsapp first (user may have updated), then imported_users.
	rows, err := db.Query(`
		SELECT
			u.username,
			u.full_name,
			COALESCE(NULLIF(u.floor, ''),    NULLIF(i.floor, ''),    '') AS floor,
			COALESCE(NULLIF(u.whatsapp, ''), NULLIF(i.whatsapp, ''), '') AS whatsapp
		FROM users u
		LEFT JOIN imported_users i ON i.gitea_username = u.username
		WHERE u.username ILIKE $1 OR u.full_name ILIKE $1
		LIMIT 10
	`, "%"+q+"%")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var username, fullName, floor, whatsapp string
			if rows.Scan(&username, &fullName, &floor, &whatsapp) == nil {
				results = append(results, searchResult{
					Username: username,
					FullName: fullName,
					Status:   "registered",
					Floor:    floor,
					WhatsApp: whatsapp,
				})
			}
		}
	} else {
		log.Printf("❌ Search registered users error: %v", err)
	}

	// Search unregistered users (imported but not registered)
	rows2, err2 := db.Query(`
		SELECT gitea_username, first_name || ' ' || last_name AS full_name,
		       COALESCE(floor, '') AS floor,
		       COALESCE(whatsapp, '') AS whatsapp
		FROM imported_users
		WHERE is_registered = FALSE
		  AND (gitea_username ILIKE $1 OR first_name || ' ' || last_name ILIKE $1)
		LIMIT 5
	`, "%"+q+"%")

	if err2 == nil {
		defer rows2.Close()
		for rows2.Next() {
			var username, fullName, floor, whatsapp string
			if rows2.Scan(&username, &fullName, &floor, &whatsapp) == nil {
				results = append(results, searchResult{
					Username: username,
					FullName: fullName,
					Status:   "unregistered",
					Floor:    floor,
					WhatsApp: whatsapp,
				})
			}
		}
	} else {
		log.Printf("❌ Search unregistered users error: %v", err2)
	}

	if results == nil {
		results = []searchResult{}
	}

	json.NewEncoder(w).Encode(results)
}

// ═══════════════════════════════════════════════════════════════
// ADMIN — GET ALL USERS
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
		Online    bool       `json:"online"`
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
// ADMIN — SYSTEM STATS
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
// Excel column layout (0-indexed):
//   0 = First_name
//   1 = Last_name
//   2 = Gitea_Username
//   3 = Nickname → IGNORED
//   4 = Floor
//   5 = WhatsApp
//   6 = Email
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
			continue
		}

		cell := func(idx int) string {
			if idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
			return ""
		}

		firstName := cell(0)
		lastName := cell(1)
		username := cell(2)
		// cell(3) = Nickname — ignored
		floor := cell(4)
		whatsapp := cell(5)
		email := cell(6)
		// cell(7) = Notes — ignored

		fullName := strings.TrimSpace(firstName + " " + lastName)

		if firstName == "" && lastName == "" && username == "" {
			continue
		}

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

		// Upsert into imported_users
		dbMu.Lock()
		db.Exec(`
			INSERT INTO imported_users (first_name, last_name, gitea_username, floor, whatsapp, email)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (gitea_username) DO UPDATE SET
				first_name  = EXCLUDED.first_name,
				last_name   = EXCLUDED.last_name,
				floor       = EXCLUDED.floor,
				whatsapp    = EXCLUDED.whatsapp,
				email       = EXCLUDED.email,
				imported_at = NOW()
		`, firstName, lastName, username, floor, whatsapp, email)
		dbMu.Unlock()

		// Check if already registered
		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username=$1", username).Scan(&userID)
		exists := (err == nil)

		if exists {
			// Backfill floor + whatsapp into the registered user record
			db.Exec(`
				UPDATE users SET
					floor    = COALESCE(NULLIF(floor, ''),    $1),
					whatsapp = COALESCE(NULLIF(whatsapp, ''), $2)
				WHERE username = $3
			`, floor, whatsapp, username)

			db.Exec(`
				UPDATE imported_users
				SET is_registered = TRUE, registered_user_id = $1
				WHERE gitea_username = $2
			`, userID, username)
			skipped++
			continue
		}

		if email == "" || !strings.Contains(email, "@") {
			email = fmt.Sprintf("%s@local.system", strings.ToLower(username))
		}
		email = strings.ToLower(email)

		var emailTaken bool
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&emailTaken)
		if emailTaken {
			email = fmt.Sprintf("%s@local.system", strings.ToLower(username))
		}

		passwordHash, err := hashPasswordBcrypt("changeme123")
		if err != nil {
			log.Printf("❌ Bcrypt error for %s: %v", username, err)
			skipped++
			continue
		}

		dbMu.Lock()
		var newUserID int
		insertErr := db.QueryRow(
			// FIX: Also store floor + whatsapp in users table on import
			"INSERT INTO users(username,email,full_name,password_hash,floor,whatsapp) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",
			username, email, fullName, passwordHash, floor, whatsapp,
		).Scan(&newUserID)
		dbMu.Unlock()

		if insertErr != nil {
			log.Printf("❌ Import skip %s: %v", username, insertErr)
			skipped++
			continue
		}

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

func ClearAuditsHandler(w http.ResponseWriter, r *http.Request) {
    cors(w)
    if !isAdmin(r) { jsonErr(w, 403, "Admin only"); return }
    db.Exec("TRUNCATE TABLE notifications RESTART IDENTITY")
    jsonOK(w, map[string]string{"message": "All audits cleared"})
}

func startDeliveryRetry() {
    go func() {
        ticker := time.NewTicker(3 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
            mu.RLock()
            onlineUsers := make([]string, 0, len(connections))
            for u := range connections {
                onlineUsers = append(onlineUsers, u)
            }
            mu.RUnlock()

            for _, username := range onlineUsers {
                rows, err := db.Query(`
                    SELECT id, sender, message, reply_to
                    FROM notifications
                    WHERE target=$1 AND delivered=FALSE
                    ORDER BY timestamp ASC LIMIT 10
                `, username)
                if err != nil {
                    continue
                }
                type pending struct {
                    id      int64
                    sender  string
                    message string
                    replyTo sql.NullInt64
                }
                var items []pending
                for rows.Next() {
                    var p pending
                    if rows.Scan(&p.id, &p.sender, &p.message, &p.replyTo) == nil {
                        items = append(items, p)
                    }
                }
                rows.Close()

                for _, it := range items {
                    payload := map[string]interface{}{
                        "id":       it.id,
                        "message":  it.message,
                        "sender":   it.sender,
                        "canReply": !it.replyTo.Valid,
                        "isReply":  it.replyTo.Valid,
                    }
                    if deliver(username, payload) {
                        db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", it.id)
                    }
                }
            }
        }
    }()
}