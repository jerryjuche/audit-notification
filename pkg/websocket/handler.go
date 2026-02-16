// pkg/websocket/handler.go
package websocket

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xuri/excelize/v2"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
			if allowedOrigins != "" {
				return true // TODO: Implement proper origin validation
			}
			return true
		},
	}

	connections = make(map[string]*websocket.Conn)
	mu          sync.RWMutex
	dbMutex     sync.Mutex

	db *sql.DB
)

// InitDB initializes the SQLite database with proper error handling
func InitDB() {
	var err error
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./notifications.db"
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Enable WAL mode for concurrent access
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")
	db.SetMaxOpenConns(1)

	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		full_name TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);
	
	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		sender TEXT NOT NULL,
		message TEXT NOT NULL,
		reply_to INTEGER DEFAULT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		delivered BOOLEAN DEFAULT 0,
		read BOOLEAN DEFAULT 0,
		FOREIGN KEY (target) REFERENCES users(username),
		FOREIGN KEY (sender) REFERENCES users(username),
		FOREIGN KEY (reply_to) REFERENCES notifications(id)
	);
	
	CREATE INDEX IF NOT EXISTS idx_target_delivered ON notifications(target, delivered);
	CREATE INDEX IF NOT EXISTS idx_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_reply_to ON notifications(reply_to);
	`

	_, err = db.Exec(createTablesSQL)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	log.Println("✅ SQLite database initialized successfully")
}

// User represents a registered user
type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	FullName     string     `json:"full_name"`
	PasswordHash string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// RegisterRequest for user registration
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
}

// LoginRequest for user login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// hashPassword creates SHA256 hash
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.FullName == "" || req.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	passwordHash := hashPassword(req.Password)

	dbMutex.Lock()
	result, err := db.Exec(
		"INSERT INTO users (username, email, full_name, password_hash) VALUES (?, ?, ?, ?)",
		req.Username, req.Email, req.FullName, passwordHash,
	)
	dbMutex.Unlock()

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}
		log.Printf("❌ Registration error: %v", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	userID, _ := result.LastInsertId()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Registration successful",
		"user": map[string]interface{}{
			"id":       userID,
			"username": req.Username,
			"email":    req.Email,
			"fullName": req.FullName,
		},
	})

	log.Printf("✅ New user registered: %s (%s)", req.Username, req.Email)
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	var user User
	var passwordHash string
	err := db.QueryRow(
		"SELECT id, username, email, full_name, password_hash, created_at FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.FullName, &passwordHash, &user.CreatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("❌ Login query error: %v", err)
		http.Error(w, "Login failed", http.StatusInternalServerError)
		return
	}

	if hashPassword(req.Password) != passwordHash {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	now := time.Now()
	dbMutex.Lock()
	db.Exec("UPDATE users SET last_login = ? WHERE id = ?", now, user.ID)
	dbMutex.Unlock()

	user.LastLogin = &now

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Login successful",
		"user":    user,
	})

	log.Printf("✅ User logged in: %s", req.Username)
}

// userExistsInDB checks if user exists in local database
func userExistsInDB(username string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		log.Printf("❌ User check error: %v", err)
		return false
	}
	return exists
}

// EchoHandler handles WebSocket connections with proper cleanup
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing 'user' parameter", http.StatusBadRequest)
		return
	}

	if !userExistsInDB(username) {
		http.Error(w, "User not registered. Please sign up first.", http.StatusUnauthorized)
		return
	}

	mu.RLock()
	_, alreadyConnected := connections[username]
	mu.RUnlock()

	if alreadyConnected {
		http.Error(w, "User already connected", http.StatusConflict)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ Upgrade error for %s: %v", username, err)
		return
	}

	mu.Lock()
	connections[username] = conn
	mu.Unlock()

	log.Printf("✅ User '%s' connected (total: %d)", username, len(connections))

	defer func() {
		mu.Lock()
		delete(connections, username)
		mu.Unlock()
		conn.Close()
		log.Printf("👋 User '%s' disconnected (total: %d)", username, len(connections)-1)
	}()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	stopPing := make(chan struct{})
	defer close(stopPing)

	go pingRoutine(conn, username, stopPing)

	if err := sendQueuedNotifications(conn, username); err != nil {
		log.Printf("⚠️  Error sending queued notifications to %s: %v", username, err)
	}

	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("⚠️  Unexpected close for %s: %v", username, err)
			}
			return
		}

		if err := conn.WriteMessage(msgType, msg); err != nil {
			log.Printf("❌ Write error for %s: %v", username, err)
			return
		}
	}
}

// pingRoutine sends periodic pings to keep connection alive
func pingRoutine(conn *websocket.Conn, username string, stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				log.Printf("⚠️  Ping failed for %s: %v", username, err)
				return
			}
		case <-stop:
			return
		}
	}
}

// sendQueuedNotifications sends undelivered notifications to newly connected user
func sendQueuedNotifications(conn *websocket.Conn, username string) error {
	dbMutex.Lock()
	rows, err := db.Query(
		"SELECT id, sender, message, reply_to FROM notifications WHERE target = ? AND delivered = 0 ORDER BY timestamp ASC",
		username,
	)
	if err != nil {
		dbMutex.Unlock()
		return fmt.Errorf("query error: %w", err)
	}

	var notifications []struct {
		ID      int64
		Sender  string
		Message string
		ReplyTo sql.NullInt64
	}

	for rows.Next() {
		var n struct {
			ID      int64
			Sender  string
			Message string
			ReplyTo sql.NullInt64
		}
		if err := rows.Scan(&n.ID, &n.Sender, &n.Message, &n.ReplyTo); err != nil {
			log.Printf("❌ Scan error: %v", err)
			continue
		}
		notifications = append(notifications, n)
	}
	rows.Close()
	dbMutex.Unlock()

	count := 0
	for _, n := range notifications {
		payload := map[string]interface{}{
			"id":      n.ID,
			"message": n.Message,
			"sender":  n.Sender,
			"canReply": !n.ReplyTo.Valid,
			"isReply": n.ReplyTo.Valid,
		}

		if n.ReplyTo.Valid {
			payload["replyTo"] = n.ReplyTo.Int64
		}

		jsonData, _ := json.Marshal(payload)

		if err := conn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
			return fmt.Errorf("send error: %w", err)
		}

		dbMutex.Lock()
		_, err = db.Exec("UPDATE notifications SET delivered = 1 WHERE id = ?", n.ID)
		dbMutex.Unlock()

		if err != nil {
			log.Printf("❌ Update error for notification %d: %v", n.ID, err)
		} else {
			count++
		}
	}

	if count > 0 {
		log.Printf("📬 Sent %d queued notification(s) to %s", count, username)
	}

	return nil
}

// AuditRequest represents an audit notification request
type AuditRequest struct {
	TargetUser string `json:"targetUser"`
	Requester  string `json:"requester"`
	Details    string `json:"details"`
}

// AuditHandler processes audit requests with notification delivery or queuing
func AuditHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.TargetUser == "" || req.Requester == "" || req.Details == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if !userExistsInDB(req.TargetUser) {
		http.Error(w, "Target user not registered", http.StatusBadRequest)
		return
	}

	message := fmt.Sprintf("🔔 Audit request from %s: %s", req.Requester, req.Details)

	mu.RLock()
	conn, exists := connections[req.TargetUser]
	mu.RUnlock()

	// Save to database first (for reply tracking)
	dbMutex.Lock()
	result, err := db.Exec(
		"INSERT INTO notifications (target, sender, message) VALUES (?, ?, ?)",
		req.TargetUser, req.Requester, message,
	)
	dbMutex.Unlock()

	if err != nil {
		log.Printf("❌ DB insert error: %v", err)
		http.Error(w, "Failed to save notification", http.StatusInternalServerError)
		return
	}

	notificationID, _ := result.LastInsertId()

	if exists {
		// Send with notification ID for reply tracking
		notifPayload := map[string]interface{}{
			"id":      notificationID,
			"message": message,
			"sender":  req.Requester,
			"canReply": true,
		}
		jsonData, _ := json.Marshal(notifPayload)

		if err := conn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
			log.Printf("❌ Send error to %s: %v", req.TargetUser, err)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "queued",
				"message": "Send failed—notification queued",
			})
			return
		}

		// Mark as delivered
		dbMutex.Lock()
		db.Exec("UPDATE notifications SET delivered = 1 WHERE id = ?", notificationID)
		dbMutex.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "delivered",
			"message": "Notification sent successfully",
		})
		log.Printf("✅ Notification sent to %s from %s", req.TargetUser, req.Requester)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "queued",
		"message": "User offline—notification queued",
	})
	log.Printf("📥 Notification queued for %s from %s", req.TargetUser, req.Requester)
}

// queueNotification persists notification to database
func queueNotification(target, message string) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	_, err := db.Exec(
		"INSERT INTO notifications (target, sender, message) VALUES (?, ?, ?)",
		target, "system", message,
	)
	if err != nil {
		log.Printf("❌ DB insert error: %v", err)
		return fmt.Errorf("database error: %w", err)
	}
	return nil
}

// ReplyRequest represents a reply to an audit notification
type ReplyRequest struct {
	NotificationID int64  `json:"notificationId"`
	ReplyMessage   string `json:"replyMessage"`
	ReplierUsername string `json:"replierUsername"`
}

// ReplyHandler handles replies to audit notifications
func ReplyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ReplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.NotificationID == 0 || req.ReplyMessage == "" || req.ReplierUsername == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Get original notification sender
	var originalSender string
	err := db.QueryRow(
		"SELECT sender FROM notifications WHERE id = ?",
		req.NotificationID,
	).Scan(&originalSender)

	if err != nil {
		http.Error(w, "Original notification not found", http.StatusNotFound)
		return
	}

	// Create reply message
	replyMsg := fmt.Sprintf("💬 Reply from %s: %s", req.ReplierUsername, req.ReplyMessage)

	// Save reply to database
	dbMutex.Lock()
	result, err := db.Exec(
		"INSERT INTO notifications (target, sender, message, reply_to) VALUES (?, ?, ?, ?)",
		originalSender, req.ReplierUsername, replyMsg, req.NotificationID,
	)
	dbMutex.Unlock()

	if err != nil {
		log.Printf("❌ Reply insert error: %v", err)
		http.Error(w, "Failed to save reply", http.StatusInternalServerError)
		return
	}

	replyID, _ := result.LastInsertId()

	// Send reply to original sender
	mu.RLock()
	conn, exists := connections[originalSender]
	mu.RUnlock()

	if exists {
		replyPayload := map[string]interface{}{
			"id":      replyID,
			"message": replyMsg,
			"sender":  req.ReplierUsername,
			"replyTo": req.NotificationID,
			"isReply": true,
		}
		jsonData, _ := json.Marshal(replyPayload)

		if err := conn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
			log.Printf("❌ Reply send error to %s: %v", originalSender, err)
		} else {
			dbMutex.Lock()
			db.Exec("UPDATE notifications SET delivered = 1 WHERE id = ?", replyID)
			dbMutex.Unlock()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "sent",
		"message": "Reply sent successfully",
	})
	log.Printf("✅ Reply sent from %s to %s", req.ReplierUsername, originalSender)
}

// GetOnlineUsers returns list of currently connected usernames
func GetOnlineUsers() []string {
	mu.RLock()
	defer mu.RUnlock()

	users := make([]string, 0, len(connections))
	for username := range connections {
		users = append(users, username)
	}
	return users
}

// OnlineUsersHandler returns list of online users as JSON
func OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	users := GetOnlineUsers()

	var totalUsers int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		log.Printf("❌ Count error: %v", err)
		totalUsers = 0
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"online": users,
		"count":  len(users),
		"total":  totalUsers,
	})
}

// SearchUsersHandler returns users matching search query
func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query().Get("q")
	if query == "" {
		json.NewEncoder(w).Encode([]map[string]string{})
		return
	}

	rows, err := db.Query(
		"SELECT username, full_name FROM users WHERE username LIKE ? OR full_name LIKE ? LIMIT 10",
		"%"+query+"%", "%"+query+"%",
	)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []map[string]string
	for rows.Next() {
		var username, fullName string
		if err := rows.Scan(&username, &fullName); err != nil {
			continue
		}
		users = append(users, map[string]string{
			"username": username,
			"fullName": fullName,
		})
	}

	json.NewEncoder(w).Encode(users)
}

// ImportUsersHandler handles bulk user import from Excel
func ImportUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	adminUser := r.URL.Query().Get("admin")
	if adminUser == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND username = 'admin')", adminUser).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, "Admin access required", http.StatusForbidden)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	f, err := excelize.OpenReader(file)
	if err != nil {
		http.Error(w, "Invalid Excel file", http.StatusBadRequest)
		return
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		http.Error(w, "No sheets found", http.StatusBadRequest)
		return
	}

	rows, err := f.GetRows(sheets[0])
	if err != nil {
		http.Error(w, "Failed to read rows", http.StatusInternalServerError)
		return
	}

	imported := 0
	skipped := 0

	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}

		firstName := strings.TrimSpace(row[0])
		lastName := strings.TrimSpace(row[1])
		username := strings.TrimSpace(row[2])

		if firstName == "" || lastName == "" || username == "" {
			skipped++
			continue
		}

		fullName := firstName + " " + lastName

		var userExists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&userExists)
		if err != nil || userExists {
			skipped++
			continue
		}

		email := fmt.Sprintf("%s@local.system", username)
		passwordHash := hashPassword("changeme123")

		dbMutex.Lock()
		_, err = db.Exec(
			"INSERT INTO users (username, email, full_name, password_hash) VALUES (?, ?, ?, ?)",
			username, email, fullName, passwordHash,
		)
		dbMutex.Unlock()

		if err != nil {
			log.Printf("⚠️ Failed to import %s: %v", username, err)
			skipped++
			continue
		}

		imported++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"imported": imported,
		"skipped":  skipped,
	})

	log.Printf("✅ Imported %d users, skipped %d", imported, skipped)
}
