// pkg/websocket/handler.go
package websocket

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	connections = make(map[string]*websocket.Conn)
	mu          sync.RWMutex
	dbMutex     sync.Mutex

	db *sql.DB
)

// InitDB initializes PostgreSQL database
func InitDB() {
	var err error
	
	
	// Build connection string
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	
	// Default values for local development
	if host == "" {
		host = "dpg-d69h9qjnv86c73eug1tg-a.oregon-postgres.render.com"
	}
	if port == "" {
		port = "5432"
	}
	if dbname == "" {
		dbname = "audit_db_dyhx"
	}
	if user == "" {
		user = "audit_db_dyhx_user"
	}
	if password == "" {
		password = "UKaGYfaMuffMA4Pu9JZoToFAxlzlzQc9"
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		host, port, user, password, dbname)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("❌ Failed to ping database:", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Create tables
	createTablesSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		full_name VARCHAR(255) NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS notifications (
		id SERIAL PRIMARY KEY,
		target VARCHAR(255) NOT NULL,
		sender VARCHAR(255) NOT NULL,
		message TEXT NOT NULL,
		reply_to INTEGER DEFAULT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		status VARCHAR(50) DEFAULT 'pending'
	);
	
	CREATE INDEX IF NOT EXISTS idx_target_delivered ON notifications(target, delivered);
	CREATE INDEX IF NOT EXISTS idx_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_reply_to ON notifications(reply_to);
	`

	_, err = db.Exec(createTablesSQL)
	if err != nil {
		log.Fatal("❌ Failed to create tables:", err)
	}

	log.Println("✅ PostgreSQL database initialized successfully")
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

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

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
	var userID int
	err := db.QueryRow(
		"INSERT INTO users (username, email, full_name, password_hash) VALUES ($1, $2, $3, $4) RETURNING id",
		req.Username, req.Email, req.FullName, passwordHash,
	).Scan(&userID)
	dbMutex.Unlock()

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			if strings.Contains(err.Error(), "username") {
				http.Error(w, "Username already exists", http.StatusConflict)
			} else {
				http.Error(w, "Email already registered", http.StatusConflict)
			}
			return
		}
		log.Printf("❌ Registration error: %v", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

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

	log.Printf("✅ New user registered: %s", req.Username)
}

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
		"SELECT id, username, email, full_name, password_hash, created_at FROM users WHERE username = $1",
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
	db.Exec("UPDATE users SET last_login = $1 WHERE id = $2", now, user.ID)
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

func userExistsInDB(username string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
	if err != nil {
		log.Printf("❌ User check error: %v", err)
		return false
	}
	return exists
}

func EchoHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing 'user' parameter", http.StatusBadRequest)
		return
	}

	if !userExistsInDB(username) {
		http.Error(w, "User not registered", http.StatusUnauthorized)
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
		log.Printf("👋 User '%s' disconnected", username)
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
		log.Printf("⚠️ Error sending queued notifications: %v", err)
	}

	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("⚠️ Unexpected close: %v", err)
			}
			return
		}

		if err := conn.WriteMessage(msgType, msg); err != nil {
			log.Printf("❌ Write error: %v", err)
			return
		}
	}
}

func pingRoutine(conn *websocket.Conn, username string, stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func sendQueuedNotifications(conn *websocket.Conn, username string) error {
	rows, err := db.Query(
		"SELECT id, sender, message, reply_to FROM notifications WHERE target = $1 AND delivered = FALSE ORDER BY timestamp ASC",
		username,
	)
	if err != nil {
		return fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

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

		db.Exec("UPDATE notifications SET delivered = TRUE WHERE id = $1", n.ID)
		count++
	}

	if count > 0 {
		log.Printf("📬 Sent %d queued notifications to %s", count, username)
	}

	return nil
}

type AuditRequest struct {
	TargetUser string `json:"targetUser"`
	Requester  string `json:"requester"`
	Details    string `json:"details"`
}

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

	message := fmt.Sprintf("@%s: %s", req.Requester, req.Details)

	mu.RLock()
	conn, exists := connections[req.TargetUser]
	mu.RUnlock()

	var notificationID int64
	err := db.QueryRow(
		"INSERT INTO notifications (target, sender, message) VALUES ($1, $2, $3) RETURNING id",
		req.TargetUser, req.Requester, message,
	).Scan(&notificationID)

	if err != nil {
		log.Printf("❌ DB insert error: %v", err)
		http.Error(w, "Failed to save notification", http.StatusInternalServerError)
		return
	}

	if exists {
		notifPayload := map[string]interface{}{
			"id":      notificationID,
			"message": message,
			"sender":  req.Requester,
			"canReply": true,
		}
		jsonData, _ := json.Marshal(notifPayload)

		if err := conn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
			log.Printf("❌ Send error: %v", err)
		} else {
			db.Exec("UPDATE notifications SET delivered = TRUE WHERE id = $1", notificationID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "delivered",
		"message": "Notification sent successfully",
	})
	log.Printf("✅ Notification sent to %s from %s", req.TargetUser, req.Requester)
}

type ReplyRequest struct {
	NotificationID  int64  `json:"notificationId"`
	ReplyMessage    string `json:"replyMessage"`
	ReplierUsername string `json:"replierUsername"`
}

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
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.NotificationID == 0 || req.ReplyMessage == "" || req.ReplierUsername == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	var originalSender string
	err := db.QueryRow("SELECT sender FROM notifications WHERE id = $1", req.NotificationID).Scan(&originalSender)

	if err != nil {
		http.Error(w, "Original notification not found", http.StatusNotFound)
		return
	}

	replyMsg := fmt.Sprintf("@%s replied: %s", req.ReplierUsername, req.ReplyMessage)

	var replyID int64
	err = db.QueryRow(
		"INSERT INTO notifications (target, sender, message, reply_to) VALUES ($1, $2, $3, $4) RETURNING id",
		originalSender, req.ReplierUsername, replyMsg, req.NotificationID,
	).Scan(&replyID)

	if err != nil {
		log.Printf("❌ Reply insert error: %v", err)
		http.Error(w, "Failed to save reply", http.StatusInternalServerError)
		return
	}

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

		if err := conn.WriteMessage(websocket.TextMessage, jsonData); err == nil {
			db.Exec("UPDATE notifications SET delivered = TRUE WHERE id = $1", replyID)
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

type BroadcastRequest struct {
	Message    string `json:"message"`
	Sender     string `json:"sender"`
	TargetType string `json:"targetType"`
}

func BroadcastHandler(w http.ResponseWriter, r *http.Request) {
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

	var req BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Message == "" || req.Sender == "" || req.TargetType == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.Sender != "admin" {
		http.Error(w, "Only admin can broadcast", http.StatusForbidden)
		return
	}

	message := fmt.Sprintf("📢 Broadcast from @%s: %s", req.Sender, req.Message)
	delivered := 0
	queued := 0

	if req.TargetType == "online" {
		mu.RLock()
		for username, conn := range connections {
			if username == req.Sender {
				continue
			}

			payload := map[string]interface{}{
				"id":        time.Now().UnixNano(),
				"message":   message,
				"sender":    req.Sender,
				"canReply":  false,
				"broadcast": true,
			}
			jsonData, _ := json.Marshal(payload)

			if err := conn.WriteMessage(websocket.TextMessage, jsonData); err == nil {
				delivered++
			}
		}
		mu.RUnlock()
	} else if req.TargetType == "all" {
		rows, err := db.Query("SELECT username FROM users WHERE username != $1", req.Sender)
		if err != nil {
			http.Error(w, "Failed to get users", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var allUsers []string
		for rows.Next() {
			var username string
			if err := rows.Scan(&username); err != nil {
				continue
			}
			allUsers = append(allUsers, username)
		}

		mu.RLock()
		for _, username := range allUsers {
			conn, online := connections[username]
			if online {
				payload := map[string]interface{}{
					"id":        time.Now().UnixNano(),
					"message":   message,
					"sender":    req.Sender,
					"canReply":  false,
					"broadcast": true,
				}
				jsonData, _ := json.Marshal(payload)

				if err := conn.WriteMessage(websocket.TextMessage, jsonData); err == nil {
					delivered++
				} else {
					db.Exec("INSERT INTO notifications (target, sender, message) VALUES ($1, $2, $3)", username, req.Sender, message)
					queued++
				}
			} else {
				db.Exec("INSERT INTO notifications (target, sender, message) VALUES ($1, $2, $3)", username, req.Sender, message)
				queued++
			}
		}
		mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "sent",
		"delivered": delivered,
		"queued":    queued,
		"message":   fmt.Sprintf("Broadcast sent to %d users, queued for %d", delivered, queued),
	})
	log.Printf("✅ Broadcast: %d delivered, %d queued", delivered, queued)
}

type FeedbackRequest struct {
	Username string `json:"username"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	Type     string `json:"type"`
}

func FeedbackHandler(w http.ResponseWriter, r *http.Request) {
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

	var req FeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Subject == "" || req.Message == "" {
		http.Error(w, "All fields required", http.StatusBadRequest)
		return
	}

	var feedbackID int64
	err := db.QueryRow(
		"INSERT INTO feedback (username, subject, message, type) VALUES ($1, $2, $3, $4) RETURNING id",
		req.Username, req.Subject, req.Message, req.Type,
	).Scan(&feedbackID)

	if err != nil {
		log.Printf("❌ Feedback insert error: %v", err)
		http.Error(w, "Failed to save feedback", http.StatusInternalServerError)
		return
	}

	adminMessage := fmt.Sprintf("📝 @%s (%s): %s - %s", req.Username, req.Type, req.Subject, req.Message)

	var notificationID int64
	err = db.QueryRow(
		"INSERT INTO notifications (target, sender, message) VALUES ($1, $2, $3) RETURNING id",
		"admin", req.Username, adminMessage,
	).Scan(&notificationID)

	if err != nil {
		log.Printf("❌ Feedback notification error: %v", err)
	}

	mu.RLock()
	adminConn, adminOnline := connections["admin"]
	mu.RUnlock()

	if adminOnline {
		payload := map[string]interface{}{
			"id":       notificationID,
			"message":  adminMessage,
			"sender":   req.Username,
			"canReply": true,
			"feedback": true,
		}
		jsonData, _ := json.Marshal(payload)

		if err := adminConn.WriteMessage(websocket.TextMessage, jsonData); err == nil {
			db.Exec("UPDATE notifications SET delivered = TRUE WHERE id = $1", notificationID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "sent",
		"message": "Feedback submitted successfully",
	})
	log.Printf("✅ Feedback from %s: %s", req.Username, req.Subject)
}

func GetOnlineUsers() []string {
	mu.RLock()
	defer mu.RUnlock()

	users := make([]string, 0, len(connections))
	for username := range connections {
		users = append(users, username)
	}
	return users
}

func OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	users := GetOnlineUsers()

	var totalUsers int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"online": users,
		"count":  len(users),
		"total":  totalUsers,
	})
}

func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query().Get("q")
	if query == "" {
		json.NewEncoder(w).Encode([]map[string]string{})
		return
	}

	rows, err := db.Query(
		"SELECT username, full_name FROM users WHERE username ILIKE $1 OR full_name ILIKE $1 LIMIT 10",
		"%"+query+"%",
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
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND username = 'admin')", adminUser).Scan(&exists)
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
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", username).Scan(&userExists)
		if userExists {
			skipped++
			continue
		}

		email := fmt.Sprintf("%s@local.system", username)
		passwordHash := hashPassword("changeme123")

		_, err = db.Exec(
			"INSERT INTO users (username, email, full_name, password_hash) VALUES ($1, $2, $3, $4)",
			username, email, fullName, passwordHash,
		)

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
