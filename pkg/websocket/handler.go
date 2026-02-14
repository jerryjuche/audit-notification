// pkg/websocket/handler.go
package websocket

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// In production, implement proper origin checking
			allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
			if allowedOrigins != "" {
				// Parse and check against allowed origins
				return true // TODO: Implement proper origin validation
			}
			return true // Allow all for development
		},
	}

	connections = make(map[string]*websocket.Conn)
	mu          sync.RWMutex

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

	// Test connection
	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Create table with index
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		delivered BOOLEAN DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_target_delivered ON notifications(target, delivered);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	log.Println("✅ SQLite database initialized successfully")
}

// EchoHandler handles WebSocket connections with proper cleanup
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing 'user' parameter", http.StatusBadRequest)
		return
	}

	// Validate username
	if !userExistsInGitea(username) {
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		return
	}

	// Check if user already connected
	mu.RLock()
	_, alreadyConnected := connections[username]
	mu.RUnlock()

	if alreadyConnected {
		http.Error(w, "User already connected", http.StatusConflict)
		return
	}

	// Upgrade connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ Upgrade error for %s: %v", username, err)
		return
	}

	// Register connection
	mu.Lock()
	connections[username] = conn
	mu.Unlock()

	log.Printf("✅ User '%s' connected (total: %d)", username, len(connections))

	// Setup cleanup
	defer func() {
		mu.Lock()
		delete(connections, username)
		mu.Unlock()
		conn.Close()
		log.Printf("👋 User '%s' disconnected (total: %d)", username, len(connections)-1)
	}()

	// Configure connection
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Start ping routine
	stopPing := make(chan struct{})
	defer close(stopPing)

	go pingRoutine(conn, username, stopPing)

	// Send queued notifications
	if err := sendQueuedNotifications(conn, username); err != nil {
		log.Printf("⚠️  Error sending queued notifications to %s: %v", username, err)
	}

	// Read loop (handle client messages)
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("⚠️  Unexpected close for %s: %v", username, err)
			}
			return
		}

		// Echo back for testing
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
	rows, err := db.Query(
		"SELECT id, message FROM notifications WHERE target = ? AND delivered = 0 ORDER BY timestamp ASC",
		username,
	)
	if err != nil {
		return fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id int
		var msg string
		if err := rows.Scan(&id, &msg); err != nil {
			log.Printf("❌ Scan error: %v", err)
			continue
		}

		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			return fmt.Errorf("send error: %w", err)
		}

		if _, err = db.Exec("UPDATE notifications SET delivered = 1 WHERE id = ?", id); err != nil {
			log.Printf("❌ Update error for notification %d: %v", id, err)
		} else {
			count++
		}
	}

	if count > 0 {
		log.Printf("📬 Sent %d queued notification(s) to %s", count, username)
	}

	return rows.Err()
}

// userExistsInGitea validates username against Gitea API
func userExistsInGitea(username string) bool {
	giteaURL := os.Getenv("GITEA_URL")
	if giteaURL == "" {
		giteaURL = "http://localhost:3000"
	}

	// For development: mock validation
	mockMode := os.Getenv("MOCK_AUTH")
	if mockMode == "true" {
		// Allow specific test users
		validUsers := map[string]bool{
			"jerry": true,
			"admin": true,
			"test":  true,
		}
		return validUsers[username]
	}

	// Real Gitea validation
	url := fmt.Sprintf("%s/api/v1/users/%s", giteaURL, username)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("⚠️  Gitea API error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true
	}

	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("⚠️  Gitea response (%d) for %s: %s", resp.StatusCode, username, string(body))
	}

	return false
}

// AuditRequest represents an audit notification request
type AuditRequest struct {
	TargetUser string `json:"targetUser" validate:"required"`
	Requester  string `json:"requester" validate:"required"`
	Details    string `json:"details" validate:"required"`
}

// AuditHandler processes audit requests with notification delivery or queuing
func AuditHandler(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*") // Configure properly in production
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

	// Validate required fields
	if req.TargetUser == "" || req.Requester == "" || req.Details == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate target user exists
	if !userExistsInGitea(req.TargetUser) {
		http.Error(w, "Invalid target user", http.StatusBadRequest)
		return
	}

	message := fmt.Sprintf("🔔 Audit request from %s: %s", req.Requester, req.Details)

	// Try to send immediately if user is connected
	mu.RLock()
	conn, exists := connections[req.TargetUser]
	mu.RUnlock()

	if exists {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("❌ Send error to %s: %v", req.TargetUser, err)
			// Queue the notification since send failed
			if err := queueNotification(req.TargetUser, message); err != nil {
				http.Error(w, "Failed to queue notification", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintln(w, "Send failed—notification queued")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "delivered",
			"message": "Notification sent successfully",
		})
		log.Printf("✅ Notification sent to %s from %s", req.TargetUser, req.Requester)
		return
	}

	// User offline - queue notification
	if err := queueNotification(req.TargetUser, message); err != nil {
		http.Error(w, "Failed to queue notification", http.StatusInternalServerError)
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
	_, err := db.Exec(
		"INSERT INTO notifications (target, message) VALUES (?, ?)",
		target, message,
	)
	if err != nil {
		log.Printf("❌ DB insert error: %v", err)
		return fmt.Errorf("database error: %w", err)
	}
	return nil
}

// GetConnectionCount returns number of active connections (for monitoring)
func GetConnectionCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(connections)
}
