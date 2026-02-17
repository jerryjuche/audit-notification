package websocket

import (
	"context"
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

	gorilla "github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
)

// ── globals ──────────────────────────────────────────────────
var (
	upgrader = gorilla.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	connections = make(map[string]*gorilla.Conn)
	mu          sync.RWMutex
	dbMu        sync.Mutex
	db          *sql.DB
)

// ── database init ─────────────────────────────────────────────
func InitDB() {
	log.Println("Initializing database...")

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

	log.Println("⏳ Connecting to PostgreSQL (up to 30s)...")
	if err = db.PingContext(ctx); err != nil {
		log.Fatal("❌ Failed to ping database:", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id            SERIAL PRIMARY KEY,
		username      VARCHAR(255) UNIQUE NOT NULL,
		email         VARCHAR(255) UNIQUE NOT NULL,
		full_name     VARCHAR(255) NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at    TIMESTAMP DEFAULT NOW(),
		last_login    TIMESTAMP
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
	CREATE INDEX IF NOT EXISTS idx_notif_target ON notifications(target, delivered);
	CREATE INDEX IF NOT EXISTS idx_users_uname  ON users(username);
	CREATE INDEX IF NOT EXISTS idx_notif_reply  ON notifications(reply_to);
	`
	if _, err = db.Exec(schema); err != nil {
		log.Fatal("❌ Failed to create tables:", err)
	}
	log.Println("✅ PostgreSQL initialized")
}

// ── helpers ───────────────────────────────────────────────────
func hashPassword(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

func userExists(username string) bool {
	var ok bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", username).Scan(&ok)
	return ok
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
	return conn.WriteMessage(gorilla.TextMessage, b) == nil
}

func queue(target, sender, message string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db.Exec("INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3)", target, sender, message)
}

// ── register ──────────────────────────────────────────────────
type registerReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email    = strings.TrimSpace(req.Email)
	req.FullName = strings.TrimSpace(req.FullName)

	if req.Username == "" || req.Email == "" || req.FullName == "" || req.Password == "" {
		jsonErr(w, 400, "All fields required"); return
	}
	if len(req.Password) < 6 {
		jsonErr(w, 400, "Password must be at least 6 characters"); return
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
			} else {
				jsonErr(w, 409, "Email already registered")
			}
			return
		}
		log.Printf("❌ Register: %v", err)
		jsonErr(w, 500, "Registration failed"); return
	}

	log.Printf("✅ Registered: %s", req.Username)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Registration successful",
		"user":    map[string]interface{}{"id": id, "username": req.Username, "email": req.Email, "full_name": req.FullName},
	})
}

// ── login ─────────────────────────────────────────────────────
type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	if req.Username == "" || req.Password == "" {
		jsonErr(w, 400, "Username and password required"); return
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

	if err == sql.ErrNoRows || hashPassword(req.Password) != passwordHash {
		jsonErr(w, 401, "Invalid username or password"); return
	}
	if err != nil {
		log.Printf("❌ Login: %v", err)
		jsonErr(w, 500, "Login failed"); return
	}

	now := time.Now()
	db.Exec("UPDATE users SET last_login=$1 WHERE id=$2", now, id)

	log.Printf("✅ Login: %s", req.Username)
	jsonOK(w, map[string]interface{}{
		"success": true,
		"message": "Login successful",
		"user":    map[string]interface{}{"id": id, "username": req.Username, "email": email, "full_name": fullName, "created_at": createdAt},
	})
}

// ── websocket ─────────────────────────────────────────────────
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" { jsonErr(w, 400, "Missing user parameter"); return }
	if !userExists(username) { jsonErr(w, 401, "User not registered"); return }

	mu.RLock()
	_, already := connections[username]
	mu.RUnlock()
	if already { jsonErr(w, 409, "User already connected"); return }

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil { log.Printf("❌ WS upgrade: %v", err); return }

	mu.Lock()
	connections[username] = conn
	mu.Unlock()
	log.Printf("✅ Connected: %s (%d online)", username, len(connections))

	defer func() {
		mu.Lock()
		delete(connections, username)
		mu.Unlock()
		conn.Close()
		log.Printf("👋 Disconnected: %s", username)
	}()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
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
				log.Printf("⚠️ WS %s: %v", username, err)
			}
			return
		}
		conn.WriteMessage(msgType, msg)
	}
}

func sendQueued(conn *gorilla.Conn, username string) {
	rows, err := db.Query(
		"SELECT id,sender,message,reply_to FROM notifications WHERE target=$1 AND delivered=FALSE ORDER BY timestamp ASC",
		username,
	)
	if err != nil { return }
	defer rows.Close()

	type item struct {
		id      int64
		sender  string
		message string
		replyTo sql.NullInt64
	}

	var items []item
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.sender, &it.message, &it.replyTo) == nil {
			items = append(items, it)
		}
	}

	for _, it := range items {
		p := map[string]interface{}{
			"id": it.id, "message": it.message, "sender": it.sender,
			"canReply": !it.replyTo.Valid, "isReply": it.replyTo.Valid,
		}
		if it.replyTo.Valid {
			p["replyTo"] = it.replyTo.Int64
		}
		b, _ := json.Marshal(p)
		if conn.WriteMessage(gorilla.TextMessage, b) != nil { break }
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", it.id)
	}
	if len(items) > 0 {
		log.Printf("📬 Delivered %d queued to %s", len(items), username)
	}
}

// ── audit ─────────────────────────────────────────────────────
type auditReq struct {
	TargetUser string `json:"targetUser"`
	Requester  string `json:"requester"`
	Details    string `json:"details"`
}

func AuditHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req auditReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	req.TargetUser = strings.TrimSpace(req.TargetUser)
	req.Requester  = strings.TrimSpace(req.Requester)
	req.Details    = strings.TrimSpace(req.Details)

	if req.TargetUser == "" || req.Requester == "" || req.Details == "" {
		jsonErr(w, 400, "All fields required"); return
	}
	if !userExists(req.TargetUser) {
		jsonErr(w, 400, "Target user not found"); return
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
		"id": nid, "message": msg, "sender": req.Requester, "canReply": true,
	})
	if sent {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", nid)
	}

	status := "queued"
	if sent { status = "delivered" }
	log.Printf("✅ Audit %s→%s (%s)", req.Requester, req.TargetUser, status)
	jsonOK(w, map[string]string{"status": status, "message": "Notification sent successfully"})
}

// ── reply ─────────────────────────────────────────────────────
type replyReq struct {
	NotificationID  int64  `json:"notificationId"`
	ReplyMessage    string `json:"replyMessage"`
	ReplierUsername string `json:"replierUsername"`
}

func ReplyHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req replyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	if req.NotificationID == 0 || req.ReplyMessage == "" || req.ReplierUsername == "" {
		jsonErr(w, 400, "Missing fields"); return
	}

	var origSender string
	if err := db.QueryRow("SELECT sender FROM notifications WHERE id=$1", req.NotificationID).Scan(&origSender); err != nil {
		jsonErr(w, 404, "Notification not found"); return
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
		"id": rid, "message": msg, "sender": req.ReplierUsername,
		"replyTo": req.NotificationID, "isReply": true,
	})
	if sent {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", rid)
	}

	log.Printf("✅ Reply %s→%s", req.ReplierUsername, origSender)
	jsonOK(w, map[string]string{"status": "sent", "message": "Reply sent"})
}

// ── broadcast ─────────────────────────────────────────────────
type broadcastReq struct {
	Message    string `json:"message"`
	Sender     string `json:"sender"`
	TargetType string `json:"targetType"`
}

func BroadcastHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req broadcastReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	if req.Message == "" || req.Sender == "" || req.TargetType == "" {
		jsonErr(w, 400, "Missing fields"); return
	}
	if req.Sender != "admin" {
		jsonErr(w, 403, "Only admin can broadcast"); return
	}

	msg := fmt.Sprintf("📢 Broadcast from @%s: %s", req.Sender, req.Message)
	delivered, queued := 0, 0

	if req.TargetType == "online" {
		mu.RLock()
		for username, conn := range connections {
			if username == req.Sender { continue }
			b, _ := json.Marshal(map[string]interface{}{
				"id": time.Now().UnixNano(), "message": msg,
				"sender": req.Sender, "canReply": false, "broadcast": true,
			})
			if conn.WriteMessage(gorilla.TextMessage, b) == nil {
				delivered++
			}
		}
		mu.RUnlock()
	} else {
		rows, err := db.Query("SELECT username FROM users WHERE username!=$1", req.Sender)
		if err != nil { jsonErr(w, 500, "DB error"); return }
		defer rows.Close()

		var users []string
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil { users = append(users, u) }
		}

		for _, u := range users {
			ok := deliver(u, map[string]interface{}{
				"id": time.Now().UnixNano(), "message": msg,
				"sender": req.Sender, "canReply": false, "broadcast": true,
			})
			if ok { delivered++ } else { queue(u, req.Sender, msg); queued++ }
		}
	}

	log.Printf("✅ Broadcast: %d delivered, %d queued", delivered, queued)
	jsonOK(w, map[string]interface{}{
		"status": "sent", "delivered": delivered, "queued": queued,
		"message": fmt.Sprintf("Sent to %d users, queued for %d", delivered, queued),
	})
}

// ── feedback (submit) ─────────────────────────────────────────
type feedbackReq struct {
	Username string `json:"username"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	Type     string `json:"type"`
}

func FeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }

	var req feedbackReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}
	if req.Username == "" || req.Subject == "" || req.Message == "" || req.Type == "" {
		jsonErr(w, 400, "All fields required"); return
	}

	dbMu.Lock()
	db.Exec("INSERT INTO feedback(username,subject,message,type) VALUES($1,$2,$3,$4)",
		req.Username, req.Subject, req.Message, req.Type)
	dbMu.Unlock()

	adminMsg := fmt.Sprintf("📝 @%s (%s): %s — %s", req.Username, req.Type, req.Subject, req.Message)

	var nid int64
	dbMu.Lock()
	db.QueryRow("INSERT INTO notifications(target,sender,message) VALUES($1,$2,$3) RETURNING id",
		"admin", req.Username, adminMsg).Scan(&nid)
	dbMu.Unlock()

	if deliver("admin", map[string]interface{}{
		"id": nid, "message": adminMsg, "sender": req.Username, "canReply": true, "feedback": true,
	}) {
		db.Exec("UPDATE notifications SET delivered=TRUE WHERE id=$1", nid)
	}

	log.Printf("✅ Feedback from %s", req.Username)
	jsonOK(w, map[string]string{"status": "sent", "message": "Feedback submitted successfully"})
}

// ── online users ──────────────────────────────────────────────
func OnlineUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")

	mu.RLock()
	list := make([]string, 0, len(connections))
	for u := range connections { list = append(list, u) }
	mu.RUnlock()

	var total int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"online": list, "count": len(list), "total": total,
	})
}

// ── search ────────────────────────────────────────────────────
func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 { json.NewEncoder(w).Encode([]interface{}{}); return }

	rows, err := db.Query(
		"SELECT username, full_name FROM users WHERE username ILIKE $1 OR full_name ILIKE $1 LIMIT 10",
		"%"+q+"%",
	)
	if err != nil { jsonErr(w, 500, "Search failed"); return }
	defer rows.Close()

	var results []map[string]string
	for rows.Next() {
		var username, fullName string
		if rows.Scan(&username, &fullName) == nil {
			results = append(results, map[string]string{"username": username, "fullName": fullName})
		}
	}
	if results == nil { results = []map[string]string{} }
	json.NewEncoder(w).Encode(results)
}

// ── admin: get all users ──────────────────────────────────────
func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Header.Get("X-Admin-User") != "admin" { jsonErr(w, 403, "Admin only"); return }

	rows, err := db.Query(
		"SELECT id,username,email,full_name,created_at,last_login FROM users ORDER BY created_at DESC",
	)
	if err != nil { jsonErr(w, 500, "DB error"); return }
	defer rows.Close()

	type userRow struct {
		ID        int        `json:"id"`
		Username  string     `json:"username"`
		Email     string     `json:"email"`
		FullName  string     `json:"full_name"`
		CreatedAt time.Time  `json:"created_at"`
		LastLogin *time.Time `json:"last_login"`
	}

	var users []userRow
	for rows.Next() {
		var u userRow
		var ll sql.NullTime
		if rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.CreatedAt, &ll) == nil {
			if ll.Valid { u.LastLogin = &ll.Time }
			users = append(users, u)
		}
	}
	if users == nil { users = []userRow{} }
	jsonOK(w, map[string]interface{}{"success": true, "users": users})
}

// ── admin: get feedback ───────────────────────────────────────
func GetFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Header.Get("X-Admin-User") != "admin" { jsonErr(w, 403, "Admin only"); return }

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
	if err != nil { jsonErr(w, 500, "DB error"); return }
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
	if items == nil { items = []fbRow{} }
	jsonOK(w, map[string]interface{}{"success": true, "feedback": items})
}

// ── admin: update feedback status ─────────────────────────────
func UpdateFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions { w.WriteHeader(200); return }
	if r.Method != http.MethodPost    { jsonErr(w, 405, "Method not allowed"); return }
	if r.Header.Get("X-Admin-User") != "admin" { jsonErr(w, 403, "Admin only"); return }

	var body struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "Invalid JSON"); return
	}

	dbMu.Lock()
	db.Exec("UPDATE feedback SET status=$1 WHERE id=$2", body.Status, body.ID)
	dbMu.Unlock()

	jsonOK(w, map[string]string{"status": "updated"})
}

// ── admin: system stats ───────────────────────────────────────
func SystemStatsHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Header.Get("X-Admin-User") != "admin" { jsonErr(w, 403, "Admin only"); return }

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

// ── import users ──────────────────────────────────────────────
func ImportUsersHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != http.MethodPost { jsonErr(w, 405, "Method not allowed"); return }
	if r.URL.Query().Get("admin") != "admin" { jsonErr(w, 403, "Admin only"); return }

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		jsonErr(w, 400, "File too large"); return
	}
	file, _, err := r.FormFile("file")
	if err != nil { jsonErr(w, 400, "No file uploaded"); return }
	defer file.Close()

	f, err := excelize.OpenReader(file)
	if err != nil { jsonErr(w, 400, "Invalid Excel file"); return }
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 { jsonErr(w, 400, "No sheets found"); return }

	rows, err := f.GetRows(sheets[0])
	if err != nil { jsonErr(w, 500, "Failed to read rows"); return }

	imported, skipped := 0, 0
	for i, row := range rows {
		if i == 0 || len(row) < 3 { continue }
		first := strings.TrimSpace(row[0])
		last  := strings.TrimSpace(row[1])
		uname := strings.TrimSpace(row[2])
		if first == "" || last == "" || uname == "" { skipped++; continue }

		var exists bool
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", uname).Scan(&exists)
		if exists { skipped++; continue }

		dbMu.Lock()
		_, err = db.Exec(
			"INSERT INTO users(username,email,full_name,password_hash) VALUES($1,$2,$3,$4)",
			uname, fmt.Sprintf("%s@local.system", uname), first+" "+last, hashPassword("changeme123"),
		)
		dbMu.Unlock()
		if err != nil { log.Printf("⚠️ Import %s: %v", uname, err); skipped++; continue }
		imported++
	}

	log.Printf("✅ Import: %d in, %d skipped", imported, skipped)
	jsonOK(w, map[string]interface{}{"success": true, "imported": imported, "skipped": skipped})
}
