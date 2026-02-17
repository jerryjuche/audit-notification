package main

import (
	"log"
	"net/http"
	"os"

	"github.com/jerryjuche/audit-notification/pkg/websocket"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	websocket.InitDB()

	// WebSocket
	http.HandleFunc("/ws", websocket.EchoHandler)

	// Auth
	http.HandleFunc("/register", websocket.RegisterHandler)
	http.HandleFunc("/login",    websocket.LoginHandler)

	// Users & Search
	http.HandleFunc("/search", websocket.SearchUsersHandler)
	http.HandleFunc("/online", websocket.OnlineUsersHandler)

	// Communication
	http.HandleFunc("/audit",     websocket.AuditHandler)
	http.HandleFunc("/reply",     websocket.ReplyHandler)
	http.HandleFunc("/broadcast", websocket.BroadcastHandler)
	http.HandleFunc("/feedback",  websocket.FeedbackHandler)

	// Admin
	http.HandleFunc("/import",                 websocket.ImportUsersHandler)
	http.HandleFunc("/admin/users",            websocket.GetAllUsersHandler)
	http.HandleFunc("/admin/feedback",         websocket.GetFeedbackHandler)
	http.HandleFunc("/admin/feedback/update",  websocket.UpdateFeedbackHandler)
	http.HandleFunc("/admin/stats",            websocket.SystemStatsHandler)

	// Static files
	http.Handle("/", http.FileServer(http.Dir("./client")))

	log.Printf("🚀 Server starting on :%s", port)
	log.Printf("📡 WebSocket : ws://localhost:%s/ws", port)
	log.Printf("🌐 Client    : http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("❌ Server error: %v", err)
	}
}
