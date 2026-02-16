// cmd/server/main.go
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

	log.Println("Initializing database...")
	// Initialize database
	websocket.InitDB()
	log.Println("Database initialized")

	// WebSocket endpoint
	http.HandleFunc("/ws", websocket.EchoHandler)

	// User management endpoints
	http.HandleFunc("/register", websocket.RegisterHandler)
	http.HandleFunc("/login", websocket.LoginHandler)
	http.HandleFunc("/import", websocket.ImportUsersHandler)
	http.HandleFunc("/search", websocket.SearchUsersHandler)

	// Audit request endpoint
	http.HandleFunc("/audit", websocket.AuditHandler)
	http.HandleFunc("/reply", websocket.ReplyHandler)

	// Online users endpoint
	http.HandleFunc("/online", websocket.OnlineUsersHandler)

	// Serve static files (HTML client)
	http.Handle("/", http.FileServer(http.Dir("./client")))

	log.Printf("Server starting on :%s", port)
	log.Printf("WebSocket endpoint: ws://localhost:%s/ws", port)
	log.Printf("Client available at: http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
