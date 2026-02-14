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

	// Initialize database
	websocket.InitDB()

	// WebSocket endpoint
	http.HandleFunc("/ws", websocket.EchoHandler)

	// Audit request endpoint
	http.HandleFunc("/audit", websocket.AuditHandler)

	// Serve static files (HTML client)
	http.Handle("/", http.FileServer(http.Dir("./client")))

	log.Printf("Server starting on :%s", port)
	log.Printf("WebSocket endpoint: ws://localhost:%s/ws", port)
	log.Printf("Client available at: http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
