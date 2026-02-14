# 🔔 Audit Notification System

Real-time notification system for Gitea users to receive audit requests via WebSocket

## Features

- ✅ Real-time WebSocket notifications
- ✅ Offline notification queuing (SQLite persistence)
- ✅ Gitea user validation
- ✅ Auto-reconnection with exponential backoff
- ✅ Browser notification support
- ✅ Mock mode for development
- ✅ Production-ready error handling

## Prerequisites

- Go 1.21+
- SQLite3
- Modern web browser with WebSocket support
- (Optional) Gitea instance for production

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/jerryjuche/audit-notification-system.git
cd audit-notification-system
```

2. **Install dependencies:**
```bash
go mod download
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Run the server:**
```bash
go run cmd/server/main.go
```

5. **Access the client:**
```
http://localhost:8080
```

## Project Structure

```
audit-notification-system/
├── cmd/
│   └── server/
│       └── main.go              # Server entry point
├── pkg/
│   └── websocket/
│       └── handler.go           # WebSocket handlers
├── client/
│   └── index.html               # Web client
├── go.mod                       # Go dependencies
├── .env.example                 # Configuration template
└── README.md                    # This file
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `DB_PATH` | `./notifications.db` | SQLite database path |
| `GITEA_URL` | `http://localhost:3000` | Gitea instance URL |
| `MOCK_AUTH` | `true` | Enable mock authentication |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

### Mock Mode (Development)

Set `MOCK_AUTH=true` to use test users without Gitea:
- `jerry`
- `admin`
- `test`

### Production Mode

Set `MOCK_AUTH=false` and configure `GITEA_URL` to your Gitea instance.

## Usage

### 1. Connect as User

1. Enter your Gitea username
2. Click "Connect"
3. Grant browser notification permissions (recommended)

### 2. Send Audit Request

1. Enter target username
2. Enter your name
3. Describe what needs auditing
4. Click "Send Audit Request"

### 3. Receive Notifications

- **Online users**: Instant notification
- **Offline users**: Queued and delivered on next connection

## API Endpoints

### WebSocket Connection
```
GET /ws?user=<username>
```

### Send Audit Request
```
POST /audit
Content-Type: application/json

{
  "targetUser": "jerry",
  "requester": "John Doe",
  "details": "Please review PR #123"
}
```

**Response (online):**
```json
{
  "status": "delivered",
  "message": "Notification sent successfully"
}
```

**Response (offline):**
```json
{
  "status": "queued",
  "message": "User offline—notification queued"
}
```

## Development

### Run Tests
```bash
go test ./...
```

### Build for Production
```bash
go build -o audit-server cmd/server/main.go
```

### Enable Live Reload (Optional)
```bash
# Install air
go install github.com/cosmtrek/air@latest

# Run with live reload
air
```

## Deployment

### Deploy to Heroku

1. **Create app:**
```bash
heroku create your-app-name
```

2. **Set environment:**
```bash
heroku config:set MOCK_AUTH=false
heroku config:set GITEA_URL=https://your-gitea.com
```

3. **Deploy:**
```bash
git push heroku main
```

### Deploy to DigitalOcean

1. **Create Droplet** (Ubuntu 22.04)

2. **SSH and setup:**
```bash
ssh root@your-droplet-ip

# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Clone and build
git clone https://github.com/jerryjuche/audit-notification-system.git
cd audit-notification-system
go build -o audit-server cmd/server/main.go
```

3. **Run with systemd:**
```bash
sudo nano /etc/systemd/system/audit-server.service
```

```ini
[Unit]
Description=Audit Notification Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/audit-notification-system
ExecStart=/root/audit-notification-system/audit-server
Restart=always
Environment="PORT=8080"
Environment="MOCK_AUTH=false"

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable audit-server
sudo systemctl start audit-server
```

### Using ngrok (Testing)

```bash
ngrok http 8080
```

Update WebSocket URL in client to use ngrok URL.

## Security Considerations

### For Production:

1. **Enable TLS:**
   - Use `wss://` instead of `ws://`
   - Obtain SSL certificates (Let's Encrypt)
   - Update server to use `ListenAndServeTLS`

2. **Configure CORS:**
   ```go
   ALLOWED_ORIGINS=https://yourdomain.com
   ```

3. **Implement Rate Limiting:**
   ```bash
   go get github.com/didip/tollbooth
   ```

4. **Add Authentication:**
   - Implement OAuth with Gitea
   - Use JWT tokens

5. **Database Security:**
   - Use PostgreSQL for production
   - Encrypt sensitive data
   - Regular backups

## Troubleshooting

### Connection Refused
- Check if server is running: `netstat -an | grep 8080`
- Verify firewall settings
- Check `PORT` environment variable

### Gitea Validation Fails
- Verify `GITEA_URL` is correct
- Check Gitea API is accessible
- Try `MOCK_AUTH=true` for testing

### Notifications Not Delivered
- Check browser notification permissions
- Verify WebSocket connection in browser console
- Check server logs for errors

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

MIT License - see LICENSE file for details

## Contact

Jerry Juche - [@jerryjuche](https://github.com/jerryjuche)

Project Link: [https://github.com/jerryjuche/audit-notification-system](https://github.com/jerryjuche/audit-notification-system)
