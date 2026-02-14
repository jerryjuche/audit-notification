# Quick Start Guide

Get the Audit Notification System running in 5 minutes!

## 1. Setup

```bash
# Navigate to project
cd audit-notification-system

# Install dependencies
go mod download

# Copy environment config
cp .env.example .env
```

## 2. Run

```bash
# Start the server
go run cmd/server/main.go
```

You should see:
```
✅ SQLite database initialized successfully
Server starting on :8080
WebSocket endpoint: ws://localhost:8080/ws
Client available at: http://localhost:8080
```

## 3. Test

Open two browser windows at `http://localhost:8080`

**Window 1 (Receiver):**
1. Username: `jerry`
2. Click "Connect"
3. Allow notifications

**Window 2 (Sender):**
1. Username: `admin`
2. Click "Connect"
3. Fill audit form:
   - Target User: `jerry`
   - Your Name: `Admin`
   - Details: `Please review PR #123`
4. Click "Send Audit Request"

Window 1 should receive a notification! 🎉

## 4. Test Offline Mode

1. Disconnect `jerry` (click Disconnect)
2. Send another audit request to `jerry`
3. Reconnect `jerry` - queued notification delivered!

## Available Test Users

When `MOCK_AUTH=true` (default):
- `jerry`
- `admin`
- `test`

## Common Issues

**Port 8080 in use:**
```bash
# Use different port
PORT=3000 go run cmd/server/main.go
```
Update client WebSocket URL accordingly.

**Cannot connect:**
- Check firewall
- Verify server is running
- Try `localhost` vs `127.0.0.1`

## Next Steps

- Read [README.md](README.md) for full documentation
- Check [Deployment](#deployment) section for production
- Review security settings for production use

## Production Checklist

- [ ] Set `MOCK_AUTH=false`
- [ ] Configure real `GITEA_URL`
- [ ] Enable TLS (wss://)
- [ ] Configure CORS properly
- [ ] Set up proper database (PostgreSQL)
- [ ] Implement rate limiting
- [ ] Set up monitoring/logging
- [ ] Use environment secrets manager
