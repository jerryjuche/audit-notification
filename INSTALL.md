# Installation Instructions

## Quick Install (Copy-Paste Method)

1. **Download all files** to your project directory
2. **Verify structure:**
   ```
   audit-notification-system/
   ├── cmd/server/main.go
   ├── pkg/websocket/handler.go
   ├── pkg/websocket/handler_test.go
   ├── client/index.html
   ├── go.mod
   ├── .env.example
   ├── .gitignore
   └── ... (other files)
   ```

3. **Run setup:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

4. **Start server:**
   ```bash
   make run
   # OR
   go run cmd/server/main.go
   ```

5. **Open browser:** http://localhost:8080

## What Changed

✅ Fixed main.go server startup bug
✅ Improved error handling throughout
✅ Added professional UI
✅ Added offline notification queue
✅ Added auto-reconnection
✅ Added comprehensive documentation
✅ Made production-ready

## Files to Replace

Replace these in your project:
- `cmd/server/main.go` - Fixed server startup
- `pkg/websocket/handler.go` - Improved handlers
- `client/index.html` - Modern UI

Add these new files:
- `.env.example` - Configuration template
- `.gitignore` - Git ignore rules
- `Dockerfile` - Containerization
- `docker-compose.yml` - Easy deployment
- `Makefile` - Common tasks
- `setup.sh` - Quick setup
- `README.md` - Full docs
- `QUICKSTART.md` - Quick guide
- `PROJECT_FIXES.md` - What was fixed
- `pkg/websocket/handler_test.go` - Tests

## Test It Works

```bash
# Terminal 1: Start server
make run

# Terminal 2: Test with curl
curl -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{"targetUser":"jerry","requester":"admin","details":"test"}'
```

## Troubleshooting

**"command not found: make"**
- Use `go run cmd/server/main.go` instead

**"port already in use"**
- Change port: `PORT=3000 go run cmd/server/main.go`

**"cannot connect"**
- Ensure server is running
- Check firewall settings
- Try 127.0.0.1 instead of localhost

Need help? Read PROJECT_FIXES.md for details!
