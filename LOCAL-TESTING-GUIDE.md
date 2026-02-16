# Local Testing Guide

## Setup

### 1. Install Dependencies
```bash
cd ~/Desktop/audit-notification

# Download Go modules
go mod download

# Verify installation
go version  # Should show Go 1.21 or higher
```

### 2. File Structure Check
```bash
# Make sure you have these files
ls -la
# Should see:
# - cmd/server/main.go
# - pkg/websocket/handler.go
# - client/index.html
# - go.mod
# - go.sum
# - Dockerfile
```

### 3. Replace Files
```bash
# Replace with new files
cp client/index-final.html client/index.html
cp pkg/websocket/handler-final.go pkg/websocket/handler.go
```

## Run Locally

### Method 1: Direct Run
```bash
# Run server
go run cmd/server/main.go

# You should see:
# 🚀 Server starting on port 8080
# 📡 WebSocket endpoint: ws://localhost:8080/ws
# 🌐 Client available at: http://localhost:8080
```

### Method 2: Build and Run
```bash
# Build binary
go build -o audit-server cmd/server/main.go

# Run binary
./audit-server

# Clean build cache if issues
go clean -cache
```

## Testing Steps

### 1. Open Browser
```
http://localhost:8080
```

### 2. Create Admin Account
- Click "Register"
- Full Name: Administrator
- Username: admin
- Password: admin123
- Click "Create Account"

### 3. Login as Admin
- Username: admin
- Password: admin123
- Click "Login"

### 4. Click "Connect"
- Status should turn green
- "Connected" badge appears

### 5. Test in Second Browser/Incognito
```
Open: http://localhost:8080 in incognito/different browser
```

### 6. Register Second User
- Full Name: Test User
- Username: testuser
- Password: test123

### 7. Login Second User
- Click "Connect"

### 8. Send Audit (from admin to testuser)
In admin browser:
- Target User: testuser
- Details: "Please review document"
- Click "Send Request"

### 9. Check Notification (in testuser browser)
- Should see notification popup
- Sound should play
- Bell icon shows unread count
- Desktop notification if enabled

### 10. Test Reply
In testuser browser:
- Click bell icon
- Click "Reply" button
- Type: "Acknowledged, reviewing now"
- Click "Send Reply"

### 11. Check Reply (in admin browser)
- Should receive reply notification
- Different sound for replies

## Troubleshooting

### Server Won't Start
```bash
# Check if port 8080 is in use
lsof -i :8080

# Kill process if found
kill -9 <PID>

# Or use different port
PORT=3000 go run cmd/server/main.go
```

### Database Issues
```bash
# Delete old database
rm notifications.db

# Restart server (will create fresh DB)
go run cmd/server/main.go
```

### Module Issues
```bash
# Clean modules
go clean -modcache

# Reinstall
go mod download

# Tidy up
go mod tidy
```

### WebSocket Not Connecting
- Check browser console (F12) for errors
- Make sure URLs use `ws://localhost:8080` not `wss://`
- Disable browser extensions
- Try incognito mode

### Notifications Not Working
- Check browser notification permissions
- Look for JavaScript errors in console
- Verify sound URLs are accessible
- Test with volume turned up

## Debug Mode

### Enable Verbose Logging
Add to main.go:
```go
log.SetFlags(log.LstdFlags | log.Lshortfile)
```

### Check Database
```bash
sqlite3 notifications.db

# List tables
.tables

# View users
SELECT * FROM users;

# View notifications
SELECT * FROM notifications;

# Exit
.quit
```

### Monitor Real-time
```bash
# Watch server logs
go run cmd/server/main.go 2>&1 | tee server.log

# In another terminal, tail logs
tail -f server.log
```

## Performance Testing

### Multiple Users
```bash
# Open multiple browsers/tabs:
# - Chrome
# - Firefox
# - Chrome Incognito
# - Edge

# Register different users in each
# Test cross-browser notifications
```

### Load Testing
```bash
# Send rapid audits
# Monitor server logs
# Check for memory leaks
# Verify all notifications delivered
```

## Ready to Deploy?

### Pre-Deploy Checklist
- ✅ All notifications working
- ✅ Reply system functional
- ✅ Sounds playing correctly
- ✅ Multiple users tested
- ✅ No console errors
- ✅ Database persisting
- ✅ WebSocket reconnecting

### Deploy
```bash
# Commit changes
git add .
git commit -m "Fixed notifications and reply system"
git push origin master

# Render will auto-deploy in 2-3 minutes
# Monitor at: https://dashboard.render.com
```

## Common Test Scenarios

### Scenario 1: User Offline
1. User A sends audit to User B (offline)
2. Notification queued in database
3. User B logs in later
4. Should receive queued notification

### Scenario 2: Network Loss
1. User connected
2. Disconnect internet
3. Reconnect internet
4. Should auto-reconnect within 30 seconds

### Scenario 3: Multiple Tabs
1. Open same user in 2 tabs
2. Only first tab connects (prevents duplicates)
3. Second tab shows "already connected" error

### Scenario 4: Rapid Notifications
1. Send 10 audits quickly
2. All should arrive
3. All should have reply buttons
4. Sounds should play for each

## Success Criteria

✅ Registration works
✅ Login works
✅ WebSocket connects
✅ Notifications arrive in <1 second
✅ Sounds play
✅ Desktop notifications work
✅ Reply system works
✅ Offline queuing works
✅ Multiple users work simultaneously
✅ No JavaScript errors
✅ No server crashes
✅ Database persists across restarts

If all tests pass → READY TO DEPLOY! 🚀
