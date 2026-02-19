# Nexus Audit — Real-Time Compliance Notification System

A full-stack audit notification platform built with Go and vanilla JavaScript. Delivers real-time audit requests between team members via WebSocket, with offline queueing, WhatsApp fallback for unregistered users, and an admin control panel.

---

## Architecture

```
audit-notification/
├── client/
│   ├── fixed-script.js     # Frontend logic (auth, WebSocket, notifications, modals)
│   └── index.html          # Single-page UI
├── cmd/server/
│   └── main.go             # HTTP server entry point, route registration
├── pkg/websocket/
│   └── handler.go          # All handlers: auth, WS, audit, broadcast, admin, import
├── docker-compose.yml      # Local development stack
├── Dockerfile
├── go.mod
├── go.sum
└── .env.example
```

---

## Features

- Real-time audit delivery via WebSocket with automatic reconnection and exponential backoff
- Offline queueing — notifications are persisted and delivered when the target user reconnects
- Notification sync polling as a fallback for idle/backgrounded browser tabs (Page Visibility API)
- User import from Excel (`.xlsx`) — maps to `imported_users` table with floor and WhatsApp metadata
- WhatsApp deep-link generation for users who are offline or not yet registered
- 6-digit recovery passcode for password reset without email dependency
- bcrypt password hashing with automatic SHA-256 legacy migration on login
- Admin panel: user management, broadcast messaging, feedback triage, system stats
- Desktop notification support (Notification API, cross-browser)

---

## Tech Stack

| Layer     | Technology                              |
|-----------|-----------------------------------------|
| Backend   | Go 1.21+                                |
| WebSocket | `github.com/gorilla/websocket`          |
| Database  | PostgreSQL 15                           |
| Driver    | `github.com/lib/pq`                     |
| Excel     | `github.com/xuri/excelize/v2`           |
| Passwords | `golang.org/x/crypto/bcrypt`            |
| Frontend  | Vanilla JS, HTML5, CSS3 (no frameworks) |
| Hosting   | Render (backend + managed Postgres)     |

---

## Prerequisites

- Go 1.21 or later
- PostgreSQL 15 or later
- A `.env` file based on `.env.example`

---

## Local Development

**1. Clone and configure environment**

```bash
git clone <repo-url>
cd audit-notification
cp .env.example .env
# Edit .env — set DATABASE_URL to your local Postgres connection string
```

**2. Run with Docker Compose (recommended)**

```bash
docker-compose up --build
```

**3. Run manually**

```bash
# Start Postgres separately, then:
go run cmd/server/main.go
```

The server starts on port `8080` by default. Open `http://localhost:8080` in your browser.

---

## Environment Variables

| Variable       | Description                              | Required |
|----------------|------------------------------------------|----------|
| `DATABASE_URL` | PostgreSQL connection string             | Yes      |
| `PORT`         | HTTP server port (default: `8080`)       | No       |

---

## Database

The schema is applied automatically on startup via `InitDB()`. All migrations (adding columns, backfilling data) are idempotent and run on every boot — no manual migration steps are needed.

**Core tables:**

- `users` — registered accounts with bcrypt password, optional floor/whatsapp, recovery passcode
- `notifications` — audit messages with delivery state, reply threading, and queue support
- `imported_users` — Excel import roster; tracks registration status and maps to `users`
- `feedback` — user-submitted bug reports and feature requests
- `password_resets` — short-lived tokens (15 min) for passcode-based password reset

---

## Excel Import Format

The admin panel accepts `.xlsx` files. Column order is fixed:

| Column | Field          | Notes                       |
|--------|----------------|-----------------------------|
| A      | First Name     | Required                    |
| B      | Last Name      | Required                    |
| C      | Gitea Username | Required — used as login ID |
| D      | Nickname       | Ignored                     |
| E      | Floor          | Optional — shown in modals  |
| F      | WhatsApp       | Optional — used for WA link |
| G      | Email          | Optional — falls back to `username@local.system` |
| H      | Notes          | Ignored                     |

Users without a Gitea username are treated as unregistered and surfaced with WhatsApp invite links. Imported users who later register are automatically linked via `imported_users.registered_user_id`.

---

## API Reference

| Method | Endpoint                    | Auth         | Description                         |
|--------|-----------------------------|--------------|-------------------------------------|
| POST   | `/register`                 | None         | Create account                      |
| POST   | `/login`                    | None         | Authenticate, returns user object   |
| GET    | `/ws?user=<username>`       | None         | Upgrade to WebSocket                |
| POST   | `/audit`                    | None         | Send audit notification             |
| POST   | `/reply`                    | None         | Reply to a notification             |
| POST   | `/broadcast`                | Admin        | Send to all or online users         |
| GET    | `/online`                   | None/Admin   | List online users; total count for admin only |
| GET    | `/search?q=<query>`         | None         | Search registered + unregistered users |
| GET    | `/sync-notifications`       | None         | Poll for undelivered notifications  |
| POST   | `/mark-delivered`           | None         | Mark notification IDs as delivered  |
| POST   | `/feedback`                 | None         | Submit feedback                     |
| POST   | `/verify-passcode`          | None         | Step 1 of passcode password reset   |
| POST   | `/reset-password-passcode`  | None         | Step 2 — set new password via token |
| POST   | `/import?admin=admin`       | Header       | Upload Excel file                   |
| GET    | `/admin/users`              | Header       | List all registered users           |
| GET    | `/admin/feedback`           | Header       | List all feedback                   |
| POST   | `/admin/feedback/update`    | Header       | Update feedback status              |
| GET    | `/admin/stats`              | Header       | System statistics                   |

Admin endpoints require the header `X-Admin-User: admin`.

---

## Password Reset

Two flows are supported:

**Passcode reset (no email required)**

1. User sets a 6-digit numeric passcode at registration
2. On the login screen, click "Reset via Passcode"
3. Enter username + passcode — backend verifies with bcrypt and issues a 15-minute token
4. Use the token to set a new password
5. Rate limited to 5 attempts per hour per username

---

## Deployment

The application is deployed on [Render](https://render.com).

**Backend service:** `audit-notification.onrender.com`  
**Database:** Render managed PostgreSQL

To deploy a new version, push to the connected branch. Render builds from the `Dockerfile` automatically.

To deploy manually:

```bash
docker build -t nexus-audit .
docker run -e DATABASE_URL=<connection-string> -p 8080:8080 nexus-audit
```

---

## Security Notes

- Passwords are hashed with bcrypt (cost 12). Legacy SHA-256 hashes are auto-migrated on login.
- Recovery passcodes are also bcrypt-hashed — never stored in plain text.
- Admin access is enforced server-side via `X-Admin-User` header check, not client state.
- All user input passed to the DOM goes through an `esc()` sanitiser to prevent XSS.
- CORS is open (`*`) — restrict in production if the frontend is served from a known origin.

---

## Default Credentials (Imported Users)

Users created via Excel import are assigned the default password `changeme123`. They should change this on first login. There is no forced password change flow — consider adding one if required by your security policy.

---

## License

Internal use. Not licensed for public distribution.