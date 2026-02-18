# Testing Your Fixed Email System

## 1. Set Environment Variables (with proper FROM address)

```bash
export SMTP_HOST=live.smtp.mailtrap.io
export SMTP_PORT=587
export SMTP_USER=smtp@mailtrap.io
export SMTP_PASS=4520b63f06383b4f7b9b9acc3b4a995b
export SMTP_FROM=noreply@demomailtrap.com  # ← THIS IS THE CRITICAL FIX
export APP_URL=https://audit-notification.onrender.com
```

**Why `@demomailtrap.com`?**
- Mailtrap's **shared sending domain** for free/dev accounts
- You can send from ANY address ending in `@demomailtrap.com`
- Examples: `support@demomailtrap.com`, `no-reply@demomailtrap.com`, `alerts@demomailtrap.com`

## 2. Deploy to Render

In Render Dashboard → Environment:
```
SMTP_HOST=live.smtp.mailtrap.io
SMTP_PORT=587
SMTP_USER=smtp@mailtrap.io
SMTP_PASS=4520b63f06383b4f7b9b9acc3b4a995b
SMTP_FROM=noreply@demomailtrap.com
APP_URL=https://audit-notification.onrender.com
```

Click **"Manual Deploy"** → **"Deploy latest commit"**

## 3. Test Password Reset

1. Register a test account with a **real email** (one you can check)
2. Click **"Forgot Password? Reset via Email"**
3. Enter your email
4. Check your **Mailtrap inbox** at: https://mailtrap.io/inboxes
5. Click the reset link
6. Set new password

## 4. Check Logs (if it still fails)

```bash
# In Render logs, you'll now see:
📧 Sending email: smtp@mailtrap.io → you@email.com via live.smtp.mailtrap.io:587 (from: noreply@demomailtrap.com)
✅ Email delivered to you@email.com
```

## 5. What Changed in the Code?

**Before (BROKEN):**
```go
from := getEnv("SMTP_FROM", user)  // Falls back to smtp@mailtrap.io ❌
```

**After (FIXED):**
```go
from := getEnv("SMTP_FROM", "")
if from == "" && strings.Contains(host, "mailtrap") {
    from = "noreply@demomailtrap.com"  // ✅ Mailtrap's allowed domain
}
```

## 6. Common Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `550 5.7.1 Sending from domain mailtrap.io is not allowed` | Using `@mailtrap.io` as FROM | Set `SMTP_FROM=noreply@demomailtrap.com` |
| `535 Authentication failed` | Wrong SMTP_USER or SMTP_PASS | Double-check credentials in Mailtrap dashboard |
| `SMTP not configured` | Missing env vars | Set all 5: HOST, PORT, USER, PASS, FROM |
| Email never arrives | Wrong Mailtrap inbox | Check https://mailtrap.io/inboxes (not your real email) |

## 7. Production Readiness

**For production with real emails:**
1. Verify your own domain in Mailtrap's "Sending Domains"
2. Update `SMTP_FROM=noreply@yourdomain.com`
3. Or switch to SendGrid/AWS SES/Mailgun for production volume

**Current setup (Mailtrap test):**
- ✅ Works for development/testing
- ✅ Catches all emails in Mailtrap inbox
- ❌ Does NOT deliver to real inboxes (by design)

---

## Quick Verification Checklist

- [ ] `SMTP_FROM` ends with `@demomailtrap.com`
- [ ] All 5 env vars set in Render
- [ ] Redeployed after env var changes
- [ ] Test user registered with real email
- [ ] Password reset email shows in Mailtrap inbox
- [ ] Reset link works and updates password
