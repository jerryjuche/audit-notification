# 🔥 CRITICAL JAVASCRIPT PATCHES FOR index.html

## DEPLOYMENT INSTRUCTIONS

Your existing `index.html` is ~1676 lines. Apply these patches in the order shown.

---

## PATCH 1: REMOVE EMAIL RESET (Lines ~850-910)

### FIND AND DELETE:
```javascript
// ── forgot password ───────────────────────────────────────────
function showForgot(){
  // ... entire function ...
}

async function sendReset(){
  // ... entire function ...
}
```

### ALSO DELETE FROM HTML (Around line 454):
```html
<div class="divider">or</div>
<button class="bg bfull" onclick="showForgot()" style="font-size:.8125rem">
  <svg class="ic" width="14" height="14"><use href="#ic-mail"/></svg> Forgot Password? Reset via Email
</button>
```

### REPLACE WITH:
```html
<div class="divider">or</div>
<button class="bg bfull" onclick="showPasscodeReset()" style="font-size:.8125rem">
  <svg class="ic" width="14" height="14"><use href="#ic-key"/></svg> Forgot Password? Reset via Passcode
</button>
```

---

## PATCH 2: ADD PASSCODE RESET (After login section, around line 900)

### INSERT THIS CODE:
```javascript
// ══════════════════════════════════════════════════════════════
// PASSCODE RESET FLOW (NEW - FIX FOR ISSUE #2)
// ══════════════════════════════════════════════════════════════
function showPasscodeReset(){
  openModal(
    '<svg class="ic" width="18" height="18"><use href="#ic-key"/></svg> Reset via Recovery Passcode',
    '<div style="background:rgba(30,184,208,.08);border:1px solid rgba(30,184,208,.3);border-radius:10px;padding:12px;margin-bottom:16px;font-size:.85rem;color:var(--t1);line-height:1.6">'+
      '<svg class="ic" width="14" height="14" style="color:var(--cyan);vertical-align:middle;margin-right:6px"><use href="#ic-info"/></svg>'+
      'Use the 6-digit recovery passcode you created during registration.'+
    '</div>'+
    '<div class="fg"><label>Gitea Username</label><div class="inp-wrap"><input id="pcUsername" type="text" placeholder="your-gitea-username" autocomplete="username" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-git"/></svg></div></div>'+
    '<div class="fg"><label>6-Digit Recovery Passcode</label><div class="inp-wrap"><input id="pcCode" type="text" placeholder="000000" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off" style="padding-left:40px;font-family:var(--font-mn);letter-spacing:4px;font-size:1.1rem;text-align:center"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-key"/></svg></div></div>'+
    '<div style="display:flex;gap:10px;justify-content:flex-end">'+
      '<button class="bg bsm" onclick="closeModal()"><svg class="ic" width="13" height="13"><use href="#ic-x"/></svg> Cancel</button>'+
      '<button class="bs bsm" onclick="verifyPasscode()"><svg class="ic" width="13" height="13"><use href="#ic-check"/></svg> Verify Passcode</button>'+
    '</div>'
  );
  document.getElementById('pcCode').addEventListener('input', function(e){
    e.target.value = e.target.value.replace(/\D/g, '').slice(0,6);
  });
}

async function verifyPasscode(){
  var username = document.getElementById('pcUsername').value.trim();
  var passcode = document.getElementById('pcCode').value.trim();
  
  if(!username || !passcode) return toast('Error','Please enter username and passcode','error');
  if(!/^\d{6}$/.test(passcode)) return toast('Error','Passcode must be exactly 6 digits','error');
  
  try{
    var r = await fetch(API+'/verify-passcode', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: username, passcode: passcode})
    });
    
    if(r.status === 429) return toast('Rate Limited','Too many attempts. Please try again in 1 hour.','error',8000);
    if(!r.ok) {
      var msg = await r.text();
      return toast('Error', msg, 'error');
    }
    
    var data = await r.json();
    closeModal();
    toast('Verified','Passcode accepted! Set your new password.','success',3000);
    setTimeout(function(){ showNewPasswordModal(data.token); }, 800);
  }catch(err){
    toast('Error','Verification failed: '+err.message,'error');
  }
}

function showNewPasswordModal(token){
  openModal(
    '<svg class="ic" width="18" height="18"><use href="#ic-lock"/></svg> Set New Password',
    '<div style="background:rgba(34,201,122,.1);border:1px solid rgba(34,201,122,.3);border-radius:10px;padding:12px;margin-bottom:16px;font-size:.85rem;color:var(--green);line-height:1.6">'+
      '<svg class="ic" width="14" height="14" style="vertical-align:middle;margin-right:6px"><use href="#ic-check"/></svg>'+
      'Passcode verified. Choose a secure password.'+
    '</div>'+
    '<div class="fg"><label>New Password</label><div class="inp-wrap pwd-wrap"><input id="newPwdPC" type="password" placeholder="Min 6 characters" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg><button type="button" class="pwd-toggle" onclick="togglePwd(\'newPwdPC\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button></div></div>'+
    '<div class="fg"><label>Confirm Password</label><div class="inp-wrap pwd-wrap"><input id="confirmPwdPC" type="password" placeholder="Repeat password" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg><button type="button" class="pwd-toggle" onclick="togglePwd(\'confirmPwdPC\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button></div></div>'+
    '<button class="bp bfull" onclick="submitPasscodeReset(\''+token+'\')"><svg class="ic" width="16" height="16"><use href="#ic-check"/></svg> Update Password</button>'
  );
}

async function submitPasscodeReset(token){
  var pwd = document.getElementById('newPwdPC').value;
  var conf = document.getElementById('confirmPwdPC').value;
  
  if(!pwd || pwd.length < 6) return toast('Error','Password must be at least 6 characters','error');
  if(pwd !== conf) return toast('Error','Passwords do not match','error');
  
  try{
    var r = await fetch(API+'/reset-password-passcode', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: token, password: pwd})
    });
    
    if(!r.ok) {
      var msg = await r.text();
      return toast('Error', msg, 'error');
    }
    
    closeModal();
    toast('Password Updated','You can now log in with your new password','success',6000);
    swTab('login', document.querySelectorAll('.tab')[0]);
  }catch(err){
    toast('Error','Reset failed: '+err.message,'error');
  }
}
```

---

## PATCH 3: ADD RECOVERY PASSCODE TO REGISTRATION (Around line 430)

### FIND:
```html
<div class="fg">
  <label>Email Address</label>
  <div class="inp-wrap">
    <input id="re" type="email" placeholder="you@company.com" autocomplete="email">
    <svg class="ic inp-ic" width="16" height="16"><use href="#ic-mail"/></svg>
  </div>
</div>
```

### INSERT AFTER IT:
```html
<div class="fg">
  <label>Recovery Passcode (Optional)</label>
  <div class="inp-wrap">
    <input id="rpc" type="text" placeholder="6 digits (e.g., 123456)" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off" style="padding-left:40px;font-family:var(--font-mn);letter-spacing:2px">
    <svg class="ic inp-ic" width="16" height="16"><use href="#ic-key"/></svg>
  </div>
  <div style="font-size:.75rem;color:var(--t2);margin-top:4px">
    Set a 6-digit code to reset your password without email. <strong style="color:var(--amber)">Highly recommended!</strong>
  </div>
</div>
```

### UPDATE register() FUNCTION (Around line 897):
```javascript
async function register(){
  var n=document.getElementById('rn').value.trim();
  var u=document.getElementById('ru').value.trim();
  var e=document.getElementById('re').value.trim();
  var p=document.getElementById('rp').value;
  var pc=document.getElementById('rpc').value.trim(); // NEW: recovery passcode
  
  if(!n||!u||!e||!p) return toast('Error','Name, username, email, and password are required','error');
  if(p.length<6) return toast('Error','Password must be at least 6 characters','error');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return toast('Error','Please enter a valid email address','error');
  
  // Validate passcode if provided
  if(pc && !/^\d{6}$/.test(pc)) return toast('Error','Recovery passcode must be exactly 6 digits (or leave empty)','error');
  
  try{
    var r=await fetch(API+'/register',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u,email:e,full_name:n,password:p,reset_passcode:pc})});
    if(!r.ok){var t2=await r.text();return toast('Error',t2,'error');}
    toast('Account Created','Welcome! Please log in with your credentials.','success');
    swTab('login',document.querySelectorAll('.tab')[0]);
    document.getElementById('lu').value=u;
  }catch(err){toast('Error',err.message,'error');}
}
```

---

## PATCH 4: NOTIFICATION SYNC (CRITICAL - FIX FOR ISSUE #1)

### INSERT AFTER `var auditCount=0;` (Around line 867):

```javascript
// ══════════════════════════════════════════════════════════════
// NOTIFICATION SYNC (NEW - FIX FOR ISSUE #1)
// Intelligent polling with Page Visibility API
// ══════════════════════════════════════════════════════════════
var syncTimer = null;
var lastSync = 0;
var syncInterval = 30000; // 30 seconds
var isTabVisible = true;

// Page Visibility API integration
document.addEventListener('visibilitychange', function(){
  isTabVisible = !document.hidden;
  
  if(isTabVisible && me){
    // Tab became visible — sync immediately
    addLog('Tab visible — syncing notifications', 'info');
    syncNotifications();
  }
  
  // Adjust sync frequency based on visibility
  if(isTabVisible){
    startNotificationSync();
  } else {
    // Tab hidden — reduce frequency to save resources
    clearInterval(syncTimer);
  }
});

function startNotificationSync(){
  if(!me) return;
  
  clearInterval(syncTimer);
  
  // Immediate sync on start
  syncNotifications();
  
  // Periodic sync while tab is visible
  syncTimer = setInterval(function(){
    if(isTabVisible && me){
      syncNotifications();
    }
  }, syncInterval);
}

async function syncNotifications(){
  if(!me) return;
  
  var now = Date.now();
  // Throttle: don't sync more than once every 5 seconds
  if(now - lastSync < 5000) return;
  lastSync = now;
  
  try{
    var r = await fetch(API + '/sync-notifications?user=' + me.username, {
      cache: 'no-cache',
      headers: {'Cache-Control': 'no-cache'}
    });
    
    if(!r.ok) return;
    
    var data = await r.json();
    var notifications = data.notifications || [];
    
    if(notifications.length > 0){
      addLog('Synced ' + notifications.length + ' missed notifications', 'success');
      
      notifications.forEach(function(n){
        playSound(n.replyTo ? 'reply' : 'audit');
        var title = n.replyTo ? ('Reply from @' + n.sender) : ('Audit from @' + n.sender);
        toast(title, n.message, n.replyTo ? 'success' : 'audit', 8000);
        deskNotif(n.sender, n.message);
        
        addNotif({
          id: n.id,
          message: n.message,
          sender: n.sender,
          time: new Date(n.timestamp),
          read: false,
          canReply: !n.replyTo,
          isReply: !!n.replyTo
        });
      });
      
      // Mark them as delivered on backend
      markNotificationsDelivered(notifications.map(function(n){ return n.id; }));
    }
  }catch(err){
    console.error('Sync error:', err);
  }
}

async function markNotificationsDelivered(ids){
  if(!ids || !ids.length) return;
  try{
    await fetch(API + '/mark-delivered', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ids: ids, user: me.username})
    });
  }catch(err){}
}
```

### UPDATE connectWS() FUNCTION (Around line 949):

#### FIND:
```javascript
ws.onopen=function(){
  setConn(true);
  addLog('Connection established','success');
  retries=0; manualDisc=false;
  reqPerm();
  fetchOnline();
  clearInterval(onlineTimer);
  onlineTimer=setInterval(fetchOnline,5000);
};
```

#### REPLACE WITH:
```javascript
ws.onopen=function(){
  setConn(true);
  addLog('Connection established','success');
  retries=0; manualDisc=false;
  reqPerm();
  fetchOnline();
  
  // Start notification sync as safety net
  startNotificationSync();
  
  clearInterval(onlineTimer);
  onlineTimer=setInterval(fetchOnline,5000);
};
```

#### ALSO UPDATE ws.onclose:
```javascript
ws.onclose=function(){
  setConn(false);
  clearInterval(onlineTimer);
  clearInterval(syncTimer); // ADD THIS LINE
  online=[]; renderChips();
  if(!manualDisc){
    var delay=Math.min(1000*Math.pow(2,retries),30000);
    addLog('Reconnecting in '+(delay/1000)+'s…','info');
    setTimeout(connectWS,delay);
    retries++;
  }
};
```

---

## PATCH 5: FIX DROPDOWN CLICKS (CRITICAL - FIX FOR ISSUE #3)

### REPLACE srchUsers() FUNCTION (Around line 1143):

```javascript
// ══════════════════════════════════════════════════════════════
// SEARCH DROPDOWN (FIXED WITH EVENT DELEGATION - ISSUE #3)
// ══════════════════════════════════════════════════════════════
function srchUsers(q){
  clearTimeout(srchTimer);
  var drop = document.getElementById('sdrop');
  
  if(!q || q.length < 2){
    drop.classList.add('hidden');
    return;
  }
  
  srchTimer = setTimeout(async function(){
    try{
      var r = await fetch(API + '/search?q=' + encodeURIComponent(q));
      if(!r.ok) return;
      
      var users = await r.json();
      
      if(!users.length){
        drop.innerHTML = '<div style="padding:14px;text-align:center;color:var(--t2);font-size:.875rem">No users found</div>';
        drop.classList.remove('hidden');
        return;
      }
      
      drop.innerHTML = users.map(function(u){
        if(u.status === 'registered'){
          return '<div class="sitem" data-username="' + esc(u.username) + '" data-status="registered">'+
            '<div style="font-weight:600;font-size:.9rem;color:var(--t0)">' + esc(u.fullName) + '</div>'+
            '<div style="font-size:.78rem;color:var(--t2);font-family:var(--font-mn)">@' + esc(u.username) + '</div>'+
          '</div>';
        } else {
          // Unregistered user
          var dataFloor = u.floor ? ' data-floor="' + esc(u.floor) + '"' : '';
          var dataPhone = u.whatsapp ? ' data-phone="' + esc(u.whatsapp) + '"' : '';
          return '<div class="sitem" data-username="' + esc(u.username) + '" data-status="unregistered"' + dataFloor + dataPhone + ' style="border-left:3px solid var(--amber)">'+
            '<div style="display:flex;align-items:center;gap:6px">'+
              '<svg class="ic" width="14" height="14" style="color:var(--amber)"><use href="#ic-alert"/></svg>'+
              '<span style="font-weight:600;font-size:.9rem;color:var(--t0)">' + esc(u.fullName) + '</span>'+
            '</div>'+
            '<div style="font-size:.78rem;color:var(--t2);font-family:var(--font-mn)">@' + esc(u.username) + ' · Not registered</div>'+
            (u.floor ? '<div style="font-size:.72rem;color:var(--amber);margin-top:2px">🏢 ' + esc(u.floor) + '</div>' : '') +
          '</div>';
        }
      }).join('');
      
      drop.classList.remove('hidden');
      
      // CRITICAL FIX: Event delegation instead of inline onclick
      // This prevents z-index and pointer-events conflicts
      drop.querySelectorAll('.sitem').forEach(function(item){
        item.addEventListener('click', function(e){
          e.stopPropagation();
          var username = item.getAttribute('data-username');
          var status = item.getAttribute('data-status');
          
          if(status === 'registered'){
            pickUser(username);
          } else {
            // Show offline/unregistered modal
            var fullName = item.textContent.match(/@(\S+)/)?.[0].replace('@','') || username;
            var floor = item.getAttribute('data-floor') || '';
            var phone = item.getAttribute('data-phone') || '';
            
            // Find full user info
            var userInfo = users.find(function(u){ return u.username === username; });
            if(userInfo) showOfflineUserModal(username, userInfo);
          }
        });
      });
      
    }catch(err){
      console.error('Search error:', err);
    }
  }, 300);
}

function pickUser(u){
  document.getElementById('tUser').value = u;
  document.getElementById('sdrop').classList.add('hidden');
  document.getElementById('aDetail').focus();
}
```

### UPDATE CSS (Add to <style> section around line 180):
```css
/* DROPDOWN FIX - Z-INDEX AND POINTER EVENTS */
.sdrop{
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  right: 0;
  background: var(--c3);
  border: 1px solid var(--br1);
  border-radius: var(--r-md);
  max-height: 260px;
  overflow-y: auto;
  z-index: 1000; /* INCREASED FROM 100 */
  box-shadow: var(--sh-lg);
  animation: drop-in .2s var(--tr);
  pointer-events: auto; /* EXPLICITLY SET */
}

.sitem{
  padding: 10px 14px;
  cursor: pointer;
  border-bottom: 1px solid var(--br0);
  transition: background var(--tr);
  pointer-events: auto; /* CRITICAL FIX */
  user-select: none; /* PREVENT TEXT SELECTION INTERFERING WITH CLICK */
}

.sitem:hover{
  background: var(--c4);
}

.sitem:last-child{
  border-bottom: none;
}
```

---

## PATCH 6: OFFLINE USER MODAL (FIX FOR ISSUE #4)

### INSERT AFTER pickUser() FUNCTION:

```javascript
// ══════════════════════════════════════════════════════════════
// OFFLINE/UNREGISTERED USER MODAL (PROFESSIONAL - ISSUE #4)
// ══════════════════════════════════════════════════════════════
function showOfflineUserModal(username, userInfo){
  if(!userInfo){
    toast('Error', 'User information not available', 'error');
    return;
  }
  
  var name = userInfo.fullName || username;
  var floor = userInfo.floor || 'Unknown';
  var phone = userInfo.whatsapp || '';
  
  // Build WhatsApp URL
  var waUrl = '';
  if(phone){
    var cleanPhone = phone.replace(/\D/g, '');
    var senderName = me && me.full_name ? me.full_name : (me ? me.username : 'Nexus Audit');
    var waText = 'Hi ' + name + (floor !== 'Unknown' ? ' (' + floor + ')' : '') + ',\n\n' +
      'This is ' + senderName + ' reaching out from Nexus Audit.\n\n' +
      'You have been requested for an audit. Please register on the Nexus Audit platform to receive real-time notifications:\n' +
      'https://audit-notification.onrender.com\n\n' +
      'Your registration details:\n- Use your Gitea username: ' + username + '\n\n' +
      'Please confirm receipt of this message.\n\nThank you.';
    
    waUrl = 'https://wa.me/' + cleanPhone + '?text=' + encodeURIComponent(waText);
  }
  
  var contactSection = phone ?
    '<a href="' + waUrl + '" target="_blank" rel="noopener noreferrer" class="wa-btn" style="margin-top:16px">' +
      '<svg class="ic" width="15" height="15"><use href="#ic-whatsapp"/></svg> Send WhatsApp Invite' +
    '</a>' :
    '<div style="background:rgba(239,69,101,.1);border:1px solid rgba(239,69,101,.3);padding:10px 14px;border-radius:8px;margin-top:16px;font-size:.85rem;color:var(--red)">' +
      '<svg class="ic" width="14" height="14" style="vertical-align:middle;margin-right:6px"><use href="#ic-alert"/></svg>' +
      'No contact information available for this user.' +
    '</div>';
  
  openModal(
    '<svg class="ic" width="18" height="18" style="color:var(--amber)"><use href="#ic-alert"/></svg> User Not Available',
    '<div style="text-align:center;padding:10px 0">' +
      '<div style="background:rgba(245,158,58,.08);border:1px solid rgba(245,158,58,.3);border-radius:10px;padding:14px;margin-bottom:20px">' +
        '<div style="font-weight:700;font-size:1.05rem;color:var(--t0);margin-bottom:8px;font-family:var(--font-hd)">' + esc(name) + '</div>' +
        '<div style="display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-top:10px">' +
          '<span class="unreg-pill pill-floor"><svg class="ic" width="11" height="11"><use href="#ic-building"/></svg> ' + esc(floor) + '</span>' +
          (phone ? '<span class="unreg-pill pill-phone"><svg class="ic" width="11" height="11"><use href="#ic-phone"/></svg> ' + esc(phone) + '</span>' : '') +
          '<span style="background:rgba(239,69,101,.12);color:var(--red);border:1px solid rgba(239,69,101,.25);padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:500;font-family:var(--font-hd)">Not Registered</span>' +
        '</div>' +
      '</div>' +
      '<p style="font-size:.875rem;color:var(--t2);margin-bottom:16px;line-height:1.6">' +
        'This user is not registered on Nexus Audit yet. You can reach them via WhatsApp to request registration.' +
      '</p>' +
      contactSection +
      '<button class="bg bfull" onclick="closeModal()" style="margin-top:16px">' +
        '<svg class="ic" width="14" height="14"><use href="#ic-x"/></svg> Close' +
      '</button>' +
    '</div>'
  );
}
```

### UPDATE sendAudit() FUNCTION (Around line 1176):

#### FIND:
```javascript
async function sendAudit(){
  if(!ws||ws.readyState!==WebSocket.OPEN) return toast('Error','Please connect first','error');
  var target=document.getElementById('tUser').value.trim();
  var detail=document.getElementById('aDetail').value.trim();
  if(!target||!detail) return toast('Error','All fields are required','error');
```

#### REPLACE WITH:
```javascript
async function sendAudit(){
  if(!ws||ws.readyState!==WebSocket.OPEN) return toast('Error','Please connect first','error');
  var target=document.getElementById('tUser').value.trim();
  var detail=document.getElementById('aDetail').value.trim();
  if(!target||!detail) return toast('Error','All fields are required','error');
  
  // Check if user is online first
  var isOnline = online.indexOf(target) > -1;
  
  if(!isOnline){
    // User is offline — check if they're registered
    try{
      var searchR = await fetch(API + '/search?q=' + encodeURIComponent(target));
      if(searchR.ok){
        var users = await searchR.json();
        var user = users.find(function(u){ return u.username === target; });
        
        if(user && user.status === 'unregistered'){
          showOfflineUserModal(target, user);
          return;
        }
      }
    }catch(e){}
    
    // Registered but offline — show warning
    if(!confirm(target + ' is currently offline. Send audit anyway? (They will receive it when they connect)')){
      return;
    }
  }
```

### CONTINUE WITH ORIGINAL sendAudit() LOGIC:

```javascript
  try{
    var r=await fetch(API+'/audit',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({targetUser:target,requester:me.username,details:detail})});
    
    var d=await r.json();
    
    // Handle unregistered user response from backend
    if(d.error==='user_not_registered' && d.user_info){
      closeModal();
      showOfflineUserModal(target, {
        fullName: d.user_info.name,
        floor: d.user_info.floor,
        whatsapp: d.user_info.phone,
        status: 'unregistered'
      });
      return;
    }
    
    if(!r.ok) throw new Error('Send failed');
    toast('Audit Sent',d.message,'success',3000);
    addLog('Audit dispatched to @'+target,'success');
    document.getElementById('tUser').value='';
    document.getElementById('aDetail').value='';
    auditCount++; localStorage.setItem('ac',auditCount);
    document.getElementById('sAud').textContent=auditCount;
  }catch(err){toast('Error',err.message,'error');}
}
```

---

## PATCH 7: ERROR HANDLERS (SYSTEM INTEGRITY - ISSUE #5)

### ADD AT END OF window.onload (Around line 1630):

```javascript
// Error tracking for production debugging
window.onerror = function(msg, url, line, col, error){
  console.error('❌ Runtime error:', msg, 'at', url + ':' + line + ':' + col);
  addLog('Error: ' + msg, 'error');
  return false;
};

// Unhandled promise rejection
window.onunhandledrejection = function(event){
  console.error('❌ Unhandled promise rejection:', event.reason);
  addLog('Promise error: ' + event.reason, 'error');
};
```

---

## DEPLOYMENT VERIFICATION

After applying all patches:

1. **Clear browser cache** (Ctrl+Shift+Del)
2. **Hard reload** (Ctrl+Shift+R)
3. **Open DevTools Console** — verify no errors
4. **Test checklist:**
   - [ ] Dropdown clicks work (both registered + unregistered)
   - [ ] Notifications sync without refresh (minimize tab, wait 30s, maximize)
   - [ ] Email reset button removed from login
   - [ ] Passcode reset modal works (6 digits only)
   - [ ] Offline user modal displays with WhatsApp button
   - [ ] Recovery passcode field in registration
   - [ ] No console errors

---

## EMERGENCY ROLLBACK

If issues occur, restore from backup:
```bash
cp client/index.html.backup client/index.html
```

---

## SUCCESS INDICATORS

✅ No "404" errors in Network tab
✅ No "Uncaught" errors in Console
✅ Dropdown items are clickable
✅ Notifications appear within 30s without refresh
✅ Page Visibility API logs: "Tab visible — syncing notifications"
✅ WebSocket reconnects after idle period
