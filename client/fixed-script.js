// ── config ────────────────────────────────────────────────────
const API = location.hostname === 'localhost' ? 'http://localhost:8080' : 'https://audit-notification.onrender.com';
const WSS = location.hostname === 'localhost' ? 'ws://localhost:8080' : 'wss://audit-notification.onrender.com';

// ── sounds ────────────────────────────────────────────────────
const SND = {
  audit: new Audio('https://assets.mixkit.co/active_storage/sfx/2354/2354-preview.mp3'),
  reply: new Audio('https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3'),
  success: new Audio('https://assets.mixkit.co/active_storage/sfx/2568/2568-preview.mp3'),
};
Object.values(SND).forEach(function (a) { a.volume = 1.0; });
function playSound(t) { var s = SND[t] || SND.audit; s.currentTime = 0; s.play().catch(function () { }); }

// ── state ─────────────────────────────────────────────────────
var ws = null, me = null, manualDisc = false, retries = 0;
var notifs = [], unread = 0, online = [], auditCount = 0;
var userList = [], onlineTimer = null, srchTimer = null;
var isBulkOperation = false;

// NOTIFICATION SYNC
var syncTimer = null;
var lastSync = 0;
var syncInterval = 4000;
var isTabVisible = true;

document.addEventListener('visibilitychange', function () {
  isTabVisible = !document.hidden;
  if (isTabVisible && me) {
    addLog('Tab visible — syncing notifications', 'info');
    syncNotifications();
  }
  if (isTabVisible) {
    clearInterval(syncTimer);
    syncTimer = setInterval(function () {
      if (me) syncNotifications();
    }, 4000); // 5 seconds when visible
  } else {
    // DON'T STOP - just slow down
    clearInterval(syncTimer);
    syncTimer = setInterval(function () {
      if (me) syncNotifications();
    }, 4000); // 15 seconds when hidden
  }
});
function startNotificationSync() {
  if (!me) return;
  clearInterval(syncTimer);
  syncNotifications();
  syncTimer = setInterval(function () {
    if (isTabVisible && me) syncNotifications();
  }, syncInterval);
}

async function syncNotifications() {
  if (!me) return;
  var now = Date.now();
  if (now - lastSync < 4000) return;
  lastSync = now;
  try {
    var r = await fetch(API + '/sync-notifications?user=' + me.username, {
      cache: 'no-cache',
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (!r.ok) return;
    var data = await r.json();
    var notifications = data.notifications || [];
    if (notifications.length > 0) {
      addLog('Synced ' + notifications.length + ' missed notifications', 'success');
      notifications.forEach(function (n) {
        playSound(n.replyTo ? 'reply' : 'audit');
        var title = n.replyTo ? ('Reply from @' + n.sender) : ('Audit from @' + n.sender);
        toast(title, n.message, n.replyTo ? 'success' : 'audit', 8000);
        deskNotif(n.sender, n.message);
        addNotif({
          id: n.id, message: n.message, sender: n.sender,
          time: new Date(n.timestamp), read: false,
          canReply: !n.replyTo, isReply: !!n.replyTo
        });
      });
      markNotificationsDelivered(notifications.map(function (n) { return n.id; }));
    }
  } catch (err) { console.error('Sync error:', err); }
}

async function markNotificationsDelivered(ids) {
  if (!ids || !ids.length) return;
  try {
    await fetch(API + '/mark-delivered', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: ids, user: me.username })
    });
  } catch (err) { }
}

// ── password toggle ───────────────────────────────────────────
function togglePwd(id, btn) {
  var inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

// ── PASSCODE RESET FLOW ───────────────────────────────────────
function showPasscodeReset() {
  openModal(
    '<svg class="ic" width="18" height="18"><use href="#ic-key"/></svg> Reset via Recovery Passcode',
    '<div style="background:rgba(30,184,208,.08);border:1px solid rgba(30,184,208,.3);border-radius:10px;padding:12px;margin-bottom:16px;font-size:.85rem;color:var(--t1);line-height:1.6">' +
    '<svg class="ic" width="14" height="14" style="color:var(--cyan);vertical-align:middle;margin-right:6px"><use href="#ic-info"/></svg>' +
    'Use the 6-digit recovery passcode you created during registration.' +
    '</div>' +
    '<div class="fg"><label>Gitea Username</label><div class="inp-wrap"><input id="pcUsername" type="text" placeholder="your-gitea-username" autocomplete="username" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-git"/></svg></div></div>' +
    '<div class="fg"><label>6-Digit Recovery Passcode</label><div class="inp-wrap"><input id="pcCode" type="text" placeholder="000000" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off" style="padding-left:40px;font-family:var(--font-mn);letter-spacing:4px;font-size:1.1rem;text-align:center"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-key"/></svg></div></div>' +
    '<div style="display:flex;gap:10px;justify-content:flex-end">' +
    '<button class="bg bsm" onclick="closeModal()"><svg class="ic" width="13" height="13"><use href="#ic-x"/></svg> Cancel</button>' +
    '<button class="bs bsm" onclick="verifyPasscode()"><svg class="ic" width="13" height="13"><use href="#ic-check"/></svg> Verify Passcode</button>' +
    '</div>'
  );
  document.getElementById('pcCode').addEventListener('input', function (e) {
    e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
  });
}

async function verifyPasscode() {
  var username = document.getElementById('pcUsername').value.trim();
  var passcode = document.getElementById('pcCode').value.trim();
  if (!username || !passcode) return toast('Error', 'Please enter username and passcode', 'error');
  if (!/^\d{6}$/.test(passcode)) return toast('Error', 'Passcode must be exactly 6 digits', 'error');
  try {
    var r = await fetch(API + '/verify-passcode', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, passcode: passcode })
    });
    if (r.status === 429) return toast('Rate Limited', 'Too many attempts. Please try again in 1 hour.', 'error', 8000);
    if (!r.ok) { var msg = await r.text(); return toast('Error', msg, 'error'); }
    var data = await r.json();
    closeModal();
    toast('Verified', 'Passcode accepted! Set your new password.', 'success', 3000);
    setTimeout(function () { showNewPasswordModal(data.token); }, 800);
  } catch (err) { toast('Error', 'Verification failed: ' + err.message, 'error'); }
}

function showNewPasswordModal(token) {
  openModal(
    '<svg class="ic" width="18" height="18"><use href="#ic-lock"/></svg> Set New Password',
    '<div style="background:rgba(34,201,122,.1);border:1px solid rgba(34,201,122,.3);border-radius:10px;padding:12px;margin-bottom:16px;font-size:.85rem;color:var(--green);line-height:1.6">' +
    '<svg class="ic" width="14" height="14" style="vertical-align:middle;margin-right:6px"><use href="#ic-check"/></svg>' +
    'Passcode verified. Choose a secure password.' +
    '</div>' +
    '<div class="fg"><label>New Password</label><div class="inp-wrap pwd-wrap"><input id="newPwdPC" type="password" placeholder="Min 6 characters" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg><button type="button" class="pwd-toggle" onclick="togglePwd(\'newPwdPC\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button></div></div>' +
    '<div class="fg"><label>Confirm Password</label><div class="inp-wrap pwd-wrap"><input id="confirmPwdPC" type="password" placeholder="Repeat password" style="padding-left:40px"><svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg><button type="button" class="pwd-toggle" onclick="togglePwd(\'confirmPwdPC\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button></div></div>' +
    '<button class="bp bfull" onclick="submitPasscodeReset(\'' + token + '\')"><svg class="ic" width="16" height="16"><use href="#ic-check"/></svg> Update Password</button>'
  );
}

async function submitPasscodeReset(token) {
  var pwd = document.getElementById('newPwdPC').value;
  var conf = document.getElementById('confirmPwdPC').value;
  if (!pwd || pwd.length < 6) return toast('Error', 'Password must be at least 6 characters', 'error');
  if (pwd !== conf) return toast('Error', 'Passwords do not match', 'error');
  try {
    var r = await fetch(API + '/reset-password-passcode', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token, password: pwd })
    });
    if (!r.ok) { var msg = await r.text(); return toast('Error', msg, 'error'); }
    closeModal();
    toast('Password Updated', 'You can now log in with your new password', 'success', 6000);
    swTab('login', document.querySelectorAll('.tab')[0]);
  } catch (err) { toast('Error', 'Reset failed: ' + err.message, 'error'); }
}

// ── generic modal ─────────────────────────────────────────────
function openModal(title, body) {
  var m = document.createElement('div');
  m.className = 'mover';
  m.id = 'genModal';
  m.setAttribute('role', 'dialog');
  m.setAttribute('aria-modal', 'true');
  m.setAttribute('aria-labelledby', 'modalTitle');
  m.innerHTML = '<div class="modal" role="document"><div class="mtitle" id="modalTitle">' + title + '</div>' + body + '</div>';
  document.body.appendChild(m);
  m.addEventListener('click', function (e) { if (e.target === m) closeModal(); });
  setTimeout(function () {
    var focusable = m.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable.length) focusable[0].focus();
  }, 100);
}
function closeModal() { var m = document.getElementById('genModal'); if (m) m.remove(); }

// ── tabs ──────────────────────────────────────────────────────
function swTab(t, btn) {
  document.querySelectorAll('.tab').forEach(function (x) { x.classList.remove('on'); });
  if (btn) btn.classList.add('on');
  document.getElementById('loginTab').classList.toggle('hidden', t !== 'login');
  document.getElementById('regTab').classList.toggle('hidden', t !== 'reg');
}

// ── register ──────────────────────────────────────────────────
async function register() {
  var n = document.getElementById('rn').value.trim();
  var u = document.getElementById('ru').value.trim();
  var e = document.getElementById('re').value.trim();
  var p = document.getElementById('rp').value;
  var pc = document.getElementById('rpc').value.trim();

  if (!n || !u || !e || !p) return toast('Error', 'Name, username, email, and password are required', 'error');
  if (p.length < 6) return toast('Error', 'Password must be at least 6 characters', 'error');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return toast('Error', 'Please enter a valid email address', 'error');
  if (pc && !/^\d{6}$/.test(pc)) return toast('Error', 'Recovery passcode must be exactly 6 digits (or leave empty)', 'error');

  try {
    var r = await fetch(API + '/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, email: e, full_name: n, password: p, reset_passcode: pc })
    });
    if (!r.ok) { var t2 = await r.text(); return toast('Error', t2, 'error'); }
    toast('Account Created', 'Welcome! Please log in with your credentials.', 'success');
    swTab('login', document.querySelectorAll('.tab')[0]);
    document.getElementById('lu').value = u;
  } catch (err) { toast('Error', err.message, 'error'); }
}

// ── login ─────────────────────────────────────────────────────
async function login() {
  var u = document.getElementById('lu').value.trim();
  var p = document.getElementById('lp').value;
  if (!u || !p) return toast('Error', 'Username and password required', 'error');
  try {
    var r = await fetch(API + '/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    if (!r.ok) return toast('Error', 'Invalid credentials. Please try again.', 'error');
    var d = await r.json();
    me = d.user;
    localStorage.setItem('me', JSON.stringify(me));
    showApp();
  } catch (err) { toast('Error', 'Login failed: ' + err.message, 'error'); }
}

// ── logout ────────────────────────────────────────────────────
function logout() {
  if (ws) { manualDisc = true; ws.close(); }
  clearInterval(onlineTimer);
  me = null; localStorage.removeItem('me');
  document.getElementById('authSec').classList.remove('hidden');
  document.getElementById('appSec').classList.add('hidden');
  document.getElementById('hdrR').style.display = 'none';
  document.getElementById('auditCard').classList.add('hidden');
  online = []; renderChips();
  addLog('Signed out', 'info');
}

// ── show app ──────────────────────────────────────────────────
function showApp() {
  document.getElementById('authSec').classList.add('hidden');
  document.getElementById('appSec').classList.remove('hidden');
  document.getElementById('hdrR').style.display = 'flex';
  document.getElementById('hdrUser').textContent = '@' + (me.username || '');
  loadNotifs();
  checkPerm();
  auditCount = parseInt(localStorage.getItem('ac') || '0');
  document.getElementById('sAud').textContent = auditCount;
  if (me.username === 'admin') showAdminPanels();
  addLog('Welcome, ' + (me.full_name || me.username), 'success');
  setTimeout(function () { if (!ws || ws.readyState !== WebSocket.OPEN) connectWS(); }, 400);
}

function showAdminPanels() {
  ['importCard', 'bcCard', 'userCard', 'fbMgmt', 'statsCard'].forEach(function (id) {
    document.getElementById(id).classList.remove('hidden');
  });
  document.getElementById('scFb').style.display = 'block';
  document.getElementById('fbForm').classList.add('hidden');
  loadUsers(); loadFeedback(); loadStats();
}

// ── websocket ─────────────────────────────────────────────────
function connectWS() {
  if (!me) return;
  addLog('Establishing connection…', 'info');
  ws = new WebSocket(WSS + '/ws?user=' + me.username);
  ws.onopen = function () {
    setConn(true);
    addLog('Connection established', 'success');
    retries = 0; manualDisc = false;
    reqPerm();
    fetchOnline();
    startNotificationSync();
    clearInterval(onlineTimer);
    onlineTimer = setInterval(fetchOnline, 5000);
  };
  ws.onmessage = function (e) {
    try {
      var d = JSON.parse(e.data);
      addNotif({
        id: d.id, message: d.message, sender: d.sender, time: new Date(), read: false,
        canReply: d.canReply !== false, isReply: d.isReply || false
      });
      if (d.id && me) {
        markNotificationsDelivered([d.id]);
      }
      addLog(d.sender + ': ' + d.message, 'success');
      if (!d.queued) {
        playSound(d.isReply ? 'reply' : 'audit');
        var title = d.isReply ? ('Reply from @' + d.sender) : ('Audit from @' + d.sender);
        toast(title, d.message, d.isReply ? 'success' : 'audit', 8000);
        deskNotif(d.sender, d.message);
      }
    } catch (err) {
      playSound('audit');
      toast('Notification', e.data, 'audit', 8000);
      addNotif({ message: e.data, sender: 'System', time: new Date(), read: false, canReply: false });
    }
  };
  ws.onclose = function () {
    setConn(false);
    clearInterval(onlineTimer);
    clearInterval(syncTimer);
    online = []; renderChips();
    if (!manualDisc) {
      var delay = Math.min(1000 * Math.pow(2, retries), 30000);
      addLog('Reconnecting in ' + (delay / 1000) + 's…', 'info');
      setTimeout(connectWS, delay);
      retries++;
    }
  };
  ws.onerror = function () { addLog('WebSocket error', 'error'); };
}

function disconnectWS() { manualDisc = true; if (ws) ws.close(); clearInterval(onlineTimer); }

function setConn(on) {
  document.getElementById('cbadge').className = 'badge ' + (on ? 'b-on' : 'b-off');
  document.getElementById('ctext').textContent = on ? 'Connected' : 'Disconnected';
  var btn = document.getElementById('cbtn');
  if (on) {
    btn.innerHTML = '<svg class="ic" width="16" height="16"><use href="#ic-wifi-off"/></svg> Disconnect';
    btn.className = 'bd bfull';
    btn.onclick = disconnectWS;
  } else {
    btn.innerHTML = '<svg class="ic" width="16" height="16"><use href="#ic-wifi"/></svg> Connect';
    btn.className = 'bp bfull';
    btn.onclick = connectWS;
  }
  document.getElementById('auditCard').classList.toggle('hidden', !on);
}

// ── online users ──────────────────────────────────────────────
async function fetchOnline() {
  try {
    var hdrs = { 'Cache-Control': 'no-cache' };
    if (me && me.username === 'admin') hdrs['X-Admin-User'] = 'admin';
    var r = await fetch(API + '/online?_=' + Date.now(), { cache: 'no-cache', headers: hdrs });
    if (!r.ok) return;
    var d = await r.json();
    online = d.online || [];
    document.getElementById('sOn').textContent = online.length;
    if (d.total !== undefined) document.getElementById('sTot').textContent = d.total;
    renderChips();
    if (me && me.username === 'admin') {
      document.getElementById('uOn').textContent = online.length;
      refreshUserOnlineStatus();
    }
  } catch (err) { }
}

function refreshUserOnlineStatus() {
  if (!userList || !userList.length) return;
  userList.forEach(function (u) { u.online = online.indexOf(u.username) > -1; });
  var rows = document.querySelectorAll('#uBody tr');
  rows.forEach(function (row) {
    var usernameCell = row.querySelector('td:first-child [style*="font-mn"]');
    if (!usernameCell) return;
    var uname = usernameCell.textContent.replace('@', '').trim();
    var isOn = online.indexOf(uname) > -1;
    var statusCell = row.querySelector('td:nth-child(3)');
    if (statusCell) {
      statusCell.innerHTML = '<span class="badge ' + (isOn ? 'b-on' : 'b-off') + '"><span class="bdot"></span>' + (isOn ? 'Online' : 'Offline') + '</span>';
    }
  });
}

function renderChips() {
  var el = document.getElementById('chips');
  if (!online.length) {
    el.innerHTML = '<span style="color:var(--t2);font-size:.875rem">No users online</span>';
    return;
  }
  el.innerHTML = online.map(function (u) {
    return '<div class="chip"><span style="width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block;box-shadow:0 0 6px var(--green)"></span>' + esc(u) + '</div>';
  }).join('');
}

// ── notifications ─────────────────────────────────────────────
function addNotif(n) { notifs.unshift(n); unread++; renderBadge(); renderList(); saveNotifs(); }
function renderBadge() {
  var b = document.getElementById('nbadge');
  if (unread > 0) { b.textContent = unread > 99 ? '99+' : unread; b.classList.remove('hidden'); }
  else b.classList.add('hidden');
}
function renderList() {
  var el = document.getElementById('nlist');
  if (!notifs.length) {
    el.innerHTML = '<div style="padding:40px;text-align:center;color:var(--t2)">No notifications yet</div>';
    return;
  }
  el.innerHTML = notifs.map(function (n) {
    var rb = n.canReply ? ('<button class="rbtn" onclick="event.stopPropagation();openReply(' + (n.id || 0) + ',\'' + esc(n.sender) + '\',\'' + esc(n.message) + '\')"><svg class="ic" width="13" height="13"><use href="#ic-reply"/></svg> Reply</button>') : '';
    var tag = n.isReply ? '<div style="color:var(--cyan);font-size:.72rem;margin-top:4px;display:flex;align-items:center;gap:4px"><svg class="ic" width="11" height="11"><use href="#ic-reply"/></svg> Reply</div>' : '';
    return '<div class="ni ' + (n.read ? '' : 'unread') + '" onclick="markRead(' + (n.id || 0) + ')">' +
      '<div class="ntime">' + timeAgo(n.time) + '</div>' +
      '<div class="nmsg">' + esc(n.message) + '</div>' + rb + tag + '</div>';
  }).join('');
}
function togglePanel() {
  var p = document.getElementById('npanel');
  p.classList.toggle('hidden');
  if (!p.classList.contains('hidden')) {
    notifs.forEach(function (n) { n.read = true; });
    unread = 0; renderBadge(); renderList(); saveNotifs();
  }
}
function markRead(id) {
  var n = notifs.find(function (x) { return x.id === id; });
  if (n && !n.read) { n.read = true; unread = Math.max(0, unread - 1); renderBadge(); saveNotifs(); }
}
function clearNotifs() { notifs = []; unread = 0; renderBadge(); renderList(); saveNotifs(); }
function saveNotifs() {
  var d = Date.now() - 86400000;
  localStorage.setItem('notifs', JSON.stringify(
    notifs.filter(function (n) { return new Date(n.time) > d; }).slice(0, 50)
  ));
}
function loadNotifs() {
  try {
    var s = localStorage.getItem('notifs');
    if (s) {
      notifs = JSON.parse(s).map(function (n) { return Object.assign({}, n, { time: new Date(n.time) }); });
      unread = notifs.filter(function (n) { return !n.read; }).length;
      renderBadge(); renderList();
    }
  } catch (err) { notifs = []; }
}

// ── reply modal ───────────────────────────────────────────────
function openReply(id, sender, origMsg) {
  var m = document.createElement('div');
  m.className = 'mover'; m.id = 'rModal';
  m.innerHTML = '<div class="modal">' +
    '<div class="mtitle"><svg class="ic" width="18" height="18"><use href="#ic-reply"/></svg> Reply to @' + esc(sender) + '</div>' +
    '<div class="origmsg"><strong style="color:var(--t0)">Original message:</strong><br><span style="color:var(--t1)">' + esc(origMsg) + '</span></div>' +
    '<div class="fg"><label>Your Reply</label><textarea id="rTxt" placeholder="Type your reply…"></textarea></div>' +
    '<div style="display:flex;gap:10px;justify-content:flex-end">' +
    '<button class="bg bsm" onclick="closeReply()"><svg class="ic" width="13" height="13"><use href="#ic-x"/></svg> Cancel</button>' +
    '<button class="bs bsm" onclick="sendReply(' + id + ',\'' + esc(sender) + '\')"><svg class="ic" width="13" height="13"><use href="#ic-send"/></svg> Send Reply</button>' +
    '</div></div>';
  document.body.appendChild(m);
  m.addEventListener('click', function (e) { if (e.target === m) closeReply(); });
  document.getElementById('rTxt').focus();
}
function closeReply() { var m = document.getElementById('rModal'); if (m) m.remove(); }
async function sendReply(id, sender) {
  var txt = document.getElementById('rTxt').value.trim();
  if (!txt) return toast('Error', 'Reply cannot be empty', 'error');
  try {
    var r = await fetch(API + '/reply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notificationId: id, replyMessage: txt, replierUsername: me.username })
    });
    if (!r.ok) throw new Error('Reply failed');
    playSound('success');
    toast('Sent', 'Reply delivered to @' + sender, 'success');
    addLog('Reply sent to @' + sender, 'success');
    closeReply();
    var n = notifs.find(function (x) { return x.id === id; });
    if (n) { n.canReply = false; renderList(); saveNotifs(); }
  } catch (err) { toast('Error', err.message, 'error'); }
}

// ── search users ──────────────────────────────────────────────
function srchUsers(q) {
  clearTimeout(srchTimer);
  var drop = document.getElementById('sdrop');
  if (!q || q.length < 2) { drop.classList.add('hidden'); return; }

  srchTimer = setTimeout(async function () {
    try {
      var r = await fetch(API + '/search?q=' + encodeURIComponent(q));
      if (!r.ok) return;
      var users = await r.json();

      if (!users.length) {
        drop.innerHTML = '<div style="padding:14px;text-align:center;color:var(--t2);font-size:.875rem">No users found</div>';
        drop.classList.remove('hidden');
        return;
      }

      drop.innerHTML = users.map(function (u) {
        if (u.status === 'registered') {
          return '<div class="sitem" data-username="' + esc(u.username) + '" data-status="registered">' +
            '<div style="font-weight:600;font-size:.9rem;color:var(--t0)">' + esc(u.fullName) + '</div>' +
            '<div style="font-size:.78rem;color:var(--t2);font-family:var(--font-mn)">@' + esc(u.username) + '</div>' +
            '</div>';
        } else {
          var dataFloor = u.floor ? ' data-floor="' + esc(u.floor) + '"' : '';
          var dataPhone = u.whatsapp ? ' data-phone="' + esc(u.whatsapp) + '"' : '';
          return '<div class="sitem" data-username="' + esc(u.username) + '" data-status="unregistered"' + dataFloor + dataPhone + ' style="border-left:3px solid var(--amber)">' +
            '<div style="display:flex;align-items:center;gap:6px">' +
            '<svg class="ic" width="14" height="14" style="color:var(--amber)"><use href="#ic-alert"/></svg>' +
            '<span style="font-weight:600;font-size:.9rem;color:var(--t0)">' + esc(u.fullName) + '</span>' +
            '</div>' +
            '<div style="font-size:.78rem;color:var(--t2);font-family:var(--font-mn)">@' + esc(u.username) + ' · Not registered</div>' +
            (u.floor ? '<div style="font-size:.72rem;color:var(--amber);margin-top:2px">🏢 ' + esc(u.floor) + '</div>' : '') +
            '</div>';
        }
      }).join('');

      drop.classList.remove('hidden');

      drop.querySelectorAll('.sitem').forEach(function (item) {
        item.addEventListener('click', function (e) {
          e.stopPropagation();
          var username = item.getAttribute('data-username');
          var status = item.getAttribute('data-status');

          if (status === 'registered') {
            pickUser(username);
          } else {
            var userInfo = users.find(function (u) { return u.username === username; });
            if (userInfo) showOfflineUserModal(username, userInfo);
          }
        });
      });

    } catch (err) { console.error('Search error:', err); }
  }, 300);
}

function pickUser(u) {
  document.getElementById('tUser').value = u;
  document.getElementById('sdrop').classList.add('hidden');
  document.getElementById('aDetail').focus();
}

// ── OFFLINE USER MODAL ────────────────────────────────────────
// FIX: Completely rewritten to handle missing/null/undefined
// floor and whatsapp data gracefully. No more "undefined" text.
// All data paths are sanitised before rendering HTML.
// ══════════════════════════════════════════════════════════════
function showOfflineUserModal(username, userInfo, onConfirm) {
  if (!userInfo) {
    toast('Error', 'User information not available', 'error');
    return;
  }

  // ── Sanitise all fields — never allow undefined/null into DOM ──
  var name = userInfo.fullName || userInfo.full_name || username || 'Unknown';
  var floor = (userInfo.floor && userInfo.floor.trim()) ? userInfo.floor.trim() : '';
  var rawPhone = userInfo.whatsapp || userInfo.phone || '';
  rawPhone = (typeof rawPhone === 'string') ? rawPhone.trim() : '';

  // Strip to digits only for wa.me URL
  var cleanPhone = rawPhone.replace(/\D/g, '');

  // Build WhatsApp message + URL only when a phone number exists
  var waUrl = '';
  if (cleanPhone) {
    var senderName = (me && me.full_name) ? me.full_name : (me ? me.username : 'Nexus Audit');
    var locationInfo = floor ? ' (' + floor + ')' : '';
    var waText =
      'Hi ' + name + ',\n\n' +
      'This is ' + senderName + ' from Nexus Audit.\n\n' +
      'You have been requested for an audit. The request has been queued and will be delivered when you come online.\n\n' +
      'Please log in to the Nexus Audit platform to view your notification:\n' +
      'https://audit-notification.onrender.com\n\n' +
      'If you need assistance, please confirm receipt of this message.\n\nThank you.';
    waUrl = 'https://wa.me/' + '+234' + cleanPhone + '?text=' + encodeURIComponent(waText);
  }

  // ── Floor row ─────────────────────────────────────────────
  var floorRow = floor
    ? '<div style="display:flex;align-items:center;gap:8px">' +
    '<svg class="ic" width="14" height="14" style="color:var(--t2)"><use href="#ic-building"/></svg>' +
    '<span style="font-size:.875rem;color:var(--t1)">' + esc(floor) + '</span>' +
    '</div>'
    : '<div style="display:flex;align-items:center;gap:8px">' +
    '<svg class="ic" width="14" height="14" style="color:var(--t3)"><use href="#ic-building"/></svg>' +
    '<span style="font-size:.8rem;color:var(--t2);font-style:italic">Floor not specified</span>' +
    '</div>';

  // ── Phone row ─────────────────────────────────────────────
  var phoneRow = rawPhone
    ? '<div style="display:flex;align-items:center;gap:8px">' +
    '<svg class="ic" width="14" height="14" style="color:var(--green)"><use href="#ic-phone"/></svg>' +
    '<span style="font-size:.875rem;color:var(--t1);font-family:var(--font-mn)">' + esc(rawPhone) + '</span>' +
    '</div>'
    : '<div style="display:flex;align-items:center;gap:8px">' +
    '<svg class="ic" width="14" height="14" style="color:var(--t3)"><use href="#ic-alert"/></svg>' +
    '<span style="font-size:.8rem;color:var(--t2);font-style:italic">No phone number on record</span>' +
    '</div>';

  // ── WhatsApp CTA or no-phone notice ───────────────────────
  var whatsappSection = waUrl
    ? '<a href="' + waUrl + '" target="_blank" rel="noopener noreferrer" class="wa-btn" style="margin-bottom:16px;display:inline-flex">' +
    '<svg class="ic" width="15" height="15"><use href="#ic-whatsapp"/></svg> Send WhatsApp Invite' +
    '</a>'
    : '<div style="background:rgba(239,69,101,.1);border:1px solid rgba(239,69,101,.3);padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:.85rem;color:var(--red)">' +
    '<svg class="ic" width="14" height="14" style="vertical-align:middle;margin-right:6px"><use href="#ic-alert"/></svg>' +
    'WhatsApp not available — no phone number on record' +
    '</div>';

  // ── Assemble modal ────────────────────────────────────────
  var modalHTML =
    '<div style="text-align:center;padding:4px 0">' +

    // Info box
    '<div style="background:rgba(245,158,58,.08);border:1px solid rgba(245,158,58,.3);border-radius:10px;padding:14px 16px;margin-bottom:20px;text-align:left">' +
    '<div style="font-size:.875rem;color:var(--t1);line-height:1.6;margin-bottom:12px">' +
    '<svg class="ic" width="14" height="14" style="color:var(--amber);vertical-align:middle;margin-right:6px"><use href="#ic-info"/></svg>' +
    'This user is currently <strong style="color:var(--amber)">offline</strong>. The audit will be queued and delivered when they connect.' +
    '</div>' +
    '<div style="font-size:.8rem;color:var(--t2);line-height:1.5">Alternatively, contact them via WhatsApp or in-person using the details below.</div>' +
    '</div>' +

    // User details card
    '<div style="background:var(--c2);border:1px solid var(--br0);border-radius:10px;padding:14px 16px;margin-bottom:20px">' +
    '<div style="font-weight:700;font-size:1rem;color:var(--t0);margin-bottom:10px;font-family:var(--font-hd)">' + esc(name) + '</div>' +
    '<div style="display:flex;flex-direction:column;gap:8px">' +
    floorRow +
    phoneRow +
    '</div>' +
    '</div>' +

    // WhatsApp section
    whatsappSection +

    // Action buttons
    '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px">' +
    '<button class="bg bsm" onclick="closeModal()" style="flex:1">' +
    '<svg class="ic" width="13" height="13"><use href="#ic-x"/></svg> Cancel' +
    '</button>' +
    '<button class="bs bsm" onclick="confirmOfflineAudit()" style="flex:1">' +
    '<svg class="ic" width="13" height="13"><use href="#ic-send"/></svg> Send Anyway' +
    '</button>' +
    '</div>' +
    '</div>';

  openModal(
    '<svg class="ic" width="18" height="18" style="color:var(--amber)"><use href="#ic-wifi-off"/></svg> User Offline — Send Audit Request?',
    modalHTML
  );

  // Store callback for "Send Anyway"
  window.confirmOfflineAudit = function () {
    closeModal();
    if (onConfirm) onConfirm();
  };

  // Escape key handler
  var escHandler = function (e) {
    if (e.key === 'Escape') { closeModal(); document.removeEventListener('keydown', escHandler); }
  };
  document.addEventListener('keydown', escHandler);

  // Auto-remove escape handler when modal is destroyed
  var observer = new MutationObserver(function () {
    if (!document.getElementById('genModal')) {
      document.removeEventListener('keydown', escHandler);
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true });
}

// Detect user reconnection while modal is open
function handleUserReconnection(username) {
  var modal = document.getElementById('genModal');
  if (modal && modal.querySelector('.mtitle') && modal.querySelector('.mtitle').textContent.includes('User Offline')) {
    closeModal();
    toast('User Online', username + ' just connected! Sending audit now...', 'success', 3000);
    if (window.confirmOfflineAudit) window.confirmOfflineAudit();
  }
}

// ── send audit ────────────────────────────────────────────────
async function sendAudit() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return toast('Error', 'Please connect first', 'error');
  var target = document.getElementById('tUser').value.trim();
  var detail = document.getElementById('aDetail').value.trim();
  if (!target || !detail) return toast('Error', 'All fields are required', 'error');

  // Skip offline check during bulk operations
  if (isBulkOperation) { proceedWithAudit(target, detail); return; }

  var isOnline = online.indexOf(target) > -1;

  if (!isOnline) {
    try {
      var searchR = await fetch(API + '/search?q=' + encodeURIComponent(target));
      if (searchR.ok) {
        var users = await searchR.json();
        // FIX: exact match on username (search can return partial matches)
        var user = users.find(function (u) { return u.username === target; });
        if (user) {
          showOfflineUserModal(target, user, function () { proceedWithAudit(target, detail); });
          return;
        }
      }
    } catch (e) { console.error('User lookup error:', e); }

    // Fallback if search fails
    if (!confirm(target + ' is currently offline. Send audit anyway?')) return;
  }

  proceedWithAudit(target, detail);
}

async function proceedWithAudit(target, detail) {
  try {
    var r = await fetch(API + '/audit', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUser: target, requester: me.username, details: detail })
    });

    var d = await r.json();

    if (d.error === 'user_not_registered' && d.user_info) {
      closeModal();
      showOfflineUserModal(target, {
        fullName: d.user_info.name,
        floor: d.user_info.floor || '',
        whatsapp: d.user_info.phone || '',
      }, function () {
        toast('Info', 'User must register first to receive audits', 'info', 5000);
      });
      return;
    }

    if (!r.ok) throw new Error('Send failed');
    toast('Audit Sent', d.message, 'success', 3000);
    addLog('Audit dispatched to @' + target, 'success');
    document.getElementById('tUser').value = '';
    document.getElementById('aDetail').value = '';
    auditCount++; localStorage.setItem('ac', auditCount);
    document.getElementById('sAud').textContent = auditCount;
  } catch (err) { toast('Error', err.message, 'error'); }
}

// Show modal for unregistered user with WhatsApp option
function showUnregisteredUserModal(info) {
  var waBtn = info.whatsapp_url
    ? '<a href="' + info.whatsapp_url + '" target="_blank" rel="noopener noreferrer" class="wa-btn" style="margin-top:16px">' +
    '<svg class="ic" width="15" height="15"><use href="#ic-whatsapp"/></svg> Send WhatsApp Invite' +
    '</a>'
    : '<div style="color:var(--t2);font-size:.85rem;margin-top:12px;text-align:center">No phone number available</div>';

  openModal(
    '<svg class="ic" width="18" height="18" style="color:var(--amber)"><use href="#ic-alert"/></svg> User Not Registered',
    '<div style="text-align:center;padding:10px 0">' +
    '<p style="color:var(--t1);margin-bottom:20px">' +
    '<strong style="color:var(--t0)">' + esc(info.name) + '</strong> is not registered yet, but you can reach them:' +
    '</p>' +
    '<div class="unreg-card" style="margin-bottom:20px">' +
    '<div class="unreg-name">' + esc(info.name) + '</div>' +
    '<div class="unreg-meta">' +
    (info.floor ? '<span class="unreg-pill pill-floor"><svg class="ic" width="11" height="11"><use href="#ic-building"/></svg> ' + esc(info.floor) + '</span>' : '') +
    (info.phone ? '<span class="unreg-pill pill-phone"><svg class="ic" width="11" height="11"><use href="#ic-phone"/></svg> ' + esc(info.phone) + '</span>' : '') +
    '</div>' +
    '</div>' +
    waBtn +
    '<p style="font-size:.8rem;color:var(--t2);margin-top:16px">They need to register with their Gitea username to receive audits.</p>' +
    '<button class="bg bfull" onclick="closeModal()" style="margin-top:16px"><svg class="ic" width="14" height="14"><use href="#ic-x"/></svg> Close</button>' +
    '</div>'
  );
}

// ── broadcast ─────────────────────────────────────────────────
async function sendBroadcast() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return toast('Error', 'Please connect first', 'error');
  var target = document.getElementById('bcTarget').value;
  var msg = document.getElementById('bcMsg').value.trim();
  if (!msg) return toast('Error', 'Message is required', 'error');
  if (!confirm('Broadcast to ' + (target === 'online' ? 'all online users' : 'all registered users') + '?')) return;
  try {
    var r = await fetch(API + '/broadcast', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, sender: me.username, targetType: target })
    });
    if (!r.ok) throw new Error('Failed');
    var d = await r.json();
    toast('Broadcast Sent', d.message, 'success', 5000);
    addLog('Broadcast: ' + d.delivered + ' delivered, ' + d.queued + ' queued', 'success');
    document.getElementById('bcMsg').value = '';
  } catch (err) { toast('Error', err.message, 'error'); }
}

// ── feedback (user) ───────────────────────────────────────────
async function submitFb() {
  var type = document.getElementById('fbT').value;
  var subj = document.getElementById('fbS').value.trim();
  var msg = document.getElementById('fbM').value.trim();
  if (!subj || !msg) return toast('Error', 'Subject and message are required', 'error');
  try {
    var r = await fetch(API + '/feedback', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: me.username, subject: subj, message: msg, type: type })
    });
    if (!r.ok) throw new Error('Submission failed');
    toast('Submitted', 'Your feedback has been sent to admin', 'success', 4000);
    addLog('Feedback submitted', 'success');
    document.getElementById('fbS').value = '';
    document.getElementById('fbM').value = '';
  } catch (err) { toast('Error', err.message, 'error'); }
}

// ── import users ──────────────────────────────────────────────
async function importUsers() {
  var file = document.getElementById('xlFile').files[0];
  var st = document.getElementById('impSt');
  var resultDiv = document.getElementById('importResults');
  if (!file) return;

  isBulkOperation = true;

  var form = new FormData(); form.append('file', file);
  st.innerHTML = '<span style="color:var(--cyan);display:flex;align-items:center;gap:6px"><svg class="ic" width="14" height="14"><use href="#ic-refresh"/></svg> Processing Excel file…</span>';
  resultDiv.classList.add('hidden');
  try {
    var r = await fetch(API + '/import?admin=' + me.username, { method: 'POST', body: form });
    if (!r.ok) throw new Error('Import failed');
    var d = await r.json();
    st.innerHTML = '<span style="color:var(--green);display:flex;align-items:center;gap:6px"><svg class="ic" width="14" height="14"><use href="#ic-check"/></svg> Imported ' + d.imported + ' users · Skipped ' + d.skipped + '</span>';
    toast('Import Complete', d.imported + ' users imported successfully', 'success');
    if (d.unregistered && d.unregistered.length > 0) renderUnregistered(d.unregistered, resultDiv);
    loadUsers();
  } catch (err) {
    st.innerHTML = '<span style="color:var(--red);display:flex;align-items:center;gap:6px"><svg class="ic" width="14" height="14"><use href="#ic-x"/></svg> ' + err.message + '</span>';
    toast('Import Failed', err.message, 'error');
  } finally {
    isBulkOperation = false;
  }
  document.getElementById('xlFile').value = '';
}

function renderUnregistered(users, container) {
  container.classList.remove('hidden');
  container.innerHTML =
    '<div style="border-top:1px solid var(--br0);margin-top:16px;padding-top:16px">' +
    '<div style="font-family:var(--font-hd);font-weight:600;color:var(--amber);margin-bottom:4px;display:flex;align-items:center;gap:8px">' +
    '<svg class="ic" width="16" height="16"><use href="#ic-alert"/></svg> ' + users.length + ' Unregistered / No Gitea Account' +
    '</div>' +
    '<div style="font-size:.78rem;color:var(--t2);margin-bottom:14px">These users can be reached via WhatsApp. Their floor location is shown for in-person contact.</div>' +
    users.map(function (u) {
      var senderName = me && me.full_name ? me.full_name : (me ? me.username : 'Nexus Audit');
      var location = u.floor ? (' (' + u.floor + ')') : '';
      var waText = 'Hi ' + u.name + location + ',\n\n' +
        'This is ' + senderName + ' reaching out from Nexus Audit.\n\n' +
        'You have been requested for an audit. Please register on the Nexus Audit platform to receive real-time notifications:\n' +
        'https://audit-notification.onrender.com\n\n' +
        'Your registration details:\n- Gitea username is required to register\n\n' +
        'Please confirm receipt of this message.\n\nThank you.';
      // FIX: guard phone — only strip digits if phone is a non-empty string
      var rawPhone = (u.phone && typeof u.phone === 'string') ? u.phone.trim() : '';
      var phone = rawPhone.replace(/\D/g, '');
      var waUrl = phone ? ('https://wa.me/+234' + phone + '?text=' + encodeURIComponent(waText)) : '';
      return '<div class="unreg-card">' +
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px">' +
        '<div>' +
        '<div class="unreg-name">' + esc(u.name) + '</div>' +
        '<div class="unreg-meta">' +
        (u.floor
          ? '<span class="unreg-pill pill-floor"><svg class="ic" width="11" height="11"><use href="#ic-building"/></svg> ' + esc(u.floor) + '</span>'
          : '<span class="unreg-pill" style="background:rgba(90,112,150,.1);border:1px solid var(--br0);color:var(--t2)"><svg class="ic" width="11" height="11"><use href="#ic-map-pin"/></svg> Floor unknown</span>') +
        (rawPhone ? '<span class="unreg-pill pill-phone"><svg class="ic" width="11" height="11"><use href="#ic-phone"/></svg> ' + esc(rawPhone) + '</span>' : '') +
        '</div>' +
        '</div>' +
        (waUrl
          ? '<a href="' + waUrl + '" target="_blank" rel="noopener noreferrer" class="wa-btn">' +
          '<svg class="ic" width="15" height="15"><use href="#ic-whatsapp"/></svg> Send WhatsApp Invite' +
          '</a>'
          : '<span style="color:var(--t2);font-size:.8rem;display:inline-flex;align-items:center;gap:5px;padding:8px">' +
          '<svg class="ic" width="13" height="13"><use href="#ic-alert"/></svg> No phone on record' +
          '</span>') +
        '</div>' +
        '</div>';
    }).join('') +
    '</div>';
}

// ── admin: load users ─────────────────────────────────────────
async function loadUsers() {
  try {
    var r = await fetch(API + '/admin/users', { headers: { 'X-Admin-User': 'admin' } });
    if (!r.ok) throw new Error('Failed');
    var d = await r.json();
    userList = d.users || [];
    renderUsers(userList);
    var today = new Date().toDateString();
    var newT = userList.filter(function (u) { return new Date(u.created_at).toDateString() === today; }).length;
    document.getElementById('uTot').textContent = userList.length;
    document.getElementById('uOn').textContent = online.length;
    document.getElementById('uNew').textContent = newT;
    document.getElementById('sTot').textContent = userList.length;
  } catch (err) { toast('Error', err.message, 'error'); }
}

function renderUsers(list) {
  var b = document.getElementById('uBody');
  if (!list || !list.length) {
    b.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--t2)">No users found</td></tr>';
    return;
  }
  b.innerHTML = list.map(function (u) {
    var on = u.online === true || (u.online === undefined && online.indexOf(u.username) > -1);
    var ini = u.full_name ? (u.full_name.split(' ').map(function (x) { return x[0] || ''; }).join('').toUpperCase().slice(0, 2)) : '?';
    var joined = new Date(u.created_at).toLocaleDateString();
    var last = u.last_login ? new Date(u.last_login).toLocaleString() : 'Never';
    return '<tr>' +
      '<td><div style="display:flex;align-items:center;gap:10px">' +
      '<div class="uav">' + esc(ini) + '</div>' +
      '<div>' +
      '<div style="font-weight:600;color:var(--t0);font-family:var(--font-hd);font-size:.9rem">' + esc(u.full_name) + '</div>' +
      '<div style="font-size:.75rem;color:var(--t2);font-family:var(--font-mn)">@' + esc(u.username) + '</div>' +
      '</div></div></td>' +
      '<td style="font-size:.8rem">' + esc(u.email) + '</td>' +
      '<td><span class="badge ' + (on ? 'b-on' : 'b-off') + '"><span class="bdot"></span>' + (on ? 'Online' : 'Offline') + '</span></td>' +
      '<td style="font-size:.8rem">' + joined + '</td>' +
      '<td style="font-size:.8rem">' + last + '</td>' +
      '<td style="text-align:center">' +
      '<button class="bg bsm" onclick="qkAudit(\'' + esc(u.username) + '\')" title="Send Audit Request">' +
      '<svg class="ic" width="13" height="13"><use href="#ic-send"/></svg>' +
      '</button>' +
      '</td>' +
      '</tr>';
  }).join('');
}

function filterUsers(q) {
  var query = (q || document.getElementById('uSrch').value).toLowerCase();
  var sf = document.getElementById('uFilter').value;
  var res = userList.filter(function (u) {
    var mq = !query || u.username.toLowerCase().indexOf(query) > -1 ||
      u.full_name.toLowerCase().indexOf(query) > -1 || u.email.toLowerCase().indexOf(query) > -1;
    var isOn = u.online === true || (u.online === undefined && online.indexOf(u.username) > -1);
    var ms = sf === 'all' || (sf === 'online' && isOn) || (sf === 'offline' && !isOn);
    return mq && ms;
  });
  renderUsers(res);
}

function exportCSV() {
  var rows = [['Username', 'Full Name', 'Email', 'Status', 'Joined', 'Last Login']];
  userList.forEach(function (u) {
    var isOn = u.online === true || (u.online === undefined && online.indexOf(u.username) > -1);
    rows.push([u.username, u.full_name, u.email,
    isOn ? 'Online' : 'Offline',
    new Date(u.created_at).toLocaleDateString(),
    u.last_login ? new Date(u.last_login).toLocaleString() : 'Never']);
  });
  var csv = rows.map(function (r) { return r.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(','); }).join('\n');
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
  a.download = 'nexus_users_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click();
  toast('Exported', 'User list downloaded', 'success', 3000);
}

function qkAudit(u) {
  document.getElementById('tUser').value = u;
  document.getElementById('auditCard').scrollIntoView({ behavior: 'smooth' });
  document.getElementById('aDetail').focus();
}

// ── admin: feedback ───────────────────────────────────────────
async function loadFeedback() {
  var type = document.getElementById('fbFilt').value;
  var url = API + '/admin/feedback' + (type && type !== 'all' ? '?type=' + type : '');
  try {
    var r = await fetch(url, { headers: { 'X-Admin-User': 'admin' } });
    if (!r.ok) throw new Error('Failed');
    var d = await r.json();
    renderFeedback(d.feedback || []);
  } catch (err) { toast('Error', err.message, 'error'); }
}

function renderFeedback(items) {
  var el = document.getElementById('fbList');
  if (!items || !items.length) {
    el.innerHTML = '<div style="padding:40px;text-align:center;color:var(--t2)">No feedback submitted yet</div>';
    return;
  }
  var typeIcons = { bug: '#ic-alert', feature: '#ic-trending', general: '#ic-message' };
  var typeColors = { bug: 'var(--red)', feature: 'var(--cyan)', general: 'var(--t1)' };
  el.innerHTML = items.map(function (f) {
    var ic = typeIcons[f.type] || '#ic-message';
    var col = typeColors[f.type] || 'var(--t1)';
    var resolved = f.status === 'resolved';
    return '<div class="unreg-card">' +
      '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">' +
      '<div style="display:flex;align-items:center;gap:8px">' +
      '<svg class="ic" width="14" height="14" style="color:' + col + '"><use href="' + ic + '"/></svg>' +
      '<span style="font-weight:600;color:var(--t0);font-family:var(--font-hd)">@' + esc(f.username) + '</span>' +
      '<span style="padding:2px 8px;background:var(--c3);border:1px solid var(--br1);border-radius:4px;font-size:.72rem;color:var(--t1);font-family:var(--font-hd)">' + f.type + '</span>' +
      '<span style="padding:2px 8px;background:' + (resolved ? 'rgba(34,201,122,.12)' : 'rgba(245,158,58,.12)') + ';border-radius:4px;font-size:.72rem;color:' + (resolved ? 'var(--green)' : 'var(--amber)') + ';font-family:var(--font-hd)">' + f.status + '</span>' +
      '</div>' +
      '<span style="font-size:.75rem;color:var(--t2);font-family:var(--font-mn)">' + timeAgo(new Date(f.timestamp)) + '</span>' +
      '</div>' +
      '<div style="font-weight:600;color:var(--t0);font-family:var(--font-hd);margin-bottom:4px">' + esc(f.subject) + '</div>' +
      '<div style="font-size:.875rem;color:var(--t1);margin-bottom:12px;line-height:1.6">' + esc(f.message) + '</div>' +
      '<div style="display:flex;gap:8px">' +
      '<button class="bg bsm" onclick="replyFb(' + f.id + ',\'' + esc(f.username) + '\')"><svg class="ic" width="13" height="13"><use href="#ic-reply"/></svg> Reply</button>' +
      (!resolved ? '<button class="bs bsm" onclick="resolveFb(' + f.id + ')"><svg class="ic" width="13" height="13"><use href="#ic-check"/></svg> Resolve</button>' : '') +
      '</div>' +
      '</div>';
  }).join('');
}

async function resolveFb(id) {
  try {
    await fetch(API + '/admin/feedback/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-User': 'admin' },
      body: JSON.stringify({ id: id, status: 'resolved' })
    });
    toast('Resolved', 'Feedback marked as resolved', 'success', 3000);
    loadFeedback();
  } catch (err) { toast('Error', err.message, 'error'); }
}

function replyFb(id, username) {
  document.getElementById('tUser').value = username;
  document.getElementById('auditCard').scrollIntoView({ behavior: 'smooth' });
  document.getElementById('aDetail').focus();
  toast('Quick Send', 'Compose an audit reply for @' + username, 'info', 3000);
}

// ── admin: stats ──────────────────────────────────────────────
async function loadStats() {
  try {
    var r = await fetch(API + '/admin/stats', { headers: { 'X-Admin-User': 'admin' } });
    if (!r.ok) throw new Error('Failed');
    var d = await r.json();
    document.getElementById('stU').textContent = d.total_users || 0;
    document.getElementById('stO').textContent = d.online_users || 0;
    document.getElementById('stA').textContent = d.total_audits || 0;
    document.getElementById('stF').textContent = d.pending_feedback || 0;
    document.getElementById('sFb').textContent = d.pending_feedback || 0;
  } catch (err) { toast('Error', err.message, 'error'); }
}

// ── notifications permission ──────────────────────────────────
function checkPerm() {
  var b = document.getElementById('permBanner');
  if (!('Notification' in window)) { b.style.display = 'none'; return; }
  b.style.display = Notification.permission === 'granted' ? 'none' : 'flex';
}

function reqPerm() {
  if (!('Notification' in window)) {
    toast('Not Supported', 'Your browser does not support desktop notifications', 'info', 4000);
    return;
  }
  if (Notification.permission === 'granted') {
    document.getElementById('permBanner').style.display = 'none';
    return;
  }
  var result = Notification.requestPermission(function (p) {
    if (p === 'granted') toast('Notifications Enabled', 'Desktop alerts are now active', 'success', 3000);
    document.getElementById('permBanner').style.display = 'none';
  });
  if (result && typeof result.then === 'function') {
    result.then(function (p) {
      if (p === 'granted') {
        toast('Notifications Enabled', 'You will receive alerts for new audits', 'success', 3000);
      } else if (p === 'denied') {
        toast('Notifications Blocked', 'Go to browser settings to allow notifications', 'info', 6000);
      }
      document.getElementById('permBanner').style.display = 'none';
    }).catch(function () {
      document.getElementById('permBanner').style.display = 'none';
    });
  }
}

function deskNotif(sender, message) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  try {
    var opts = { body: message, tag: 'nexus-audit-' + Date.now(), requireInteraction: false };
    var n = new Notification('Nexus Audit — @' + sender, opts);
    n.onclick = function () { try { window.focus(); } catch (e) { } n.close(); };
    setTimeout(function () { try { n.close(); } catch (e) { } }, 8000);
  } catch (err) {
    if (navigator.serviceWorker && navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({
        type: 'SHOW_NOTIFICATION', title: 'Nexus Audit — @' + sender, body: message
      });
    }
  }
}

// ── log ───────────────────────────────────────────────────────
function addLog(msg, type) {
  var box = document.getElementById('logBox');
  var row = document.createElement('div');
  row.className = 'lr l-' + (type || 'info');
  row.innerHTML = '<span class="lt">[' + new Date().toLocaleTimeString() + ']</span><span class="lm">' + esc(msg) + '</span>';
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
  if (box.children.length > 100) box.removeChild(box.firstChild);
}

// ── toast ─────────────────────────────────────────────────────
function toast(title, msg, type, dur) {
  if (dur === undefined) dur = 5000;
  var c = document.getElementById('tc');
  var t = document.createElement('div');
  t.className = 'toast ' + (type || 'info');
  var icMap = { success: '#ic-check', error: '#ic-x', warning: '#ic-alert', info: '#ic-info', audit: '#ic-bell' };
  var ic = icMap[type] || '#ic-info';
  t.innerHTML =
    '<div class="ticon"><svg class="ic" width="18" height="18"><use href="' + ic + '"/></svg></div>' +
    '<div class="tbody"><div class="ttitle">' + esc(title) + '</div><div class="tmsg">' + esc(msg) + '</div></div>' +
    '<button class="tcls" onclick="this.parentElement.remove()"><svg class="ic" width="14" height="14"><use href="#ic-x"/></svg></button>';
  c.appendChild(t);
  if (dur > 0) setTimeout(function () { t.style.opacity = '0'; setTimeout(function () { try { t.remove(); } catch (e) { } }, 300); }, dur);
}

// ── utils ─────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  var d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}
function timeAgo(d) {
  var diff = Math.floor((Date.now() - new Date(d)) / 1000);
  if (diff < 60) return 'Just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return new Date(d).toLocaleDateString();
}

// ── init ──────────────────────────────────────────────────────
window.onload = function () {
  var params = new URLSearchParams(window.location.search);
  var resetToken = params.get('token');
  if (resetToken && window.location.pathname.indexOf('reset-password') > -1) {
    showResetPage(resetToken);
    return;
  }
  try {
    var s = localStorage.getItem('me');
    if (s) { me = JSON.parse(s); showApp(); }
  } catch (err) { localStorage.removeItem('me'); }
};

window.onerror = function (msg, url, line, col, error) {
  console.error('❌ Runtime error:', msg, 'at', url + ':' + line + ':' + col);
  addLog('Error: ' + msg, 'error');
  return false;
};

window.onunhandledrejection = function (event) {
  console.error('❌ Unhandled promise rejection:', event.reason);
  addLog('Promise error: ' + event.reason, 'error');
};

function showResetPage(token) {
  document.getElementById('authSec').classList.remove('hidden');
  document.getElementById('authSec').innerHTML =
    '<div class="card" style="max-width:460px;margin:70px auto">' +
    '<div style="text-align:center;margin-bottom:22px">' +
    '<div style="width:56px;height:56px;background:linear-gradient(135deg,var(--cyan),var(--blue2));border-radius:14px;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;box-shadow:0 0 24px var(--cyan-gl)">' +
    '<svg class="ic" width="26" height="26" style="color:#fff"><use href="#ic-key"/></svg>' +
    '</div>' +
    '<div style="font-family:var(--font-hd);font-size:1.3rem;font-weight:700;letter-spacing:-.02em">Set New Password</div>' +
    '<div style="color:var(--t2);font-size:.875rem;margin-top:4px">Enter your new password below</div>' +
    '</div>' +
    '<div class="fg"><label>New Password</label>' +
    '<div class="inp-wrap pwd-wrap">' +
    '<input id="newPwd" type="password" placeholder="Min 6 characters" style="padding-left:40px">' +
    '<svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg>' +
    '<button type="button" class="pwd-toggle" onclick="togglePwd(\'newPwd\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button>' +
    '</div></div>' +
    '<div class="fg"><label>Confirm Password</label>' +
    '<div class="inp-wrap pwd-wrap">' +
    '<input id="confirmPwd" type="password" placeholder="Repeat password" style="padding-left:40px">' +
    '<svg class="ic inp-ic" width="16" height="16"><use href="#ic-lock"/></svg>' +
    '<button type="button" class="pwd-toggle" onclick="togglePwd(\'confirmPwd\',this)"><svg class="ic" width="16" height="16"><use href="#ic-eye"/></svg></button>' +
    '</div></div>' +
    '<button class="bp bfull" onclick="submitReset(\'' + token + '\')">' +
    '<svg class="ic" width="16" height="16"><use href="#ic-check"/></svg> Update Password' +
    '</button>' +
    '</div>';
}

async function submitReset(token) {
  var pwd = document.getElementById('newPwd').value;
  var conf = document.getElementById('confirmPwd').value;
  if (!pwd || pwd.length < 6) return toast('Error', 'Password must be at least 6 characters', 'error');
  if (pwd !== conf) return toast('Error', 'Passwords do not match', 'error');
  try {
    var r = await fetch(API + '/reset-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token, password: pwd })
    });
    var msg = await r.text();
    if (!r.ok) return toast('Error', msg, 'error');
    toast('Password Updated', 'You can now log in with your new password', 'success', 6000);
    setTimeout(function () { window.location.href = '/'; }, 2500);
  } catch (err) { toast('Error', 'Reset failed: ' + err.message, 'error'); }
}

document.addEventListener('click', function (e) {
  var panel = document.getElementById('npanel');
  var bell = document.querySelector('.nbell');
  if (panel && !panel.contains(e.target) && bell && !bell.contains(e.target))
    panel.classList.add('hidden');
  var drop = document.getElementById('sdrop');
  var wrap = document.querySelector('.swrap');
  if (drop && wrap && !wrap.contains(e.target))
    drop.classList.add('hidden');
});