Role: Senior Full-Stack UI/UX Engineer & CSS Architect\
Task: Perform a "Visual Engine Swap" on a production Enterprise Audit Notification System.
Core Objective:\
Redesign the provided index.html into a world-class, high-density "Command Center" interface. The aesthetic must be "Enterprise Dark" (Refined charcoal/navy, precision typography, surgical accents) inspired by platforms like Linear.app or Vercel.
Strict Technical Constraints:

1. Zero Logic Disruption: Do NOT modify, rename, or delete any <script> logic, variable names, or existing id="" attributes. The JavaScript must remain 100% functional.

2. Vanilla Stack: Use only standard CSS3 and HTML5. No Tailwind, Bootstrap, or external JS libraries.

3. Typography: Integrate 'Plus Jakarta Sans' for UI and 'JetBrains Mono' for logs/system data via Google Fonts.

4. Icons: Use purposeful Emojis as visual anchors for headers and buttons as per the design brief.

Design System Specifications:

* Palette: Background #0b0e14, Surface #151921, Borders #22272e, Primary Accent #00d1ff (Electric Blue).

* Layout: Implement a 12-column CSS Grid. Use a persistent glassmorphism Sidebar or Header.

* Interactive States: Add transition: all 0.2s ease to all buttons. Use translateY(-1px) and subtle box-shadows on hover.

* Notifications: Design the toast system and notification bell dropdown to feel native to a macOS/Windows professional app.

* Status Indicators: Implement a pulsing animation for the "Online" status dot.

* Mobile: Ensure the layout stacks into a clean single-column view at < 768px.

Deliverable:\
Provide the entire updated index.html file. Ensure the CSS is neatly organized with CSS Variables at the top. The HTML structure can be wrapped in new div containers for layout purposes, but all original functional elements must remain present.
 
here is my index.html
 

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<title>Audit Notification System</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg0:#0d1117;--bg1:#161b22;--bg2:#1c2128;--bg3:#21262d;
  --br:#30363d;--br2:#484f58;
  --t0:#e6edf3;--t1:#7d8590;--t2:#636e7b;
  --blue:#58a6ff;--blue2:#1f6feb;
  --green:#3fb950;--yellow:#d29922;--red:#f85149;--purple:#a371f7;
  --font:'Inter',-apple-system,sans-serif;--mono:'JetBrains Mono',monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg0);color:var(--t0);min-height:100vh}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
/* header */
.hdr{background:var(--bg1);border-bottom:1px solid var(--br);padding:14px 0;margin-bottom:24px}
.hdr-in{max-width:1400px;margin:0 auto;padding:0 20px;display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600}
.logo-ic{width:32px;height:32px;background:linear-gradient(135deg,var(--blue),var(--purple));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px}
.hdr-r{display:flex;align-items:center;gap:12px}
/* cards */
.card{background:var(--bg1);border:1px solid var(--br);border-radius:12px;padding:22px;margin-bottom:20px;transition:border-color .2s}
.card:hover{border-color:var(--br2)}
.ch{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--br)}
.ct{font-size:15px;font-weight:600}
/* tabs */
.tabs{display:flex;gap:4px;background:var(--bg2);padding:4px;border-radius:8px;margin-bottom:20px}
.tab{flex:1;padding:10px;background:transparent;border:none;border-radius:6px;color:var(--t1);font-weight:500;cursor:pointer;transition:all .2s;font-family:var(--font);font-size:14px}
.tab:hover{color:var(--t0)}
.tab.on{background:var(--blue2);color:#fff}
/* forms */
.fg{margin-bottom:15px}
label{display:block;margin-bottom:5px;color:var(--t1);font-size:12px;font-weight:500;text-transform:uppercase;letter-spacing:.5px}
input,textarea,select{width:100%;padding:11px 14px;background:var(--bg2);border:1px solid var(--br);border-radius:8px;color:var(--t0);font-size:14px;font-family:var(--font);transition:all .2s}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(88,166,255,.1)}
textarea{resize:vertical;min-height:100px}
/* buttons */
button{padding:10px 18px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;font-family:var(--font)}
.bp{background:var(--blue2);color:#fff}.bp:hover:not(:disabled){background:var(--blue);transform:translateY(-1px)}
.bs{background:var(--green);color:#fff}.bs:hover:not(:disabled){background:#2ea043;transform:translateY(-1px)}
.bd{background:var(--red);color:#fff}.bd:hover:not(:disabled){background:#da3633}
.bg{background:var(--bg2);color:var(--t1);border:1px solid var(--br)}.bg:hover{color:var(--t0);border-color:var(--br2)}
.bfull{width:100%}.bsm{padding:6px 12px;font-size:13px}
button:disabled{opacity:.5;cursor:not-allowed}
/* grids */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
/* stat cards */
.sc{background:var(--bg2);border:1px solid var(--br);padding:18px;border-radius:10px}
.sl{font-size:12px;color:var(--t1);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.sv{font-size:26px;font-weight:700;background:linear-gradient(135deg,var(--blue),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
/* badges */
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:500}
.b-on{background:rgba(63,185,80,.1);color:var(--green)}
.b-off{background:rgba(125,133,144,.1);color:var(--t2)}
.bdot{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
/* notification bell */
.nbell{position:relative;cursor:pointer;padding:8px 10px;background:var(--bg2);border:1px solid var(--br);border-radius:8px;font-size:16px;transition:all .2s}
.nbell:hover{background:var(--bg3)}
.nbadge{position:absolute;top:-4px;right:-4px;min-width:18px;height:18px;background:var(--red);border:2px solid var(--bg1);border-radius:10px;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;color:#fff}
/* notification panel */
.npanel{position:fixed;top:70px;right:20px;width:400px;max-height:calc(100vh - 100px);background:var(--bg1);border:1px solid var(--br);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.5);overflow:hidden;z-index:10000;display:flex;flex-direction:column}
.nphdr{padding:13px 16px;border-bottom:1px solid var(--br);display:flex;justify-content:space-between;align-items:center;font-weight:600}
.nlist{flex:1;overflow-y:auto}
.ni{padding:13px 16px;border-bottom:1px solid var(--br);cursor:pointer;transition:background .15s}
.ni:hover{background:var(--bg2)}
.ni.unread{background:rgba(88,166,255,.04);border-left:3px solid var(--blue)}
.ntime{font-size:11px;color:var(--t2);font-family:var(--mono);margin-bottom:4px}
.nmsg{font-size:13px;color:var(--t0);word-break:break-word;line-height:1.5}
.rbtn{margin-top:7px;padding:4px 11px;background:var(--blue2);color:#fff;border:none;border-radius:5px;font-size:12px;cursor:pointer;font-family:var(--font)}
.rbtn:hover{background:var(--blue)}
/* toasts */
.tc{position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;max-width:380px}
.toast{background:var(--bg1);border:1px solid var(--br);border-radius:10px;padding:13px 15px;box-shadow:0 6px 20px rgba(0,0,0,.4);display:flex;gap:12px;animation:sli .3s ease-out}
.toast.audit{border-left:3px solid var(--blue)}
.toast.success{border-left:3px solid var(--green)}
.toast.error{border-left:3px solid var(--red)}
.toast.info{border-left:3px solid var(--t1)}
@keyframes sli{from{transform:translateX(400px);opacity:0}to{transform:translateX(0);opacity:1}}
.ticon{font-size:18px;flex-shrink:0}
.tbody{flex:1}
.ttitle{font-weight:600;font-size:14px;margin-bottom:2px}
.tmsg{font-size:12px;color:var(--t1)}
.tcls{background:none;border:none;color:var(--t2);cursor:pointer;font-size:16px;padding:0;width:auto}
/* log */
.log{background:var(--bg0);border:1px solid var(--br);border-radius:8px;padding:10px;max-height:280px;overflow-y:auto;font-family:var(--mono);font-size:12px}
.lr{padding:5px 0;border-bottom:1px solid var(--br);display:flex;gap:10px}
.lt{color:var(--t2);flex-shrink:0}
.lm{color:var(--t1)}
.l-success .lm{color:var(--green)}.l-error .lm{color:var(--red)}.l-warn .lm{color:var(--yellow)}.l-info .lm{color:var(--blue)}
/* search */
.swrap{position:relative}
.sdrop{position:absolute;top:100%;left:0;right:0;background:var(--bg3);border:1px solid var(--br);border-radius:8px;margin-top:4px;max-height:200px;overflow-y:auto;z-index:1000;box-shadow:0 4px 12px rgba(0,0,0,.3)}
.sitem{padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--br)}
.sitem:hover{background:var(--bg2)}
/* user table */
.utbl{width:100%;border-collapse:collapse}
.utbl th{padding:10px 12px;text-align:left;font-size:11px;color:var(--t1);text-transform:uppercase;letter-spacing:.5px;background:var(--bg0);border-bottom:1px solid var(--br);position:sticky;top:0}
.utbl td{padding:11px 12px;border-bottom:1px solid var(--br);font-size:13px;color:var(--t1)}
.uav{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--blue),var(--purple));display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:13px;flex-shrink:0}
/* file upload */
.fil{display:none}
.flab{display:inline-block;padding:10px 18px;background:var(--blue2);color:#fff;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;transition:all .2s}
.flab:hover{background:var(--blue);transform:translateY(-1px)}
/* modal */
.mover{position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:10001;animation:fi .2s}
@keyframes fi{from{opacity:0}to{opacity:1}}
.modal{background:var(--bg1);border:1px solid var(--br);border-radius:12px;padding:24px;width:90%;max-width:480px;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.mtitle{font-size:15px;font-weight:600;margin-bottom:14px}
.origmsg{background:var(--bg2);border-left:3px solid var(--blue);border-radius:6px;padding:10px 12px;margin-bottom:14px;font-size:13px;color:var(--t1)}
/* util */
.hidden{display:none!important}
.chip{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;background:var(--bg3);border:1px solid var(--br);border-radius:20px;font-size:13px;font-family:var(--mono)}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--br2);border-radius:3px}
@media(max-width:768px){.g2,.g4{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-in">
    <div class="logo"><div class="logo-ic">🔔</div><span>Audit System</span></div>
    <div class="hdr-r" id="hdrR" style="display:none">
      <span id="hdrUser" style="color:var(--t1);font-size:13px"></span>
      <div class="nbell" onclick="togglePanel()">🔔<span class="nbadge hidden" id="nbadge">0</span></div>
      <button class="bd bsm" onclick="logout()">Logout</button>
    </div>
  </div>
</div>

<!-- NOTIFICATION PANEL -->
<div class="npanel hidden" id="npanel">
  <div class="nphdr">
    <span>Notifications</span>
    <button class="bg bsm" onclick="clearNotifs()">Clear All</button>
  </div>
  <div class="nlist" id="nlist"><div style="padding:40px;text-align:center;color:var(--t2)">No notifications</div></div>
</div>

<!-- TOASTS -->
<div class="tc" id="tc"></div>

<div class="wrap">

<!-- AUTH -->
<div id="authSec">
  <div class="card" style="max-width:460px;margin:80px auto">
    <div class="tabs">
      <button class="tab on" onclick="swTab('login',this)">Login</button>
      <button class="tab"    onclick="swTab('reg',this)">Register</button>
    </div>
    <div id="loginTab">
      <div class="fg"><label>Username</label><input id="lu" type="text" placeholder="Enter username"></div>
      <div class="fg"><label>Password</label><input id="lp" type="password" placeholder="Enter password"></div>
      <button class="bp bfull" onclick="login()">Login</button>
    </div>
    <div id="regTab" class="hidden">
      <div class="fg"><label>Full Name</label><input id="rn" type="text" placeholder="John Doe"></div>
      <div class="fg"><label>Username</label><input id="ru" type="text" placeholder="johndoe"></div>
      <div class="fg"><label>Password</label><input id="rp" type="password" placeholder="Min 6 characters"></div>
      <button class="bs bfull" onclick="register()">Create Account</button>
    </div>
  </div>
</div>

<!-- MAIN APP -->
<div id="appSec" class="hidden">

  <!-- permission banner -->
  <div id="permBanner" style="display:none;background:var(--bg2);border:1px solid var(--yellow);border-left:4px solid var(--yellow);padding:13px 16px;border-radius:8px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center">
    <span style="font-size:14px">🔔 Enable desktop notifications to stay updated</span>
    <button class="bp bsm" onclick="reqPerm()">Enable</button>
  </div>

  <!-- STATS -->
  <div class="g4" style="margin-bottom:20px">
    <div class="sc"><div class="sl">Online</div><div class="sv" id="sOn">0</div></div>
    <div class="sc"><div class="sl">Total Users</div><div class="sv" id="sTot">0</div></div>
    <div class="sc"><div class="sl">Audits Sent</div><div class="sv" id="sAud">0</div></div>
    <div class="sc" id="scFb" style="display:none"><div class="sl">Pending Feedback</div><div class="sv" id="sFb">0</div></div>
  </div>

  <!-- CONNECTION + ONLINE -->
  <div class="g2">
    <div class="card">
      <div class="ch"><div class="ct">Connection</div>
        <span class="badge b-off" id="cbadge"><span class="bdot"></span><span id="ctext">Offline</span></span>
      </div>
      <button id="cbtn" class="bp bfull" onclick="connectWS()">Connect</button>
    </div>
    <div class="card">
      <div class="ch"><div class="ct">🌐 Online Now</div></div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;min-height:30px" id="chips">
        <span style="color:var(--t2);font-size:13px">No users online</span>
      </div>
    </div>
  </div>

  <!-- SEND AUDIT -->
  <div id="auditCard" class="card hidden">
    <div class="ch"><div class="ct">📤 Send Audit Request</div></div>
    <div class="g2">
      <div class="fg swrap">
        <label>Target User</label>
        <input id="tUser" type="text" placeholder="Type to search…" autocomplete="off"
          oninput="srchUsers(this.value)" onfocus="srchUsers(this.value)">
        <div id="sdrop" class="sdrop hidden"></div>
      </div>
      <div class="fg"><label>Details</label><input id="aDetail" type="text" placeholder="What needs auditing?"></div>
    </div>
    <button class="bs bfull" onclick="sendAudit()">Send Request</button>
  </div>

  <!-- FEEDBACK FORM (non-admin) -->
  <div id="fbForm" class="card">
    <div class="ch"><div class="ct">💬 Send Feedback</div></div>
    <div class="g2">
      <div class="fg">
        <label>Type</label>
        <select id="fbT">
          <option value="bug">🐛 Bug Report</option>
          <option value="feature">✨ Feature Request</option>
          <option value="general">💭 General Feedback</option>
        </select>
      </div>
      <div class="fg"><label>Subject</label><input id="fbS" type="text" placeholder="Brief description"></div>
    </div>
    <div class="fg"><label>Message</label><textarea id="fbM" placeholder="Describe in detail…"></textarea></div>
    <button class="bs bfull" onclick="submitFb()">Submit Feedback</button>
  </div>

  <!-- ===== ADMIN ONLY ===== -->

  <!-- IMPORT -->
  <div id="importCard" class="card hidden">
    <div class="ch"><div class="ct">📥 Import Users</div></div>
    <div style="text-align:center;padding:14px">
      <p style="color:var(--t1);margin-bottom:14px">Excel: Column A = First Name, B = Last Name, C = Username</p>
      <input type="file" id="xlFile" class="fil" accept=".xlsx,.xls" onchange="importUsers()">
      <label for="xlFile" class="flab">Choose Excel File</label>
      <div id="impSt" style="margin-top:10px;font-size:14px"></div>
    </div>
  </div>

  <!-- BROADCAST -->
  <div id="bcCard" class="card hidden">
    <div class="ch"><div class="ct">📢 Broadcast Message</div></div>
    <div class="g2">
      <div class="fg">
        <label>Audience</label>
        <select id="bcTarget"><option value="online">Online Users Only</option><option value="all">All Registered Users</option></select>
      </div>
      <div class="fg"><label>Message</label><input id="bcMsg" type="text" placeholder="Type your announcement…"></div>
    </div>
    <button class="bp bfull" onclick="sendBroadcast()">Send Broadcast</button>
  </div>

  <!-- USER MANAGEMENT -->
  <div id="userCard" class="card hidden">
    <div class="ch">
      <div class="ct">👥 User Management</div>
      <div style="display:flex;gap:8px">
        <button class="bg bsm" onclick="loadUsers()">🔄 Refresh</button>
        <button class="bs bsm" onclick="exportCSV()">📊 Export CSV</button>
      </div>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:10px">
      <input id="uSrch" type="text" placeholder="Search users…" style="flex:1" oninput="filterUsers(this.value)">
      <select id="uFilter" onchange="filterUsers()" style="width:155px">
        <option value="all">All Users</option>
        <option value="online">Online Only</option>
        <option value="offline">Offline Only</option>
      </select>
    </div>
    <div style="display:flex;gap:24px;background:var(--bg2);padding:9px 14px;border-radius:8px;margin-bottom:12px">
      <span style="font-size:13px;color:var(--t1)">Total: <strong id="uTot" style="color:var(--t0)">0</strong></span>
      <span style="font-size:13px;color:var(--t1)">Online: <strong id="uOn" style="color:var(--green)">0</strong></span>
      <span style="font-size:13px;color:var(--t1)">New Today: <strong id="uNew" style="color:var(--blue)">0</strong></span>
    </div>
    <div style="max-height:460px;overflow-y:auto;border:1px solid var(--br);border-radius:8px">
      <table class="utbl">
        <thead>
          <tr>
            <th>User</th><th>Email</th><th>Status</th><th>Joined</th><th>Last Login</th><th style="text-align:center">Actions</th>
          </tr>
        </thead>
        <tbody id="uBody"><tr><td colspan="6" style="text-align:center;padding:40px;color:var(--t2)">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- FEEDBACK MANAGEMENT -->
  <div id="fbMgmt" class="card hidden">
    <div class="ch">
      <div class="ct">📋 Feedback Management</div>
      <div style="display:flex;gap:8px">
        <select id="fbFilt" onchange="loadFeedback()" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--br);border-radius:6px;color:var(--t0);font-size:13px">
          <option value="all">All Types</option>
          <option value="bug">🐛 Bugs</option>
          <option value="feature">✨ Features</option>
          <option value="general">💭 General</option>
        </select>
        <button class="bg bsm" onclick="loadFeedback()">🔄 Refresh</button>
      </div>
    </div>
    <div id="fbList" style="max-height:400px;overflow-y:auto"></div>
  </div>

  <!-- SYSTEM STATS -->
  <div id="statsCard" class="card hidden">
    <div class="ch">
      <div class="ct">📈 System Analytics</div>
      <button class="bg bsm" onclick="loadStats()">🔄 Refresh</button>
    </div>
    <div class="g4">
      <div class="sc"><div class="sl">Total Users</div><div class="sv" id="stU">0</div></div>
      <div class="sc"><div class="sl">Online Now</div><div class="sv" id="stO">0</div></div>
      <div class="sc"><div class="sl">Total Audits</div><div class="sv" id="stA">0</div></div>
      <div class="sc"><div class="sl">Pending Feedback</div><div class="sv" id="stF">0</div></div>
    </div>
  </div>

  <!-- ACTIVITY LOG -->
  <div class="card">
    <div class="ch">
      <div class="ct">📋 Activity Log</div>
      <button class="bg bsm" onclick="document.getElementById('logBox').innerHTML=''">Clear</button>
    </div>
    <div class="log" id="logBox">
      <div class="lr l-info"><span class="lt">[SYSTEM]</span><span class="lm">Ready</span></div>
    </div>
  </div>

</div><!-- /appSec -->
</div><!-- /wrap -->

<script>
// ── config ───────────────────────────────────────────────────
const API = location.hostname==='localhost'?'http://localhost:8080':'https://audit-notification.onrender.com';
const WSS = location.hostname==='localhost'?'ws://localhost:8080':'wss://audit-notification.onrender.com';

// ── sounds ───────────────────────────────────────────────────
const SND = {
  audit:   new Audio('https://assets.mixkit.co/active_storage/sfx/2354/2354-preview.mp3'),
  reply:   new Audio('https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3'),
  success: new Audio('https://assets.mixkit.co/active_storage/sfx/2568/2568-preview.mp3'),
};
Object.values(SND).forEach(a=>a.volume=1.0);
function playSound(t){const s=SND[t]||SND.audit;s.currentTime=0;s.play().catch(()=>{})}

// ── state (single declarations) ─────────────────────────────
var ws=null, me=null, manualDisc=false, retries=0;
var notifs=[], unread=0, online=[], auditCount=0;
var userList=[];          // admin user list
var onlineTimer=null, srchTimer=null;

// ── tabs ─────────────────────────────────────────────────────
function swTab(t,btn){
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
  btn&&btn.classList.add('on');
  document.getElementById('loginTab').classList.toggle('hidden',t!=='login');
  document.getElementById('regTab').classList.toggle('hidden',t!=='reg');
}

// ── auth ─────────────────────────────────────────────────────
async function register(){
  var n=document.getElementById('rn').value.trim();
  var u=document.getElementById('ru').value.trim();
  var p=document.getElementById('rp').value;
  if(!n||!u||!p) return toast('Error','All fields required','error');
  if(p.length<6) return toast('Error','Password must be at least 6 characters','error');
  try{
    var r=await fetch(API+'/register',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u,email:u+'@local.system',full_name:n,password:p})});
    if(!r.ok){var t2=await r.text();return toast('Error',t2,'error');}
    toast('Success','Account created! Please login.','success');
    swTab('login',document.querySelectorAll('.tab')[0]);
    document.getElementById('lu').value=u;
  }catch(e){toast('Error',e.message,'error');}
}

async function login(){
  var u=document.getElementById('lu').value.trim();
  var p=document.getElementById('lp').value;
  if(!u||!p) return toast('Error','Username and password required','error');
  try{
    var r=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u,password:p})});
    if(!r.ok) return toast('Error','Invalid credentials','error');
    var d=await r.json();
    me=d.user;
    localStorage.setItem('me',JSON.stringify(me));
    showApp();
  }catch(e){toast('Error','Login failed: '+e.message,'error');}
}

function logout(){
  if(ws){manualDisc=true;ws.close();}
  clearInterval(onlineTimer);
  me=null; localStorage.removeItem('me');
  document.getElementById('authSec').classList.remove('hidden');
  document.getElementById('appSec').classList.add('hidden');
  document.getElementById('hdrR').style.display='none';
  document.getElementById('auditCard').classList.add('hidden');
  online=[]; renderChips();
  addLog('Logged out','info');
}

// ── show app ─────────────────────────────────────────────────
function showApp(){
  document.getElementById('authSec').classList.add('hidden');
  document.getElementById('appSec').classList.remove('hidden');
  document.getElementById('hdrR').style.display='flex';
  document.getElementById('hdrUser').textContent='@'+(me.username||'');
  loadNotifs();
  checkPerm();
  auditCount=parseInt(localStorage.getItem('ac')||'0');
  document.getElementById('sAud').textContent=auditCount;
  if(me.username==='admin') showAdminPanels();
  addLog('Welcome '+(me.full_name||me.username),'success');
  setTimeout(()=>{if(!ws||ws.readyState!==WebSocket.OPEN)connectWS();},400);
}

function showAdminPanels(){
  ['importCard','bcCard','userCard','fbMgmt','statsCard'].forEach(function(id){
    document.getElementById(id).classList.remove('hidden');
  });
  document.getElementById('scFb').style.display='block';
  document.getElementById('fbForm').classList.add('hidden');
  loadUsers(); loadFeedback(); loadStats();
}

// ── websocket ─────────────────────────────────────────────────
function connectWS(){
  if(!me) return;
  addLog('Connecting…','info');
  ws=new WebSocket(WSS+'/ws?user='+me.username);

  ws.onopen=function(){
    setConn(true);
    addLog('Connected','success');
    retries=0; manualDisc=false;
    reqPerm();
    fetchOnline();
    clearInterval(onlineTimer);
    onlineTimer=setInterval(fetchOnline,5000);
  };

  ws.onmessage=function(e){
    try{
      var d=JSON.parse(e.data);
      playSound(d.isReply?'reply':'audit');
      var title=d.isReply?('Reply from @'+d.sender):('Audit from @'+d.sender);
      toast(title,d.message,d.isReply?'success':'audit',8000);
      deskNotif(d.sender,d.message);
      addNotif({id:d.id,message:d.message,sender:d.sender,time:new Date(),read:false,
        canReply:d.canReply!==false,isReply:d.isReply||false});
      addLog(d.sender+': '+d.message,'success');
    }catch(err){
      playSound('audit');
      toast('Notification',e.data,'audit',8000);
      addNotif({message:e.data,sender:'System',time:new Date(),read:false,canReply:false});
    }
  };

  ws.onclose=function(){
    setConn(false);
    clearInterval(onlineTimer);
    online=[]; renderChips();
    if(!manualDisc){
      var delay=Math.min(1000*Math.pow(2,retries),30000);
      addLog('Reconnecting in '+(delay/1000)+'s…','info');
      setTimeout(connectWS,delay);
      retries++;
    }
  };

  ws.onerror=function(){addLog('WebSocket error','error');};
}

function disconnectWS(){manualDisc=true;if(ws)ws.close();clearInterval(onlineTimer);}

function setConn(on){
  document.getElementById('cbadge').className='badge '+(on?'b-on':'b-off');
  document.getElementById('ctext').textContent=on?'Connected':'Disconnected';
  var btn=document.getElementById('cbtn');
  btn.textContent=on?'Disconnect':'Connect';
  btn.className=on?'bd bfull':'bp bfull';
  btn.onclick=on?disconnectWS:connectWS;
  document.getElementById('auditCard').classList.toggle('hidden',!on);
}

// ── online users ──────────────────────────────────────────────
async function fetchOnline(){
  try{
    var r=await fetch(API+'/online?_='+Date.now(),{cache:'no-cache'});
    if(!r.ok) return;
    var d=await r.json();
    online=d.online||[];
    document.getElementById('sOn').textContent=online.length;
    document.getElementById('sTot').textContent=d.total||0;
    renderChips();
    if(me&&me.username==='admin'){
      document.getElementById('uOn').textContent=online.length;
    }
  }catch(e){}
}

function renderChips(){
  var el=document.getElementById('chips');
  if(!online.length){el.innerHTML='<span style="color:var(--t2);font-size:13px">No users online</span>';return;}
  el.innerHTML=online.map(function(u){
    return '<div class="chip"><span style="width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block"></span>'+esc(u)+'</div>';
  }).join('');
}

// ── notifications ─────────────────────────────────────────────
function addNotif(n){
  notifs.unshift(n); unread++;
  renderBadge(); renderList(); saveNotifs();
}

function renderBadge(){
  var b=document.getElementById('nbadge');
  if(unread>0){b.textContent=unread>99?'99+':unread;b.classList.remove('hidden');}
  else b.classList.add('hidden');
}

function renderList(){
  var el=document.getElementById('nlist');
  if(!notifs.length){el.innerHTML='<div style="padding:40px;text-align:center;color:var(--t2)">No notifications</div>';return;}
  el.innerHTML=notifs.map(function(n){
    var replyBtn=n.canReply?('<button class="rbtn" onclick="event.stopPropagation();openReply('+(n.id||0)+',\''+esc(n.sender)+'\',\''+esc(n.message)+'\')">💬 Reply</button>'):'';
    var tag=n.isReply?'<div style="color:var(--blue);font-size:11px;margin-top:4px">↩ Reply</div>':'';
    return '<div class="ni '+(n.read?'':'unread')+'" onclick="markRead('+(n.id||0)+')">'+
      '<div class="ntime">'+timeAgo(n.time)+'</div>'+
      '<div class="nmsg">'+esc(n.message)+'</div>'+replyBtn+tag+'</div>';
  }).join('');
}

function togglePanel(){
  var p=document.getElementById('npanel');
  p.classList.toggle('hidden');
  if(!p.classList.contains('hidden')){
    notifs.forEach(function(n){n.read=true;});
    unread=0; renderBadge(); renderList(); saveNotifs();
  }
}

function markRead(id){
  var n=notifs.find(function(x){return x.id===id;});
  if(n&&!n.read){n.read=true;unread=Math.max(0,unread-1);renderBadge();saveNotifs();}
}

function clearNotifs(){notifs=[];unread=0;renderBadge();renderList();saveNotifs();}

function saveNotifs(){
  var d=Date.now()-86400000;
  localStorage.setItem('notifs',JSON.stringify(
    notifs.filter(function(n){return new Date(n.time)>d;}).slice(0,50)
  ));
}

function loadNotifs(){
  try{
    var s=localStorage.getItem('notifs');
    if(s){
      notifs=JSON.parse(s).map(function(n){return Object.assign({},n,{time:new Date(n.time)});});
      unread=notifs.filter(function(n){return !n.read;}).length;
      renderBadge(); renderList();
    }
  }catch(e){notifs=[];}
}

// ── reply modal ───────────────────────────────────────────────
function openReply(id,sender,origMsg){
  var m=document.createElement('div');
  m.className='mover'; m.id='rModal';
  m.innerHTML='<div class="modal">'+
    '<div class="mtitle">Reply to @'+esc(sender)+'</div>'+
    '<div class="origmsg"><strong>Original:</strong><br>'+esc(origMsg)+'</div>'+
    '<div class="fg"><label>Your Reply</label><textarea id="rTxt" placeholder="Type your reply…"></textarea></div>'+
    '<div style="display:flex;gap:10px;justify-content:flex-end">'+
      '<button class="bg" onclick="closeReply()">Cancel</button>'+
      '<button class="bs" onclick="sendReply('+id+',\''+esc(sender)+'\')">Send Reply</button>'+
    '</div></div>';
  document.body.appendChild(m);
  m.addEventListener('click',function(e){if(e.target===m)closeReply();});
  document.getElementById('rTxt').focus();
}

function closeReply(){var m=document.getElementById('rModal');if(m)m.remove();}

async function sendReply(id,sender){
  var txt=document.getElementById('rTxt').value.trim();
  if(!txt) return toast('Error','Reply cannot be empty','error');
  try{
    var r=await fetch(API+'/reply',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({notificationId:id,replyMessage:txt,replierUsername:me.username})});
    if(!r.ok) throw new Error('Reply failed');
    playSound('success');
    toast('Sent','Reply sent to @'+sender,'success');
    addLog('Reply sent to @'+sender,'success');
    closeReply();
    var n=notifs.find(function(x){return x.id===id;});
    if(n){n.canReply=false;renderList();saveNotifs();}
  }catch(e){toast('Error',e.message,'error');}
}

// ── send audit ────────────────────────────────────────────────
function srchUsers(q){
  clearTimeout(srchTimer);
  var drop=document.getElementById('sdrop');
  if(!q||q.length<2){drop.classList.add('hidden');return;}
  srchTimer=setTimeout(async function(){
    try{
      var r=await fetch(API+'/search?q='+encodeURIComponent(q));
      if(!r.ok) return;
      var users=await r.json();
      drop.innerHTML=users.length
        ?users.map(function(u){return '<div class="sitem" onclick="pickUser(\''+esc(u.username)+'\')"><strong>'+esc(u.fullName)+'</strong><div style="font-size:11px;color:var(--t2)">@'+esc(u.username)+'</div></div>';}).join('')
        :'<div style="padding:12px;color:var(--t2)">No users found</div>';
      drop.classList.remove('hidden');
    }catch(e){}
  },300);
}

function pickUser(u){
  document.getElementById('tUser').value=u;
  document.getElementById('sdrop').classList.add('hidden');
  document.getElementById('aDetail').focus();
}

async function sendAudit(){
  if(!ws||ws.readyState!==WebSocket.OPEN) return toast('Error','Connect first','error');
  var target=document.getElementById('tUser').value.trim();
  var detail=document.getElementById('aDetail').value.trim();
  if(!target||!detail) return toast('Error','All fields required','error');
  try{
    var r=await fetch(API+'/audit',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({targetUser:target,requester:me.username,details:detail})});
    if(!r.ok) throw new Error('Send failed');
    var d=await r.json();
    toast('Sent',d.message,'success',3000);
    addLog('Audit sent to @'+target,'success');
    document.getElementById('tUser').value='';
    document.getElementById('aDetail').value='';
    auditCount++; localStorage.setItem('ac',auditCount);
    document.getElementById('sAud').textContent=auditCount;
  }catch(e){toast('Error',e.message,'error');}
}

// ── broadcast ─────────────────────────────────────────────────
async function sendBroadcast(){
  if(!ws||ws.readyState!==WebSocket.OPEN) return toast('Error','Connect first','error');
  var target=document.getElementById('bcTarget').value;
  var msg=document.getElementById('bcMsg').value.trim();
  if(!msg) return toast('Error','Message required','error');
  if(!confirm('Broadcast to '+(target==='online'?'online users':'all users')+'?')) return;
  try{
    var r=await fetch(API+'/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({message:msg,sender:me.username,targetType:target})});
    if(!r.ok) throw new Error('Failed');
    var d=await r.json();
    toast('Broadcast Sent',d.message,'success',5000);
    addLog('Broadcast: '+d.delivered+' delivered, '+d.queued+' queued','success');
    document.getElementById('bcMsg').value='';
  }catch(e){toast('Error',e.message,'error');}
}

// ── feedback (user) ───────────────────────────────────────────
async function submitFb(){
  var type=document.getElementById('fbT').value;
  var subj=document.getElementById('fbS').value.trim();
  var msg=document.getElementById('fbM').value.trim();
  if(!subj||!msg) return toast('Error','All fields required','error');
  try{
    var r=await fetch(API+'/feedback',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:me.username,subject:subj,message:msg,type:type})});
    if(!r.ok) throw new Error('Submission failed');
    toast('Submitted','Feedback sent to admin!','success',4000);
    addLog('Feedback submitted','success');
    document.getElementById('fbS').value='';
    document.getElementById('fbM').value='';
  }catch(e){toast('Error',e.message,'error');}
}

// ── import ────────────────────────────────────────────────────
async function importUsers(){
  var file=document.getElementById('xlFile').files[0];
  var st=document.getElementById('impSt');
  if(!file) return;
  var form=new FormData(); form.append('file',file);
  st.innerHTML='<span style="color:var(--blue)">Importing…</span>';
  try{
    var r=await fetch(API+'/import?admin='+me.username,{method:'POST',body:form});
    if(!r.ok) throw new Error('Import failed');
    var d=await r.json();
    st.innerHTML='<span style="color:var(--green)">✅ Imported '+d.imported+', skipped '+d.skipped+'</span>';
    toast('Done','Imported '+d.imported+' users','success');
    loadUsers();
  }catch(e){
    st.innerHTML='<span style="color:var(--red)">'+e.message+'</span>';
    toast('Error',e.message,'error');
  }
  document.getElementById('xlFile').value='';
}

// ── admin: users ──────────────────────────────────────────────
async function loadUsers(){
  try{
    var r=await fetch(API+'/admin/users',{headers:{'X-Admin-User':'admin'}});
    if(!r.ok) throw new Error('Failed');
    var d=await r.json();
    userList=d.users||[];
    renderUsers(userList);
    var today=new Date().toDateString();
    var newT=userList.filter(function(u){return new Date(u.created_at).toDateString()===today;}).length;
    document.getElementById('uTot').textContent=userList.length;
    document.getElementById('uOn').textContent=online.length;
    document.getElementById('uNew').textContent=newT;
    document.getElementById('sTot').textContent=userList.length;
  }catch(e){toast('Error',e.message,'error');}
}

function renderUsers(list){
  var b=document.getElementById('uBody');
  if(!list||!list.length){
    b.innerHTML='<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--t2)">No users found</td></tr>';
    return;
  }
  b.innerHTML=list.map(function(u){
    var on=online.indexOf(u.username)>-1;
    var ini=u.full_name.split(' ').map(function(x){return x[0];}).join('').toUpperCase().slice(0,2);
    var joined=new Date(u.created_at).toLocaleDateString();
    var last=u.last_login?new Date(u.last_login).toLocaleString():'Never';
    return '<tr>'+
      '<td><div style="display:flex;align-items:center;gap:10px">'+
        '<div class="uav">'+esc(ini)+'</div>'+
        '<div><div style="font-weight:500;color:var(--t0)">'+esc(u.full_name)+'</div>'+
        '<div style="font-size:11px;color:var(--t2);font-family:var(--mono)">@'+esc(u.username)+'</div></div></div></td>'+
      '<td>'+esc(u.email)+'</td>'+
      '<td><span class="badge '+(on?'b-on':'b-off')+'"><span class="bdot"></span>'+(on?'Online':'Offline')+'</span></td>'+
      '<td>'+joined+'</td>'+
      '<td>'+last+'</td>'+
      '<td style="text-align:center"><button class="bp bsm" onclick="qkAudit(\''+esc(u.username)+'\')" title="Send Audit">📤</button></td>'+
      '</tr>';
  }).join('');
}

function filterUsers(q){
  var query=(q||document.getElementById('uSrch').value).toLowerCase();
  var sf=document.getElementById('uFilter').value;
  var res=userList.filter(function(u){
    var mq=!query||u.username.toLowerCase().indexOf(query)>-1||u.full_name.toLowerCase().indexOf(query)>-1||u.email.toLowerCase().indexOf(query)>-1;
    var ms=sf==='all'||(sf==='online'&&online.indexOf(u.username)>-1)||(sf==='offline'&&online.indexOf(u.username)<0);
    return mq&&ms;
  });
  renderUsers(res);
}

function exportCSV(){
  var rows=[['Username','Full Name','Email','Status','Joined','Last Login']];
  userList.forEach(function(u){
    rows.push([u.username,u.full_name,u.email,
      online.indexOf(u.username)>-1?'Online':'Offline',
      new Date(u.created_at).toLocaleDateString(),
      u.last_login?new Date(u.last_login).toLocaleString():'Never']);
  });
  var csv=rows.map(function(r){return r.join(',');}).join('\n');
  var a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download='users_'+new Date().toISOString().split('T')[0]+'.csv';
  a.click();
  toast('Exported','User list downloaded','success',3000);
}

function qkAudit(u){
  document.getElementById('tUser').value=u;
  document.getElementById('auditCard').scrollIntoView({behavior:'smooth'});
  document.getElementById('aDetail').focus();
}

// ── admin: feedback ───────────────────────────────────────────
async function loadFeedback(){
  var type=document.getElementById('fbFilt').value;
  var url=API+'/admin/feedback'+(type&&type!=='all'?'?type='+type:'');
  try{
    var r=await fetch(url,{headers:{'X-Admin-User':'admin'}});
    if(!r.ok) throw new Error('Failed');
    var d=await r.json();
    renderFeedback(d.feedback||[]);
  }catch(e){toast('Error',e.message,'error');}
}

function renderFeedback(items){
  var el=document.getElementById('fbList');
  if(!items||!items.length){
    el.innerHTML='<div style="padding:40px;text-align:center;color:var(--t2)">No feedback yet</div>';
    return;
  }
  var icons={bug:'🐛',feature:'✨',general:'💭'};
  el.innerHTML=items.map(function(f){
    var ic=icons[f.type]||'💭';
    var resolved=f.status==='resolved';
    return '<div style="background:var(--bg2);border:1px solid var(--br);border-radius:8px;padding:13px;margin-bottom:10px">'+
      '<div style="display:flex;justify-content:space-between;margin-bottom:6px">'+
        '<div>'+
          '<span style="font-weight:600;color:var(--t0)">@'+esc(f.username)+'</span>'+
          '<span style="margin-left:8px;padding:2px 8px;background:var(--bg3);border-radius:4px;font-size:11px;color:var(--t1)">'+ic+' '+f.type+'</span>'+
          '<span style="margin-left:6px;padding:2px 8px;background:'+(resolved?'rgba(63,185,80,.1)':'rgba(210,153,34,.1)')+';border-radius:4px;font-size:11px;color:'+(resolved?'var(--green)':'var(--yellow)')+'">'+f.status+'</span>'+
        '</div>'+
        '<span style="font-size:12px;color:var(--t2)">'+timeAgo(new Date(f.timestamp))+'</span>'+
      '</div>'+
      '<div style="font-weight:500;color:var(--t0);margin-bottom:4px">'+esc(f.subject)+'</div>'+
      '<div style="font-size:13px;color:var(--t1);margin-bottom:10px">'+esc(f.message)+'</div>'+
      '<div style="display:flex;gap:8px">'+
        '<button class="bs bsm" onclick="replyFb('+f.id+',\''+esc(f.username)+'\')">💬 Reply</button>'+
        (!resolved?'<button class="bg bsm" onclick="resolveFb('+f.id+')">✅ Resolve</button>':'')+
      '</div></div>';
  }).join('');
}

async function resolveFb(id){
  try{
    await fetch(API+'/admin/feedback/update',{method:'POST',
      headers:{'Content-Type':'application/json','X-Admin-User':'admin'},
      body:JSON.stringify({id:id,status:'resolved'})});
    toast('Done','Marked as resolved','success',3000);
    loadFeedback();
  }catch(e){toast('Error',e.message,'error');}
}

function replyFb(id,username){
  document.getElementById('tUser').value=username;
  document.getElementById('auditCard').scrollIntoView({behavior:'smooth'});
  document.getElementById('aDetail').focus();
  toast('Ready','Send reply to @'+username,'info',3000);
}

// ── admin: stats ──────────────────────────────────────────────
async function loadStats(){
  try{
    var r=await fetch(API+'/admin/stats',{headers:{'X-Admin-User':'admin'}});
    if(!r.ok) throw new Error('Failed');
    var d=await r.json();
    document.getElementById('stU').textContent=d.total_users||0;
    document.getElementById('stO').textContent=d.online_users||0;
    document.getElementById('stA').textContent=d.total_audits||0;
    document.getElementById('stF').textContent=d.pending_feedback||0;
    document.getElementById('sFb').textContent=d.pending_feedback||0;
  }catch(e){toast('Error',e.message,'error');}
}

// ── permissions ───────────────────────────────────────────────
function checkPerm(){
  var b=document.getElementById('permBanner');
  b.style.display=('Notification' in window&&Notification.permission==='default')?'flex':'none';
}

function reqPerm(){
  if(!('Notification' in window)) return;
  Notification.requestPermission().then(function(p){
    if(p==='granted') toast('Enabled','Desktop notifications enabled','success',3000);
    document.getElementById('permBanner').style.display='none';
  });
}

function deskNotif(sender,message){
  if('Notification' in window&&Notification.permission==='granted'){
    try{
      var n=new Notification(sender,{body:message,requireInteraction:false});
      n.onclick=function(){window.focus();n.close();};
      setTimeout(function(){n.close();},8000);
    }catch(e){}
  }
}

// ── log ───────────────────────────────────────────────────────
function addLog(msg,type){
  var box=document.getElementById('logBox');
  var row=document.createElement('div');
  row.className='lr l-'+(type||'info');
  row.innerHTML='<span class="lt">['+new Date().toLocaleTimeString()+']</span><span class="lm">'+esc(msg)+'</span>';
  box.appendChild(row);
  box.scrollTop=box.scrollHeight;
  if(box.children.length>100) box.removeChild(box.firstChild);
}

// ── toast ─────────────────────────────────────────────────────
function toast(title,msg,type,dur){
  if(dur===undefined) dur=5000;
  var c=document.getElementById('tc');
  var t=document.createElement('div');
  t.className='toast '+(type||'info');
  var icons={success:'✅',error:'❌',warning:'⚠️',info:'ℹ️',audit:'🔔'};
  t.innerHTML='<div class="ticon">'+(icons[type]||'ℹ️')+'</div>'+
    '<div class="tbody"><div class="ttitle">'+esc(title)+'</div><div class="tmsg">'+esc(msg)+'</div></div>'+
    '<button class="tcls" onclick="this.parentElement.remove()">×</button>';
  c.appendChild(t);
  if(dur>0) setTimeout(function(){t.style.opacity='0';setTimeout(function(){t.remove();},300);},dur);
}

// ── utils ─────────────────────────────────────────────────────
function esc(s){
  if(s==null) return '';
  var d=document.createElement('div');
  d.textContent=String(s);
  return d.innerHTML;
}

function timeAgo(d){
  var diff=Math.floor((Date.now()-new Date(d))/1000);
  if(diff<60) return 'Just now';
  if(diff<3600) return Math.floor(diff/60)+'m ago';
  if(diff<86400) return Math.floor(diff/3600)+'h ago';
  return new Date(d).toLocaleDateString();
}

// ── init ──────────────────────────────────────────────────────
window.onload=function(){
  try{
    var s=localStorage.getItem('me');
    if(s){me=JSON.parse(s);showApp();}
  }catch(e){localStorage.removeItem('me');}
};

document.addEventListener('click',function(e){
  var panel=document.getElementById('npanel');
  var bell=document.querySelector('.nbell');
  if(panel&&!panel.contains(e.target)&&bell&&!bell.contains(e.target))
    panel.classList.add('hidden');

  var drop=document.getElementById('sdrop');
  var wrap=document.querySelector('.swrap');
  if(drop&&wrap&&!wrap.contains(e.target))
    drop.classList.add('hidden');
});
</script>
</body>
</html>
