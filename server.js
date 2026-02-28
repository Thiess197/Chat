/**
 * Flux Chat — server.js  (single file, everything included)
 *
 * SETUP IN GITHUB CODESPACES:
 *   1. Put this file anywhere in your repo
 *   2. Open terminal and run:
 *        npm install express better-sqlite3
 *        node server.js
 *   3. Go to the "Ports" tab → port 3000 → right-click → Port Visibility → Public
 *   4. Click the globe 🌐 to open — share that URL with anyone!
 */

const express  = require('express');
const Database = require('better-sqlite3');
const crypto   = require('crypto');
const https    = require('https');

const app  = express();
const db   = new Database('flux_chat.db');
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10kb' }));

// ── Database ──────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode=WAL;
  PRAGMA foreign_keys=ON;

  CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    password   TEXT NOT NULL,
    color      TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    convo      TEXT NOT NULL,
    sender     TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_convo ON messages(convo, id);
  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    last_seen  INTEGER DEFAULT (unixepoch())
  );
`);

// ── Helpers ───────────────────────────────────────────────
const COLORS = ['#6c63ff','#ff5f87','#3be09a','#ffc94a','#38bdf8','#fb923c','#a78bfa','#34d399'];
function colorFor(u) {
  let h = 0;
  for (let i = 0; i < u.length; i++) h = u.charCodeAt(i) + ((h << 5) - h);
  return COLORS[Math.abs(h) % COLORS.length];
}
function cid(a, b)   { return [a, b].sort().join('::'); }
function token()     { return crypto.randomBytes(24).toString('hex'); }
function hash(p)     { return crypto.createHash('sha256').update('fluxsalt::' + p).digest('hex'); }
function ok(res, d)  { res.json({ ok: true,  ...d }); }
function fail(res, msg, code = 400) { res.status(code).json({ ok: false, error: msg }); }

function auth(req, res) {
  const t = req.headers['x-token'] || '';
  if (!t) { fail(res, 'Not authenticated', 401); return null; }
  const row = db.prepare('SELECT username FROM sessions WHERE token=? AND last_seen > unixepoch()-86400').get(t);
  if (!row) { fail(res, 'Session expired', 401); return null; }
  db.prepare('UPDATE sessions SET last_seen=unixepoch() WHERE token=?').run(t);
  return row.username;
}

// ── API Routes ────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  const u = (req.body.username || '').trim().toLowerCase();
  const p =  req.body.password || '';
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return fail(res, 'Username: 3–20 chars, lowercase/numbers/_');
  if (p.length < 8)                  return fail(res, 'Password must be at least 8 characters');
  if (!/[A-Z]/.test(p))             return fail(res, 'Password needs at least one uppercase letter');
  if (!/[0-9]/.test(p))             return fail(res, 'Password needs at least one number');
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(u)) return fail(res, 'Username already taken');
  db.prepare('INSERT INTO users(username,password,color) VALUES(?,?,?)').run(u, hash(p), colorFor(u));
  const t = token();
  db.prepare('INSERT INTO sessions(token,username) VALUES(?,?)').run(t, u);
  ok(res, { token: t, username: u, color: colorFor(u) });
});

app.post('/api/login', (req, res) => {
  const u = (req.body.username || '').trim().toLowerCase();
  const p =  req.body.password || '';
  if (!u || !p) return fail(res, 'Username and password required');
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if (!row || row.password !== hash(p)) return fail(res, 'Incorrect username or password');
  const t = token();
  db.prepare('INSERT INTO sessions(token,username) VALUES(?,?)').run(t, u);
  ok(res, { token: t, username: u, color: row.color });
});

app.post('/api/change_password', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { current, newpw } = req.body;
  if (!current)            return fail(res, 'Current password required');
  if ((newpw||'').length < 8)  return fail(res, 'New password must be at least 8 characters');
  if (!/[A-Z]/.test(newpw))    return fail(res, 'New password needs at least one uppercase letter');
  if (!/[0-9]/.test(newpw))    return fail(res, 'New password needs at least one number');
  const row = db.prepare('SELECT password FROM users WHERE username=?').get(me);
  if (row.password !== hash(current)) return fail(res, 'Current password is incorrect');
  if (hash(newpw) === row.password)   return fail(res, 'New password must differ from current');
  db.prepare('UPDATE users SET password=? WHERE username=?').run(hash(newpw), me);
  ok(res, {});
});

app.get('/api/users', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const rows = db.prepare('SELECT username, color FROM users ORDER BY username').all();
  const users = rows.map(u => ({
    ...u,
    online: !!db.prepare('SELECT 1 FROM sessions WHERE username=? AND last_seen > unixepoch()-20').get(u.username)
  }));
  ok(res, { users });
});

app.post('/api/send', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const peer = (req.body.peer || '').toLowerCase().trim();
  const text = (req.body.text || '').trim();
  if (!peer || !text)   return fail(res, 'Missing peer or text');
  if (text.length > 4000) return fail(res, 'Message too long');
  if (!db.prepare('SELECT 1 FROM users WHERE username=?').get(peer)) return fail(res, 'User not found');
  const r = db.prepare('INSERT INTO messages(convo,sender,text) VALUES(?,?,?)').run(cid(me, peer), me, text);
  ok(res, { id: r.lastInsertRowid });
});

app.get('/api/messages', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const peer  = (req.query.peer  || '').toLowerCase().trim();
  const since = parseInt(req.query.since || '0');
  if (!peer) return fail(res, 'Missing peer');
  const msgs = db.prepare(
    'SELECT id,sender,text,created_at FROM messages WHERE convo=? AND id>? ORDER BY id ASC LIMIT 100'
  ).all(cid(me, peer), since);
  ok(res, { messages: msgs });
});

app.post('/api/ai', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { api_key, history } = req.body;
  if (!api_key || !history?.length) return fail(res, 'Missing api_key or history');
  const payload = JSON.stringify({
    model: 'claude-sonnet-4-20250514', max_tokens: 1024,
    system: 'You are a friendly AI assistant inside Flux Chat. Be conversational and concise.',
    messages: history,
  });
  const r = https.request({
    hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': api_key,
               'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(payload) }
  }, resp => {
    let d = '';
    resp.on('data', c => d += c);
    resp.on('end', () => {
      try {
        const j = JSON.parse(d);
        if (resp.statusCode !== 200) return fail(res, j.error?.message || 'Anthropic error', resp.statusCode);
        ok(res, { reply: j.content[0].text });
      } catch { fail(res, 'Bad response from Anthropic'); }
    });
  });
  r.on('error', e => fail(res, e.message));
  r.write(payload); r.end();
});

app.post('/api/ping', (req, res) => { const me = auth(req, res); if (!me) return; ok(res, {}); });

// ── Embedded HTML (served at /) ───────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Flux Chat</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#0d0d14;--s1:#13131f;--s2:#1c1c2e;--s3:#242438;--bd:#2e2e4a;--ac:#6c63ff;--ac2:#ff5f87;--tx:#eaeaf8;--mu:#6464a0;--gr:#3be09a;--rd:#ff5f6d;--yw:#ffc94a;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Syne',sans-serif;background:var(--bg);color:var(--tx);height:100vh;display:flex;overflow:hidden;}

.screen{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg);z-index:100;}
.screen.hidden{display:none;}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:24px;padding:46px 44px;width:450px;position:relative;overflow:hidden;animation:rise .35s cubic-bezier(.16,1,.3,1);}
.card::before{content:'';position:absolute;top:-100px;right:-100px;width:260px;height:260px;background:radial-gradient(circle,rgba(108,99,255,.18),transparent 70%);pointer-events:none;}
.card::after{content:'';position:absolute;bottom:-80px;left:-70px;width:200px;height:200px;background:radial-gradient(circle,rgba(255,95,135,.1),transparent 70%);pointer-events:none;}
.logo{font-size:32px;font-weight:800;letter-spacing:-2px;margin-bottom:4px;}.logo b{color:var(--ac);font-weight:800;}
.tagline{color:var(--mu);font-size:12px;font-family:'DM Mono',monospace;margin-bottom:32px;}

.tabs{display:flex;background:var(--s2);border-radius:12px;padding:4px;margin-bottom:28px;gap:4px;}
.tab{flex:1;padding:10px;border:none;border-radius:9px;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;cursor:pointer;background:transparent;color:var(--mu);transition:all .2s;}
.tab.on{background:var(--s3);color:var(--tx);box-shadow:0 2px 8px rgba(0,0,0,.4);}

.fg{margin-bottom:16px;position:relative;}
.fg label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--mu);margin-bottom:8px;font-family:'DM Mono',monospace;}
.fg input{width:100%;background:var(--s2);border:1.5px solid var(--bd);border-radius:12px;padding:13px 44px 13px 16px;color:var(--tx);font-family:'DM Mono',monospace;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s;}
.fg input:focus{border-color:var(--ac);box-shadow:0 0 0 4px rgba(108,99,255,.1);}
.fg input.bad{border-color:var(--rd)!important;box-shadow:0 0 0 4px rgba(255,95,109,.08)!important;}
.fg input.good{border-color:var(--gr)!important;}
.eyebtn{position:absolute;right:14px;bottom:14px;background:none;border:none;color:var(--mu);cursor:pointer;font-size:15px;padding:0;line-height:1;transition:color .2s;}
.eyebtn:hover{color:var(--tx);}

.pwbar{height:4px;background:var(--bd);border-radius:4px;overflow:hidden;margin-top:8px;}
.pwfill{height:100%;border-radius:4px;width:0%;transition:width .4s,background .4s;}
.pwlabel{font-size:10px;font-family:'DM Mono',monospace;color:var(--mu);margin-top:5px;height:14px;}
.pwreqs{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-top:8px;display:none;}
.pwreqs.show{display:block;}
.pwreq{display:flex;align-items:center;gap:8px;font-size:11px;font-family:'DM Mono',monospace;color:var(--mu);margin-bottom:5px;transition:color .2s;}
.pwreq:last-child{margin-bottom:0;}.pwreq.ok{color:var(--gr);}
.pwreq .ic{font-size:12px;width:14px;text-align:center;}

.errmsg{color:var(--rd);font-size:11px;font-family:'DM Mono',monospace;margin-top:6px;display:none;align-items:center;gap:5px;}
.errmsg.show{display:flex;}

.btn{width:100%;border:none;border-radius:12px;padding:14px;font-family:'Syne',sans-serif;font-size:15px;font-weight:700;cursor:pointer;transition:all .2s;letter-spacing:.3px;margin-top:6px;display:flex;align-items:center;justify-content:center;gap:8px;}
.btn-ac{background:var(--ac);color:#fff;}.btn-ac:hover{background:#8580ff;transform:translateY(-1px);box-shadow:0 6px 24px rgba(108,99,255,.4);}
.btn-ac:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;}
.btn-gh{background:var(--s2);color:var(--tx);border:1.5px solid var(--bd);}.btn-gh:hover{border-color:var(--mu);}
.hint{text-align:center;margin-top:16px;font-size:12px;font-family:'DM Mono',monospace;color:var(--mu);}
.hint a{color:var(--ac);cursor:pointer;text-decoration:underline;}

/* ── APP ── */
#app{display:flex;width:100%;height:100vh;}#app.hidden{display:none;}
.sidebar{width:270px;background:var(--s1);border-right:1px solid var(--bd);display:flex;flex-direction:column;flex-shrink:0;}
.sbhead{padding:18px 16px 14px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;}
.apptitle{font-size:18px;font-weight:800;letter-spacing:-.5px;}.apptitle b{color:var(--ac);}
.opill{display:flex;align-items:center;gap:5px;background:rgba(59,224,154,.08);border:1px solid rgba(59,224,154,.2);border-radius:20px;padding:3px 10px;font-size:11px;font-family:'DM Mono',monospace;color:var(--gr);}
.opill .dot{width:5px;height:5px;border-radius:50%;background:var(--gr);animation:pulse 2s infinite;}
.seclbl{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--mu);font-family:'DM Mono',monospace;padding:14px 16px 6px;}
.chatlist{flex:1;overflow-y:auto;padding:0 8px 8px;}
.ci{display:flex;align-items:center;gap:10px;padding:10px;border-radius:12px;cursor:pointer;transition:background .15s;margin-bottom:2px;}
.ci:hover{background:var(--s2);}.ci.on{background:rgba(108,99,255,.12);}
.av{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;position:relative;}
.av .odot{position:absolute;bottom:-1px;right:-1px;width:11px;height:11px;border-radius:50%;border:2px solid var(--s1);}
.ciinfo{flex:1;min-width:0;}.ciname{font-size:13px;font-weight:700;}
.ciprev{font-size:11px;color:var(--mu);font-family:'DM Mono',monospace;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}
.sbfoot{padding:12px 16px;border-top:1px solid var(--bd);display:flex;align-items:center;gap:10px;}
.sbav{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0;}
.sbinfo{flex:1;min-width:0;}.sbname{font-size:13px;font-weight:700;}.sbsub{font-size:10px;color:var(--mu);font-family:'DM Mono',monospace;}
.icobtn{background:none;border:none;color:var(--mu);cursor:pointer;font-size:16px;padding:5px;border-radius:8px;transition:all .2s;line-height:1;}
.icobtn:hover{color:var(--tx);background:var(--s2);}

.chatarea{flex:1;display:flex;flex-direction:column;min-width:0;}
.empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:var(--mu);}
.empty .ico{font-size:56px;opacity:.2;}.empty h3{font-size:18px;color:var(--tx);font-weight:700;}
.empty p{font-size:12px;font-family:'DM Mono',monospace;}
#panel{display:none;flex-direction:column;height:100%;}
.panhead{padding:14px 22px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:12px;background:var(--s1);}
.panhav{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;}
.panname{font-size:15px;font-weight:700;}.panstatus{font-size:11px;font-family:'DM Mono',monospace;display:flex;align-items:center;gap:5px;margin-top:2px;}
.psdot{width:6px;height:6px;border-radius:50%;}
.aibanner{background:linear-gradient(90deg,rgba(108,99,255,.08),rgba(255,95,135,.06));border-bottom:1px solid rgba(108,99,255,.15);padding:9px 22px;font-size:12px;font-family:'DM Mono',monospace;color:var(--mu);display:flex;align-items:center;justify-content:space-between;}
.aibanner.hidden{display:none;}
.keybtn{background:var(--ac);border:none;border-radius:7px;padding:5px 12px;color:#fff;font-size:11px;font-family:'DM Mono',monospace;cursor:pointer;font-weight:700;}

.msgs{flex:1;overflow-y:auto;padding:18px 22px;display:flex;flex-direction:column;gap:10px;}
.msg{display:flex;gap:8px;max-width:76%;}.msg.me{margin-left:auto;flex-direction:row-reverse;}
.mav{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;margin-top:2px;}
.mcont{flex:1;}.mname{font-size:10px;color:var(--mu);font-family:'DM Mono',monospace;margin-bottom:3px;}.msg.me .mname{text-align:right;}
.mbub{padding:10px 14px;border-radius:14px;font-size:13.5px;line-height:1.55;font-family:'DM Mono',monospace;word-break:break-word;}
.msg:not(.me) .mbub{background:var(--s2);border:1px solid var(--bd);border-top-left-radius:4px;}
.msg.me .mbub{background:var(--ac);color:#fff;border-top-right-radius:4px;}
.aibub{background:linear-gradient(135deg,rgba(108,99,255,.14),rgba(255,95,135,.09))!important;border:1px solid rgba(108,99,255,.25)!important;border-top-left-radius:4px!important;}
.mtime{font-size:10px;color:var(--mu);font-family:'DM Mono',monospace;margin-top:4px;}.msg.me .mtime{text-align:right;}
.typingbub{display:flex;gap:4px;padding:11px 14px;background:var(--s2);border:1px solid var(--bd);border-radius:14px;border-top-left-radius:4px;width:fit-content;}
.td{width:6px;height:6px;border-radius:50%;background:var(--mu);animation:bounce .9s infinite;}
.td:nth-child(2){animation-delay:.15s;}.td:nth-child(3){animation-delay:.3s;}
.datediv{display:flex;align-items:center;gap:10px;margin:4px 0;}
.datediv span{font-size:10px;color:var(--mu);font-family:'DM Mono',monospace;white-space:nowrap;}
.datediv::before,.datediv::after{content:'';flex:1;height:1px;background:var(--bd);}

.inparea{padding:12px 18px;border-top:1px solid var(--bd);background:var(--s1);display:flex;gap:10px;align-items:flex-end;}
.minput{flex:1;background:var(--s2);border:1.5px solid var(--bd);border-radius:12px;padding:11px 15px;color:var(--tx);font-family:'DM Mono',monospace;font-size:13px;outline:none;resize:none;max-height:120px;line-height:1.5;transition:border-color .2s;}
.minput:focus{border-color:var(--ac);}.minput::placeholder{color:var(--mu);}
.sndbtn{width:44px;height:44px;background:var(--ac);border:none;border-radius:12px;color:#fff;cursor:pointer;font-size:19px;display:flex;align-items:center;justify-content:center;transition:all .2s;flex-shrink:0;}
.sndbtn:hover{background:#8580ff;transform:scale(1.07);}

/* Modals */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;z-index:200;backdrop-filter:blur(8px);}
.overlay.hidden{display:none;}
.modal{background:var(--s1);border:1px solid var(--bd);border-radius:20px;padding:36px;width:440px;animation:rise .25s ease;}
.modal h3{font-size:20px;font-weight:800;margin-bottom:8px;}
.modal p{color:var(--mu);font-size:12px;font-family:'DM Mono',monospace;line-height:1.8;margin-bottom:20px;}
.mbtns{display:flex;gap:10px;margin-top:18px;}
.okmsg{color:var(--gr);font-size:12px;font-family:'DM Mono',monospace;margin-top:10px;display:none;align-items:center;gap:6px;}
.okmsg.show{display:flex;}

::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-track{background:transparent;}::-webkit-scrollbar-thumb{background:var(--bd);border-radius:4px;}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes fi{from{opacity:0}to{opacity:1}}
@keyframes bounce{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-7px)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.fi{animation:fi .2s ease;}
</style>
</head>
<body>

<!-- LOGIN -->
<div class="screen" id="login-screen">
  <div class="card">
    <div class="logo">flux<b>.</b>chat</div>
    <div class="tagline">// secure · real-time · AI-powered</div>
    <div class="tabs">
      <button class="tab on" id="tab-li" onclick="switchTab('li')">Sign In</button>
      <button class="tab" id="tab-reg" onclick="switchTab('reg')">Create Account</button>
    </div>

    <!-- Sign in -->
    <div id="form-li">
      <div class="fg">
        <label>Username</label>
        <input id="li-u" type="text" placeholder="your_username" autocomplete="username" onkeydown="if(event.key==='Enter')doLogin()"/>
        <div class="errmsg" id="li-err"></div>
      </div>
      <div class="fg">
        <label>Password</label>
        <input id="li-p" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"/>
        <button class="eyebtn" type="button" onclick="toggleEye('li-p',this)">👁</button>
      </div>
      <button class="btn btn-ac" id="li-btn" onclick="doLogin()">Sign In →</button>
      <div class="hint">No account? <a onclick="switchTab('reg')">Create one free</a></div>
    </div>

    <!-- Register -->
    <div id="form-reg" style="display:none">
      <div class="fg">
        <label>Username</label>
        <input id="reg-u" type="text" placeholder="pick_a_username" autocomplete="username" oninput="valReg()" onkeydown="if(event.key==='Enter')doRegister()"/>
        <div class="errmsg" id="reg-uerr"></div>
      </div>
      <div class="fg">
        <label>Password</label>
        <input id="reg-p" type="password" placeholder="min. 8 chars, 1 uppercase, 1 number" autocomplete="new-password" oninput="valPw('reg-p','reg-sfill','reg-slbl','reg-reqs')" onkeydown="if(event.key==='Enter')doRegister()" onfocus="document.getElementById('reg-reqs').classList.add('show')"/>
        <button class="eyebtn" type="button" onclick="toggleEye('reg-p',this)">👁</button>
        <div class="pwbar"><div class="pwfill" id="reg-sfill"></div></div>
        <div class="pwlabel" id="reg-slbl"></div>
        <div class="pwreqs" id="reg-reqs">
          <div class="pwreq" id="req-len"><span class="ic">○</span> At least 8 characters</div>
          <div class="pwreq" id="req-up"><span class="ic">○</span> One uppercase letter (A–Z)</div>
          <div class="pwreq" id="req-num"><span class="ic">○</span> One number (0–9)</div>
          <div class="pwreq" id="req-match"><span class="ic">○</span> Passwords match</div>
        </div>
        <div class="errmsg" id="reg-perr"></div>
      </div>
      <div class="fg">
        <label>Confirm Password</label>
        <input id="reg-c" type="password" placeholder="repeat password" autocomplete="new-password" oninput="valPw('reg-p','reg-sfill','reg-slbl','reg-reqs')" onkeydown="if(event.key==='Enter')doRegister()"/>
        <button class="eyebtn" type="button" onclick="toggleEye('reg-c',this)">👁</button>
        <div class="errmsg" id="reg-cerr"></div>
      </div>
      <button class="btn btn-ac" id="reg-btn" onclick="doRegister()">Create Account →</button>
      <div class="hint">Already registered? <a onclick="switchTab('li')">Sign in</a></div>
    </div>
  </div>
</div>

<!-- CHANGE PASSWORD MODAL -->
<div class="overlay hidden" id="pw-modal">
  <div class="modal">
    <h3>🔒 Change Password</h3>
    <p>Enter your current password then choose a new secure one.</p>
    <div class="fg">
      <label>Current Password</label>
      <input id="pw-cur" type="password" placeholder="••••••••"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-cur',this)">👁</button>
      <div class="errmsg" id="pw-err"></div>
    </div>
    <div class="fg">
      <label>New Password</label>
      <input id="pw-new" type="password" placeholder="min. 8 chars, 1 uppercase, 1 number" oninput="valPw('pw-new','pw-sfill','pw-slbl','pw-reqs')" onfocus="document.getElementById('pw-reqs').classList.add('show')"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-new',this)">👁</button>
      <div class="pwbar"><div class="pwfill" id="pw-sfill"></div></div>
      <div class="pwlabel" id="pw-slbl"></div>
      <div class="pwreqs" id="pw-reqs">
        <div class="pwreq" id="pwreq-len"><span class="ic">○</span> At least 8 characters</div>
        <div class="pwreq" id="pwreq-up"><span class="ic">○</span> One uppercase letter (A–Z)</div>
        <div class="pwreq" id="pwreq-num"><span class="ic">○</span> One number (0–9)</div>
      </div>
      <div class="errmsg" id="pw-nerr"></div>
    </div>
    <div class="fg">
      <label>Confirm New Password</label>
      <input id="pw-conf" type="password" placeholder="repeat new password"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-conf',this)">👁</button>
      <div class="errmsg" id="pw-cerr"></div>
    </div>
    <div class="okmsg" id="pw-ok">✓ Password changed successfully!</div>
    <div class="mbtns">
      <button class="btn btn-gh" style="flex:1;margin-top:0" onclick="closePwModal()">Cancel</button>
      <button class="btn btn-ac" style="flex:1;margin-top:0" onclick="savePw()">Save Password</button>
    </div>
  </div>
</div>

<!-- API KEY MODAL -->
<div class="overlay hidden" id="key-modal">
  <div class="modal">
    <h3>🤖 Connect Claude AI</h3>
    <p>Your API key is stored only in this browser session and sent directly to Anthropic. The server never stores it.</p>
    <div class="fg">
      <label>Anthropic API Key</label>
      <input id="key-inp" type="password" placeholder="sk-ant-api03-…"/>
      <button class="eyebtn" type="button" onclick="toggleEye('key-inp',this)">👁</button>
      <div class="errmsg" id="key-err"></div>
    </div>
    <div class="mbtns">
      <button class="btn btn-gh" style="flex:1;margin-top:0" onclick="closeKeyModal()">Maybe Later</button>
      <button class="btn btn-ac" style="flex:1;margin-top:0" onclick="saveKey()">Connect →</button>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app" class="hidden">
  <div class="sidebar">
    <div class="sbhead">
      <div class="apptitle">flux<b>.</b>chat</div>
      <div class="opill"><span class="dot"></span><span id="online-n">–</span></div>
    </div>
    <div class="seclbl">People</div>
    <div class="chatlist" id="chatlist"></div>
    <div class="sbfoot">
      <div class="sbav" id="sbav"></div>
      <div class="sbinfo">
        <div class="sbname" id="sbname"></div>
        <div class="sbsub">// online</div>
      </div>
      <button class="icobtn" onclick="openPwModal()" title="Change password">⚙</button>
      <button class="icobtn" onclick="doLogout()" title="Sign out" style="color:var(--rd)">↩</button>
    </div>
  </div>

  <div class="chatarea">
    <div class="empty" id="empty">
      <div class="ico">💬</div>
      <h3>No conversation open</h3>
      <p>// pick someone from the left</p>
    </div>
    <div id="panel">
      <div class="panhead">
        <div class="panhav" id="panav"></div>
        <div>
          <div class="panname" id="panname"></div>
          <div class="panstatus"><span class="psdot" id="psdot"></span><span id="panst">online</span></div>
        </div>
      </div>
      <div class="aibanner hidden" id="aibanner">
        ✦ AI assistant — add your Anthropic API key to chat
        <button class="keybtn" onclick="openKeyModal()">Set Key</button>
      </div>
      <div class="msgs" id="msgs"></div>
      <div class="inparea">
        <textarea class="minput" id="msginp" placeholder="Type a message… (Enter to send)" rows="1"
          onkeydown="onKey(event)" oninput="resize(this)"></textarea>
        <button class="sndbtn" onclick="sendMsg()">↑</button>
      </div>
    </div>
  </div>
</div>

<script>
const API = '/api';
let token   = sessionStorage.getItem('fc_tok')   || null;
let me      = sessionStorage.getItem('fc_me')    || null;
let myColor = sessionStorage.getItem('fc_col')   || '#6c63ff';
let apiKey  = sessionStorage.getItem('fc_akey')  || null;
let peer = null, lastId = 0, pollT = null, hbT = null, users = [], aiHist = [];

// ── API ───────────────────────────────────────────────────
async function api(path, body, method='POST') {
  const isGet = method === 'GET';
  const url   = isGet && body ? \`\${API}/\${path}?\${new URLSearchParams(body)}\` : \`\${API}/\${path}\`;
  const r = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Token': token || '' },
    ...(isGet ? {} : { body: JSON.stringify(body || {}) })
  });
  const d = await r.json();
  if (!d.ok) throw new Error(d.error || 'Error');
  return d;
}

// ── Helpers ───────────────────────────────────────────────
const inits   = u => u.slice(0,2).toUpperCase();
const escH    = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\n/g,'<br>');
const fmtTime = e => new Date(e*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const fmtDate = e => new Date(e*1000).toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});

function showErr(id, msg, inp) {
  const el = document.getElementById(id);
  el.innerHTML = '⚠ ' + msg; el.classList.add('show');
  if (inp) document.getElementById(inp).classList.add('bad');
}
function clearErr(id, inp) {
  document.getElementById(id).classList.remove('show');
  if (inp) { document.getElementById(inp).classList.remove('bad','good'); }
}
function setBtn(id, loading, label) {
  const b = document.getElementById(id);
  b.disabled = loading;
  b.innerHTML = loading ? '<span style="opacity:.5;letter-spacing:3px">···</span>' : label;
}

// ── Password eye toggle ───────────────────────────────────
function toggleEye(inpId, btn) {
  const inp = document.getElementById(inpId);
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
}

// ── Password strength ─────────────────────────────────────
function valPw(inpId, fillId, lblId, reqsId) {
  const p    = document.getElementById(inpId).value;
  const fill = document.getElementById(fillId);
  const lbl  = document.getElementById(lblId);
  const conf = inpId === 'reg-p' ? document.getElementById('reg-c').value : null;

  const hasLen   = p.length >= 8;
  const hasUpper = /[A-Z]/.test(p);
  const hasNum   = /[0-9]/.test(p);
  const matches  = conf !== null ? (p === conf && conf.length > 0) : true;

  // Checklist
  const setReq = (id, ok) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('ok', ok);
    el.querySelector('.ic').textContent = ok ? '✓' : '○';
  };
  setReq(reqsId === 'reg-reqs' ? 'req-len'   : 'pwreq-len',  hasLen);
  setReq(reqsId === 'reg-reqs' ? 'req-up'    : 'pwreq-up',   hasUpper);
  setReq(reqsId === 'reg-reqs' ? 'req-num'   : 'pwreq-num',  hasNum);
  if (reqsId === 'reg-reqs') setReq('req-match', matches);

  // Strength bar
  const score = [hasLen, hasUpper, hasNum, p.length >= 12, /[^a-zA-Z0-9]/.test(p)].filter(Boolean).length;
  const levels = [
    { w:'0%',   bg:'transparent', t:'' },
    { w:'20%',  bg:'var(--rd)',   t:'Very weak' },
    { w:'45%',  bg:'var(--yw)',   t:'Weak' },
    { w:'65%',  bg:'var(--yw)',   t:'Fair' },
    { w:'85%',  bg:'var(--gr)',   t:'Strong' },
    { w:'100%', bg:'var(--ac)',   t:'Very strong' },
  ];
  const lvl = p.length === 0 ? levels[0] : levels[Math.min(score, 5)];
  fill.style.width = lvl.w; fill.style.background = lvl.bg;
  lbl.textContent = lvl.t;
  lbl.style.color = lvl.bg === 'transparent' ? 'var(--mu)' : lvl.bg;
}

// ── Tabs ──────────────────────────────────────────────────
function switchTab(t) {
  document.getElementById('form-li').style.display  = t==='li'  ? 'block':'none';
  document.getElementById('form-reg').style.display = t==='reg' ? 'block':'none';
  document.getElementById('tab-li').classList.toggle('on',  t==='li');
  document.getElementById('tab-reg').classList.toggle('on', t==='reg');
}

// ── Register ──────────────────────────────────────────────
function valReg() {
  const u = document.getElementById('reg-u').value.trim();
  if (u && !/^[a-z0-9_]{3,20}$/.test(u)) showErr('reg-uerr','3–20 chars: lowercase, numbers, _','reg-u');
  else clearErr('reg-uerr','reg-u');
  valPw('reg-p','reg-sfill','reg-slbl','reg-reqs');
}

async function doRegister() {
  const u = document.getElementById('reg-u').value.trim().toLowerCase();
  const p = document.getElementById('reg-p').value;
  const c = document.getElementById('reg-c').value;
  ['reg-uerr','reg-perr','reg-cerr'].forEach(id => document.getElementById(id).classList.remove('show'));
  if (!u)                              { showErr('reg-uerr','Username required','reg-u'); return; }
  if (!/^[a-z0-9_]{3,20}$/.test(u))   { showErr('reg-uerr','3–20 chars: lowercase, numbers, _','reg-u'); return; }
  if (p.length < 8)                    { showErr('reg-perr','At least 8 characters required','reg-p'); return; }
  if (!/[A-Z]/.test(p))               { showErr('reg-perr','Needs at least one uppercase letter','reg-p'); return; }
  if (!/[0-9]/.test(p))               { showErr('reg-perr','Needs at least one number','reg-p'); return; }
  if (p !== c)                         { showErr('reg-cerr','Passwords do not match','reg-c'); return; }
  setBtn('reg-btn', true);
  try {
    const d = await api('register', { username: u, password: p });
    startSession(d.token, d.username, d.color);
  } catch(e) { showErr('reg-uerr', e.message, 'reg-u'); }
  finally { setBtn('reg-btn', false, 'Create Account →'); }
}

// ── Login ─────────────────────────────────────────────────
async function doLogin() {
  const u = document.getElementById('li-u').value.trim().toLowerCase();
  const p = document.getElementById('li-p').value;
  document.getElementById('li-err').classList.remove('show');
  if (!u || !p) { showErr('li-err','Username and password required','li-u'); return; }
  setBtn('li-btn', true);
  try {
    const d = await api('login', { username: u, password: p });
    startSession(d.token, d.username, d.color);
  } catch(e) { showErr('li-err', e.message, 'li-u'); }
  finally { setBtn('li-btn', false, 'Sign In →'); }
}

function startSession(tok, username, color) {
  token = tok; me = username; myColor = color;
  sessionStorage.setItem('fc_tok', tok);
  sessionStorage.setItem('fc_me',  username);
  sessionStorage.setItem('fc_col', color);
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  const av = document.getElementById('sbav');
  av.textContent = inits(me); av.style.background = myColor+'33'; av.style.color = myColor;
  document.getElementById('sbname').textContent = me;
  loadUsers();
  hbT = setInterval(() => api('ping').catch(()=>{}), 10000);
  setInterval(loadUsers, 8000);
}

function doLogout() {
  clearInterval(hbT); clearInterval(pollT);
  token = me = null; sessionStorage.clear(); peer = null;
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('panel').style.display = 'none';
  document.getElementById('empty').style.display = 'flex';
  document.getElementById('li-u').value = '';
  document.getElementById('li-p').value = '';
}

// ── Users ─────────────────────────────────────────────────
async function loadUsers() {
  try {
    const d = await api('users', null, 'GET');
    users = d.users;
    document.getElementById('online-n').textContent = users.filter(u=>u.online).length;
    renderSidebar();
  } catch(e) {}
}

function renderSidebar() {
  const list = document.getElementById('chatlist');
  list.innerHTML = '';
  users.filter(u=>u.username!==me).sort((a,b)=>a.username.localeCompare(b.username)).forEach(u => {
    const el = document.createElement('div');
    el.className = 'ci' + (peer===u.username?' on':'');
    el.dataset.peer = u.username;
    el.innerHTML = \`
      <div class="av" style="background:\${u.color}33;color:\${u.color}">
        \${inits(u.username)}
        <span class="odot" style="background:\${u.online?'var(--gr)':'var(--bd)'}"></span>
      </div>
      <div class="ciinfo">
        <div class="ciname">\${escH(u.username)}</div>
        <div class="ciprev">\${u.online?'// online':'// offline'}</div>
      </div>\`;
    el.onclick = () => openChat(u.username, false);
    list.appendChild(el);
  });
  // AI
  const ai = document.createElement('div');
  ai.className = 'ci' + (peer==='__ai__'?' on':'');
  ai.dataset.peer = '__ai__';
  ai.innerHTML = \`
    <div class="av" style="background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff;font-size:16px">
      ✦<span class="odot" style="background:\${apiKey?'var(--gr)':'var(--bd)'}"></span>
    </div>
    <div class="ciinfo">
      <div class="ciname">Claude AI</div>
      <div class="ciprev">\${apiKey?'// connected':'// needs API key'}</div>
    </div>\`;
  ai.onclick = () => openChat('__ai__', true);
  list.appendChild(ai);
}

// ── Chat ──────────────────────────────────────────────────
function openChat(p, isAI) {
  peer = p; clearInterval(pollT); lastId = 0; aiHist = [];
  document.querySelectorAll('.ci').forEach(e=>e.classList.remove('on'));
  document.querySelector(\`.ci[data-peer="\${p}"]\`)?.classList.add('on');
  document.getElementById('empty').style.display = 'none';
  document.getElementById('panel').style.display = 'flex';

  const av = document.getElementById('panav');
  const sd = document.getElementById('psdot');
  if (isAI) {
    av.style.background = 'linear-gradient(135deg,var(--ac),var(--ac2))';
    av.style.color = '#fff'; av.textContent = '✦';
    document.getElementById('panname').textContent = 'Claude AI';
    document.getElementById('panst').textContent = apiKey ? 'AI · connected' : 'AI · needs API key';
    sd.style.background = apiKey ? 'var(--gr)' : 'var(--mu)';
    document.getElementById('aibanner').classList.toggle('hidden', !!apiKey);
  } else {
    const u = users.find(x=>x.username===p);
    const c = u?.color || '#6c63ff';
    av.style.background = c+'33'; av.style.color = c; av.textContent = inits(p);
    document.getElementById('panname').textContent = p;
    document.getElementById('panst').textContent = u?.online ? 'online' : 'offline';
    sd.style.background = u?.online ? 'var(--gr)' : 'var(--mu)';
    document.getElementById('aibanner').classList.add('hidden');
  }
  document.getElementById('msgs').innerHTML = '';
  if (!isAI) { fetchMsgs(); pollT = setInterval(fetchMsgs, 2000); }
  document.getElementById('msginp').focus();
}

async function fetchMsgs() {
  if (!peer || peer === '__ai__') return;
  try {
    const d = await api('messages', { peer, since: lastId }, 'GET');
    if (d.messages.length) {
      d.messages.forEach(m => addBubble(m));
      lastId = d.messages[d.messages.length-1].id;
    }
  } catch(e) {}
}

function addBubble(m, isAI=false) {
  const box    = document.getElementById('msgs');
  const isMine = (m.sender||m.from) === me;
  const sender = m.sender || m.from;
  const u      = users.find(x=>x.username===sender);
  const c      = isAI ? null : (u?.color || '#6c63ff');
  const epoch  = m.created_at || Math.floor(Date.now()/1000);

  // Date divider
  const dl = fmtDate(epoch);
  const lastDiv = box.querySelector('.datediv:last-of-type');
  if (!lastDiv || lastDiv.dataset.date !== dl) {
    const dv = document.createElement('div');
    dv.className = 'datediv fi'; dv.dataset.date = dl;
    dv.innerHTML = \`<span>\${dl}</span>\`; box.appendChild(dv);
  }

  const div = document.createElement('div');
  div.className = 'msg fi' + (isMine ? ' me' : '');
  const avSt = isAI
    ? 'background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff'
    : \`background:\${c}33;color:\${c}\`;
  div.innerHTML = \`
    <div class="mav" style="\${avSt}">\${isAI?'✦':inits(sender)}</div>
    <div class="mcont">
      <div class="mname">\${isAI?'Claude AI':escH(sender)}</div>
      <div class="mbub\${isAI?' aibub':''}">\${escH(m.text)}</div>
      <div class="mtime">\${fmtTime(epoch)}</div>
    </div>\`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function showTyping() {
  const box = document.getElementById('msgs');
  const t = document.createElement('div');
  t.id = 'typing'; t.className = 'msg fi';
  t.innerHTML = \`
    <div class="mav" style="background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff">✦</div>
    <div class="mcont">
      <div class="mname">Claude AI</div>
      <div class="typingbub"><div class="td"></div><div class="td"></div><div class="td"></div></div>
    </div>\`;
  box.appendChild(t); box.scrollTop = box.scrollHeight;
}

function onKey(e) { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();} }
function resize(el){ el.style.height='auto'; el.style.height=Math.min(el.scrollHeight,120)+'px'; }

async function sendMsg() {
  const inp  = document.getElementById('msginp');
  const text = inp.value.trim();
  if (!text || !peer) return;
  inp.value = ''; inp.style.height = 'auto';
  if (peer === '__ai__') { await sendAI(text); return; }
  addBubble({ sender: me, text, created_at: Math.floor(Date.now()/1000) });
  try { await api('send', { peer, text }); } catch(e) {}
}

async function sendAI(text) {
  if (!apiKey) { openKeyModal(); return; }
  aiHist.push({ role: 'user', content: text });
  addBubble({ from: me, text, created_at: Math.floor(Date.now()/1000) });
  showTyping();
  try {
    const d = await api('ai', { api_key: apiKey, history: aiHist });
    document.getElementById('typing')?.remove();
    aiHist.push({ role: 'assistant', content: d.reply });
    addBubble({ sender: '__ai__', text: d.reply, created_at: Math.floor(Date.now()/1000) }, true);
  } catch(e) {
    document.getElementById('typing')?.remove();
    addBubble({ sender: '__ai__', text: '⚠️ ' + e.message, created_at: Math.floor(Date.now()/1000) }, true);
  }
}

// ── Change Password ───────────────────────────────────────
function openPwModal() {
  document.getElementById('pw-modal').classList.remove('hidden');
  ['pw-cur','pw-new','pw-conf'].forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('pw-sfill').style.width = '0%';
  document.getElementById('pw-slbl').textContent = '';
  document.getElementById('pw-ok').classList.remove('show');
  ['pw-err','pw-nerr','pw-cerr'].forEach(id => document.getElementById(id).classList.remove('show'));
  document.getElementById('pw-reqs').classList.remove('show');
  setTimeout(() => document.getElementById('pw-cur').focus(), 100);
}
function closePwModal() { document.getElementById('pw-modal').classList.add('hidden'); }

async function savePw() {
  const cur  = document.getElementById('pw-cur').value;
  const nw   = document.getElementById('pw-new').value;
  const conf = document.getElementById('pw-conf').value;
  ['pw-err','pw-nerr','pw-cerr'].forEach(id => document.getElementById(id).classList.remove('show'));
  if (!cur)            { showErr('pw-err','Current password required','pw-cur'); return; }
  if (nw.length < 8)   { showErr('pw-nerr','At least 8 characters required','pw-new'); return; }
  if (!/[A-Z]/.test(nw)){ showErr('pw-nerr','Needs at least one uppercase letter','pw-new'); return; }
  if (!/[0-9]/.test(nw)){ showErr('pw-nerr','Needs at least one number','pw-new'); return; }
  if (nw === cur)      { showErr('pw-nerr','New password must differ from current','pw-new'); return; }
  if (nw !== conf)     { showErr('pw-cerr','Passwords do not match','pw-conf'); return; }
  try {
    await api('change_password', { current: cur, newpw: nw });
    document.getElementById('pw-ok').classList.add('show');
    setTimeout(closePwModal, 1600);
  } catch(e) { showErr('pw-err', e.message, 'pw-cur'); }
}

// ── API Key ───────────────────────────────────────────────
function openKeyModal() {
  document.getElementById('key-modal').classList.remove('hidden');
  document.getElementById('key-err').classList.remove('show');
  document.getElementById('key-inp').value = apiKey || '';
  setTimeout(() => document.getElementById('key-inp').focus(), 100);
}
function closeKeyModal() { document.getElementById('key-modal').classList.add('hidden'); }
function saveKey() {
  const k = document.getElementById('key-inp').value.trim();
  if (!k.startsWith('sk-ant-')) { showErr('key-err','Key must start with sk-ant-','key-inp'); return; }
  apiKey = k; sessionStorage.setItem('fc_akey', k);
  closeKeyModal(); renderSidebar();
  if (peer === '__ai__') {
    document.getElementById('aibanner').classList.add('hidden');
    document.getElementById('panst').textContent = 'AI · connected';
    document.getElementById('psdot').style.background = 'var(--gr)';
    aiHist = [];
    addBubble({ sender:'__ai__', text:"API key connected! I'm Claude — ask me anything ✦", created_at: Math.floor(Date.now()/1000) }, true);
  }
}

// ── Auto restore ──────────────────────────────────────────
if (token && me) {
  api('ping').then(() => startSession(token, me, myColor)).catch(() => { sessionStorage.clear(); });
}
</script>
</body>
</html>`;

// Serve HTML at root
app.get('/', (_, res) => res.send(HTML));

app.listen(PORT, () => {
  console.log(`\n✦ Flux Chat is running!`);
  console.log(`  Local:   http://localhost:${PORT}`);
  console.log(`\n  In Codespaces: go to the Ports tab, find port ${PORT},`);
  console.log(`  right-click → Port Visibility → Public, then click 🌐\n`);
});
