/**
 * Flux Chat — server.js (single file)
 *
 * SETUP IN GITHUB CODESPACES:
 *   1. Upload this file to your repo
 *   2. Open terminal and run:
 *        npm install express better-sqlite3
 *        node server.js
 *   3. Ports tab → port 3000 → right-click → Port Visibility → Public
 *   4. Click 🌐 to open — share the URL with friends!
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
  CREATE TABLE IF NOT EXISTS friends (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user  TEXT NOT NULL,
    to_user    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER DEFAULT (unixepoch()),
    UNIQUE(from_user, to_user)
  );
`);

// ── Helpers ───────────────────────────────────────────────
const COLORS = ['#6c63ff','#ff5f87','#3be09a','#ffc94a','#38bdf8','#fb923c','#a78bfa','#34d399'];
function colorFor(u) {
  let h = 0;
  for (let i = 0; i < u.length; i++) h = u.charCodeAt(i) + ((h << 5) - h);
  return COLORS[Math.abs(h) % COLORS.length];
}
function cid(a, b)  { return [a, b].sort().join('::'); }
function mkToken()  { return crypto.randomBytes(24).toString('hex'); }
function hash(p)    { return crypto.createHash('sha256').update('fluxsalt::' + p).digest('hex'); }
function ok(res, d) { res.json({ ok: true, ...d }); }
function fail(res, msg, code = 400) { res.status(code).json({ ok: false, error: msg }); }

function auth(req, res) {
  const t = req.headers['x-token'] || '';
  if (!t) { fail(res, 'Not authenticated', 401); return null; }
  const row = db.prepare('SELECT username FROM sessions WHERE token=? AND last_seen > unixepoch()-86400').get(t);
  if (!row) { fail(res, 'Session expired', 401); return null; }
  db.prepare('UPDATE sessions SET last_seen=unixepoch() WHERE token=?').run(t);
  return row.username;
}

// ── Auth ──────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const u = (req.body.username || '').trim().toLowerCase();
  const p =  req.body.password || '';
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return fail(res, 'Username: 3–20 chars, lowercase/numbers/_');
  if (p.length < 8)                  return fail(res, 'Password must be at least 8 characters');
  if (!/[A-Z]/.test(p))             return fail(res, 'Password needs at least one uppercase letter');
  if (!/[0-9]/.test(p))             return fail(res, 'Password needs at least one number');
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(u)) return fail(res, 'Username already taken');
  db.prepare('INSERT INTO users(username,password,color) VALUES(?,?,?)').run(u, hash(p), colorFor(u));
  const t = mkToken();
  db.prepare('INSERT INTO sessions(token,username) VALUES(?,?)').run(t, u);
  ok(res, { token: t, username: u, color: colorFor(u) });
});

app.post('/api/login', (req, res) => {
  const u = (req.body.username || '').trim().toLowerCase();
  const p =  req.body.password || '';
  if (!u || !p) return fail(res, 'Username and password required');
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if (!row || row.password !== hash(p)) return fail(res, 'Incorrect username or password');
  const t = mkToken();
  db.prepare('INSERT INTO sessions(token,username) VALUES(?,?)').run(t, u);
  ok(res, { token: t, username: u, color: row.color });
});

app.post('/api/change_password', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { current, newpw } = req.body;
  if (!current)               return fail(res, 'Current password required');
  if ((newpw||'').length < 8) return fail(res, 'New password must be at least 8 characters');
  if (!/[A-Z]/.test(newpw))   return fail(res, 'New password needs at least one uppercase letter');
  if (!/[0-9]/.test(newpw))   return fail(res, 'New password needs at least one number');
  const row = db.prepare('SELECT password FROM users WHERE username=?').get(me);
  if (row.password !== hash(current)) return fail(res, 'Current password is incorrect');
  if (hash(newpw) === row.password)   return fail(res, 'New password must differ from current');
  db.prepare('UPDATE users SET password=? WHERE username=?').run(hash(newpw), me);
  ok(res, {});
});

app.post('/api/ping', (req, res) => {
  const me = auth(req, res); if (!me) return;
  ok(res, {});
});

// ── Friends ───────────────────────────────────────────────
app.post('/api/friends/request', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const to = (req.body.to || '').trim().toLowerCase();
  if (!to || to === me) return fail(res, 'Invalid username');
  if (!db.prepare('SELECT 1 FROM users WHERE username=?').get(to)) return fail(res, 'User not found');
  const existing = db.prepare(
    'SELECT * FROM friends WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)'
  ).get(me, to, to, me);
  if (existing) {
    if (existing.status === 'accepted') return fail(res, 'Already friends');
    return fail(res, 'Request already pending');
  }
  db.prepare('INSERT INTO friends(from_user,to_user,status) VALUES(?,?,?)').run(me, to, 'pending');
  ok(res, {});
});

app.post('/api/friends/accept', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const from = (req.body.from || '').trim().toLowerCase();
  const row = db.prepare('SELECT * FROM friends WHERE from_user=? AND to_user=? AND status=?').get(from, me, 'pending');
  if (!row) return fail(res, 'No pending request found');
  db.prepare('UPDATE friends SET status=? WHERE from_user=? AND to_user=?').run('accepted', from, me);
  ok(res, {});
});

app.post('/api/friends/remove', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const other = (req.body.username || '').trim().toLowerCase();
  db.prepare(
    'DELETE FROM friends WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)'
  ).run(me, other, other, me);
  ok(res, {});
});

app.get('/api/friends', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const friends = db.prepare(`
    SELECT u.username, u.color,
      CASE WHEN s.last_seen > unixepoch()-20 THEN 1 ELSE 0 END as online
    FROM friends f
    JOIN users u ON (CASE WHEN f.from_user=? THEN f.to_user ELSE f.from_user END = u.username)
    LEFT JOIN sessions s ON s.username = u.username
    WHERE (f.from_user=? OR f.to_user=?) AND f.status='accepted'
    GROUP BY u.username
  `).all(me, me, me);
  const incoming = db.prepare(`
    SELECT u.username, u.color FROM friends f
    JOIN users u ON f.from_user = u.username
    WHERE f.to_user=? AND f.status='pending'
  `).all(me);
  const outgoing = db.prepare(`
    SELECT u.username, u.color FROM friends f
    JOIN users u ON f.to_user = u.username
    WHERE f.from_user=? AND f.status='pending'
  `).all(me);
  ok(res, { friends, incoming, outgoing });
});

app.get('/api/users/search', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const q = (req.query.q || '').trim().toLowerCase();
  if (q.length < 2) return ok(res, { users: [] });
  const rows = db.prepare(
    "SELECT username, color FROM users WHERE username LIKE ? AND username != ? LIMIT 10"
  ).all('%' + q + '%', me);
  ok(res, { users: rows });
});

// ── Messages ──────────────────────────────────────────────
app.post('/api/send', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const peer = (req.body.peer || '').toLowerCase().trim();
  const text = (req.body.text || '').trim();
  if (!peer || !text)     return fail(res, 'Missing peer or text');
  if (text.length > 4000) return fail(res, 'Message too long');
  const areFriends = db.prepare(
    "SELECT 1 FROM friends WHERE ((from_user=? AND to_user=?) OR (from_user=? AND to_user=?)) AND status='accepted'"
  ).get(me, peer, peer, me);
  if (!areFriends) return fail(res, 'You must be friends to message this person');
  const r = db.prepare('INSERT INTO messages(convo,sender,text) VALUES(?,?,?)').run(cid(me, peer), me, text);
  ok(res, { id: r.lastInsertRowid });
});

app.get('/api/messages', (req, res) => {
  const me    = auth(req, res); if (!me) return;
  const peer  = (req.query.peer  || '').toLowerCase().trim();
  const since = parseInt(req.query.since || '0');
  if (!peer) return fail(res, 'Missing peer');
  const msgs = db.prepare(
    'SELECT id,sender,text,created_at FROM messages WHERE convo=? AND id>? ORDER BY id ASC LIMIT 100'
  ).all(cid(me, peer), since);
  ok(res, { messages: msgs });
});

// ── Gemini AI ─────────────────────────────────────────────
app.post('/api/ai', (req, res) => {
  const me = auth(req, res); if (!me) return;
  const { api_key, history } = req.body;
  if (!api_key || !history?.length) return fail(res, 'Missing api_key or history');
  const contents = history.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));
  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: 'You are a friendly AI assistant inside Flux Chat. Be conversational and concise.' }] },
    contents,
    generationConfig: { maxOutputTokens: 1024 }
  });
  const r = https.request({
    hostname: 'generativelanguage.googleapis.com',
    path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${api_key}`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
  }, resp => {
    let d = '';
    resp.on('data', c => d += c);
    resp.on('end', () => {
      try {
        const j = JSON.parse(d);
        if (resp.statusCode !== 200) return fail(res, j.error?.message || 'Gemini API error', resp.statusCode);
        const text = j.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) return fail(res, 'No response from Gemini');
        ok(res, { reply: text });
      } catch { fail(res, 'Bad response from Gemini'); }
    });
  });
  r.on('error', e => fail(res, e.message));
  r.write(payload); r.end();
});

// ── Frontend HTML ─────────────────────────────────────────
app.get('/', (_, res) => res.send(`<!DOCTYPE html>
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
.card{background:var(--s1);border:1px solid var(--bd);border-radius:24px;padding:46px 44px;width:460px;position:relative;overflow:hidden;animation:rise .35s cubic-bezier(.16,1,.3,1);}
.card::before{content:'';position:absolute;top:-100px;right:-100px;width:260px;height:260px;background:radial-gradient(circle,rgba(108,99,255,.18),transparent 70%);pointer-events:none;}
.card::after{content:'';position:absolute;bottom:-80px;left:-70px;width:200px;height:200px;background:radial-gradient(circle,rgba(255,95,135,.1),transparent 70%);pointer-events:none;}
.logo{font-size:32px;font-weight:800;letter-spacing:-2px;margin-bottom:4px;}.logo b{color:var(--ac);}
.tagline{color:var(--mu);font-size:12px;font-family:'DM Mono',monospace;margin-bottom:32px;}
.tabs{display:flex;background:var(--s2);border-radius:12px;padding:4px;margin-bottom:28px;gap:4px;}
.tab{flex:1;padding:10px;border:none;border-radius:9px;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;cursor:pointer;background:transparent;color:var(--mu);transition:all .2s;}
.tab.on{background:var(--s3);color:var(--tx);box-shadow:0 2px 8px rgba(0,0,0,.4);}
.fg{margin-bottom:16px;position:relative;}
.fg label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--mu);margin-bottom:8px;font-family:'DM Mono',monospace;}
.fg input{width:100%;background:var(--s2);border:1.5px solid var(--bd);border-radius:12px;padding:13px 46px 13px 16px;color:var(--tx);font-family:'DM Mono',monospace;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s;}
.fg input:focus{border-color:var(--ac);box-shadow:0 0 0 4px rgba(108,99,255,.1);}
.fg input.bad{border-color:var(--rd)!important;box-shadow:0 0 0 3px rgba(255,95,109,.1)!important;}
.eyebtn{position:absolute;right:14px;bottom:14px;background:none;border:none;color:var(--mu);cursor:pointer;font-size:16px;padding:0;line-height:1;transition:color .2s;}
.eyebtn:hover{color:var(--tx);}
.pwbar{height:4px;background:var(--bd);border-radius:4px;overflow:hidden;margin-top:8px;}
.pwfill{height:100%;border-radius:4px;width:0%;transition:width .4s,background .4s;}
.pwlabel{font-size:10px;font-family:'DM Mono',monospace;color:var(--mu);margin-top:5px;min-height:15px;}
.pwreqs{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-top:8px;display:none;}
.pwreqs.show{display:block;}
.pwreq{display:flex;align-items:center;gap:8px;font-size:11px;font-family:'DM Mono',monospace;color:var(--mu);margin-bottom:6px;transition:color .2s;}
.pwreq:last-child{margin-bottom:0;}.pwreq.ok{color:var(--gr);}
.pwreq .ic{width:14px;text-align:center;font-size:12px;}
.errmsg{color:var(--rd);font-size:11px;font-family:'DM Mono',monospace;margin-top:6px;display:none;align-items:center;gap:5px;}
.errmsg.show{display:flex;}
.btn{width:100%;border:none;border-radius:12px;padding:14px;font-family:'Syne',sans-serif;font-size:15px;font-weight:700;cursor:pointer;transition:all .2s;letter-spacing:.3px;margin-top:6px;display:flex;align-items:center;justify-content:center;gap:6px;}
.btn-ac{background:var(--ac);color:#fff;}.btn-ac:hover{background:#8580ff;transform:translateY(-1px);box-shadow:0 6px 24px rgba(108,99,255,.4);}
.btn-ac:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;}
.btn-gh{background:var(--s2);color:var(--tx);border:1.5px solid var(--bd);}.btn-gh:hover{border-color:var(--mu);}
.btn-sm{width:auto;padding:7px 14px;font-size:12px;margin-top:0;border-radius:8px;}
.btn-gr{background:rgba(59,224,154,.1);color:var(--gr);border:1px solid rgba(59,224,154,.3);}.btn-gr:hover{background:rgba(59,224,154,.2);}
.btn-rd{background:rgba(255,95,109,.1);color:var(--rd);border:1px solid rgba(255,95,109,.3);}.btn-rd:hover{background:rgba(255,95,109,.2);}
.hint{text-align:center;margin-top:16px;font-size:12px;font-family:'DM Mono',monospace;color:var(--mu);}
.hint a{color:var(--ac);cursor:pointer;text-decoration:underline;}
#app{display:flex;width:100%;height:100vh;}#app.hidden{display:none;}
.sidebar{width:280px;background:var(--s1);border-right:1px solid var(--bd);display:flex;flex-direction:column;flex-shrink:0;}
.sbhead{padding:18px 16px 14px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;}
.apptitle{font-size:18px;font-weight:800;letter-spacing:-.5px;}.apptitle b{color:var(--ac);}
.opill{display:flex;align-items:center;gap:5px;background:rgba(59,224,154,.08);border:1px solid rgba(59,224,154,.2);border-radius:20px;padding:3px 10px;font-size:11px;font-family:'DM Mono',monospace;color:var(--gr);}
.opill .dot{width:5px;height:5px;border-radius:50%;background:var(--gr);animation:pulse 2s infinite;}
.sbtabs{display:flex;padding:8px 8px 0;gap:4px;}
.sbtab{flex:1;padding:8px;border:none;border-radius:9px;font-family:'Syne',sans-serif;font-size:12px;font-weight:700;cursor:pointer;background:transparent;color:var(--mu);transition:all .2s;position:relative;}
.sbtab.on{background:var(--s2);color:var(--tx);}
.sbtab .badge{position:absolute;top:4px;right:4px;background:var(--rd);color:#fff;border-radius:10px;padding:1px 5px;font-size:9px;font-family:'DM Mono',monospace;}
.sbcontent{flex:1;overflow-y:auto;padding:8px;}
.hidden{display:none!important;}
.ci{display:flex;align-items:center;gap:10px;padding:10px;border-radius:12px;cursor:pointer;transition:background .15s;margin-bottom:2px;}
.ci:hover{background:var(--s2);}.ci.on{background:rgba(108,99,255,.12);}
.av{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;position:relative;}
.av .odot{position:absolute;bottom:-1px;right:-1px;width:11px;height:11px;border-radius:50%;border:2px solid var(--s1);}
.ciinfo{flex:1;min-width:0;}.ciname{font-size:13px;font-weight:700;}
.ciprev{font-size:11px;color:var(--mu);font-family:'DM Mono',monospace;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}
.freq{background:var(--s2);border:1px solid var(--bd);border-radius:12px;padding:12px;margin-bottom:8px;}
.freq-top{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
.freq-name{font-size:13px;font-weight:700;}.freq-sub{font-size:11px;color:var(--mu);font-family:'DM Mono',monospace;}
.freq-btns{display:flex;gap:6px;}
.search-box{padding:4px 0 8px;}
.search-inp{width:100%;background:var(--s2);border:1.5px solid var(--bd);border-radius:10px;padding:10px 14px;color:var(--tx);font-family:'DM Mono',monospace;font-size:13px;outline:none;transition:border-color .2s;}
.search-inp:focus{border-color:var(--ac);}.search-inp::placeholder{color:var(--mu);}
.sr{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:10px;margin-bottom:2px;}
.sr-info{flex:1;}.sr-name{font-size:13px;font-weight:700;}
.sr-sent{font-size:11px;color:var(--mu);font-family:'DM Mono',monospace;}
.seclbl{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--mu);font-family:'DM Mono',monospace;padding:10px 4px 6px;}
.empty-state{text-align:center;padding:30px 16px;color:var(--mu);font-size:12px;font-family:'DM Mono',monospace;line-height:1.8;}
.sbfoot{padding:12px 16px;border-top:1px solid var(--bd);display:flex;align-items:center;gap:10px;}
.sbav{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0;}
.sbinfo{flex:1;min-width:0;}.sbname{font-size:13px;font-weight:700;}.sbsub{font-size:10px;color:var(--mu);font-family:'DM Mono',monospace;}
.icobtn{background:none;border:none;color:var(--mu);cursor:pointer;font-size:16px;padding:5px;border-radius:8px;transition:all .2s;line-height:1;}
.icobtn:hover{color:var(--tx);background:var(--s2);}
.chatarea{flex:1;display:flex;flex-direction:column;min-width:0;}
.empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:var(--mu);}
.empty .ico{font-size:56px;opacity:.2;}.empty h3{font-size:18px;color:var(--tx);font-weight:700;}
.empty p{font-size:12px;font-family:'DM Mono',monospace;text-align:center;line-height:1.7;}
#panel{display:none;flex-direction:column;height:100%;}
.panhead{padding:14px 22px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:12px;background:var(--s1);}
.panhav{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;}
.panname{font-size:15px;font-weight:700;}.panstatus{font-size:11px;font-family:'DM Mono',monospace;display:flex;align-items:center;gap:5px;margin-top:2px;}
.psdot{width:6px;height:6px;border-radius:50%;}
.aibanner{background:linear-gradient(90deg,rgba(108,99,255,.08),rgba(255,95,135,.06));border-bottom:1px solid rgba(108,99,255,.15);padding:9px 22px;font-size:12px;font-family:'DM Mono',monospace;color:var(--mu);display:flex;align-items:center;justify-content:space-between;}
.aibanner.hidden{display:none!important;}
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
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;z-index:200;backdrop-filter:blur(8px);}
.overlay.hidden{display:none!important;}
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
    <div id="form-li">
      <div class="fg"><label>Username</label>
        <input id="li-u" type="text" placeholder="your_username" autocomplete="username" onkeydown="if(event.key==='Enter')doLogin()"/>
        <div class="errmsg" id="li-err"></div>
      </div>
      <div class="fg"><label>Password</label>
        <input id="li-p" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"/>
        <button class="eyebtn" type="button" onclick="toggleEye('li-p',this)" tabindex="-1">👁</button>
      </div>
      <button class="btn btn-ac" id="li-btn" onclick="doLogin()">Sign In →</button>
      <div class="hint">No account? <a onclick="switchTab('reg')">Create one free</a></div>
    </div>
    <div id="form-reg" style="display:none">
      <div class="fg"><label>Username</label>
        <input id="reg-u" type="text" placeholder="pick_a_username" autocomplete="username" oninput="valReg()" onkeydown="if(event.key==='Enter')doRegister()"/>
        <div class="errmsg" id="reg-uerr"></div>
      </div>
      <div class="fg"><label>Password</label>
        <input id="reg-p" type="password" placeholder="min. 8 chars, 1 uppercase, 1 number" autocomplete="new-password"
          oninput="valPw('reg-p','reg-c','reg-sfill','reg-slbl','reg-reqs')"
          onfocus="document.getElementById('reg-reqs').classList.add('show')"
          onkeydown="if(event.key==='Enter')doRegister()"/>
        <button class="eyebtn" type="button" onclick="toggleEye('reg-p',this)" tabindex="-1">👁</button>
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
      <div class="fg"><label>Confirm Password</label>
        <input id="reg-c" type="password" placeholder="repeat password" autocomplete="new-password"
          oninput="valPw('reg-p','reg-c','reg-sfill','reg-slbl','reg-reqs')"
          onkeydown="if(event.key==='Enter')doRegister()"/>
        <button class="eyebtn" type="button" onclick="toggleEye('reg-c',this)" tabindex="-1">👁</button>
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
    <div class="fg"><label>Current Password</label>
      <input id="pw-cur" type="password" placeholder="••••••••"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-cur',this)" tabindex="-1">👁</button>
      <div class="errmsg" id="pw-err"></div>
    </div>
    <div class="fg"><label>New Password</label>
      <input id="pw-new" type="password" placeholder="min. 8 chars, 1 uppercase, 1 number"
        oninput="valPw('pw-new','pw-conf','pw-sfill','pw-slbl','pw-reqs')"
        onfocus="document.getElementById('pw-reqs').classList.add('show')"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-new',this)" tabindex="-1">👁</button>
      <div class="pwbar"><div class="pwfill" id="pw-sfill"></div></div>
      <div class="pwlabel" id="pw-slbl"></div>
      <div class="pwreqs" id="pw-reqs">
        <div class="pwreq" id="pwreq-len"><span class="ic">○</span> At least 8 characters</div>
        <div class="pwreq" id="pwreq-up"><span class="ic">○</span> One uppercase letter (A–Z)</div>
        <div class="pwreq" id="pwreq-num"><span class="ic">○</span> One number (0–9)</div>
        <div class="pwreq" id="pwreq-match"><span class="ic">○</span> Passwords match</div>
      </div>
      <div class="errmsg" id="pw-nerr"></div>
    </div>
    <div class="fg"><label>Confirm New Password</label>
      <input id="pw-conf" type="password" placeholder="repeat new password"
        oninput="valPw('pw-new','pw-conf','pw-sfill','pw-slbl','pw-reqs')"/>
      <button class="eyebtn" type="button" onclick="toggleEye('pw-conf',this)" tabindex="-1">👁</button>
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
    <h3>✦ Connect Gemini AI</h3>
    <p>Get a free API key at <b>aistudio.google.com</b> → "Get API Key".<br>Stored only in your browser session, never on the server.</p>
    <div class="fg"><label>Google Gemini API Key</label>
      <input id="key-inp" type="password" placeholder="AIzaSy…"/>
      <button class="eyebtn" type="button" onclick="toggleEye('key-inp',this)" tabindex="-1">👁</button>
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
    <div class="sbtabs">
      <button class="sbtab on" id="sbtab-chats" onclick="switchSbTab('chats')">Chats</button>
      <button class="sbtab" id="sbtab-friends" onclick="switchSbTab('friends')">Friends<span class="badge hidden" id="req-badge"></span></button>
      <button class="sbtab" id="sbtab-add" onclick="switchSbTab('add')">+ Add</button>
    </div>
    <div class="sbcontent" id="sb-chats"><div id="chatlist"></div></div>
    <div class="sbcontent hidden" id="sb-friends">
      <div id="incoming-section"></div>
      <div id="outgoing-section"></div>
      <div id="friends-list"></div>
    </div>
    <div class="sbcontent hidden" id="sb-add">
      <div class="search-box">
        <input class="search-inp" id="search-inp" type="text" placeholder="Search username…" oninput="searchUsers()"/>
      </div>
      <div id="search-results"></div>
    </div>
    <div class="sbfoot">
      <div class="sbav" id="sbav"></div>
      <div class="sbinfo"><div class="sbname" id="sbname"></div><div class="sbsub">// online</div></div>
      <button class="icobtn" onclick="openPwModal()" title="Change password">⚙</button>
      <button class="icobtn" onclick="doLogout()" title="Sign out" style="color:var(--rd)">↩</button>
    </div>
  </div>

  <div class="chatarea">
    <div class="empty" id="empty">
      <div class="ico">💬</div>
      <h3>No conversation open</h3>
      <p>// add friends first via "+ Add"<br>// then select a chat to start messaging</p>
    </div>
    <div id="panel">
      <div class="panhead">
        <div class="panhav" id="panav"></div>
        <div>
          <div class="panname" id="panname"></div>
          <div class="panstatus"><span class="psdot" id="psdot"></span><span id="panst"></span></div>
        </div>
      </div>
      <div class="aibanner hidden" id="aibanner">
        ✦ Gemini AI — add your Google API key to chat
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
const API='/api';
let token=sessionStorage.getItem('fc_tok')||null,me=sessionStorage.getItem('fc_me')||null,myColor=sessionStorage.getItem('fc_col')||'#6c63ff',apiKey=sessionStorage.getItem('fc_akey')||null;
let activePeer=null,lastId=0,pollT=null,hbT=null,aiHist=[];
let fd={friends:[],incoming:[],outgoing:[]};

async function api(path,body,method='POST'){
  const isGet=method==='GET';
  const url=isGet&&body?\`\${API}/\${path}?\${new URLSearchParams(body)}\`:\`\${API}/\${path}\`;
  const r=await fetch(url,{method,headers:{'Content-Type':'application/json','X-Token':token||''},...(isGet?{}:{body:JSON.stringify(body||{})})});
  const d=await r.json();if(!d.ok)throw new Error(d.error||'Error');return d;
}

const inits=u=>u.slice(0,2).toUpperCase();
const escH=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\n/g,'<br>');
const fmtTime=e=>new Date(e*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const fmtDate=e=>new Date(e*1000).toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});

function showErr(id,msg,inp){const el=document.getElementById(id);el.innerHTML='⚠ '+msg;el.classList.add('show');if(inp)document.getElementById(inp).classList.add('bad');}
function hideErr(id,inp){document.getElementById(id).classList.remove('show');if(inp)document.getElementById(inp).classList.remove('bad','good');}
function setBtn(id,on,lbl){const b=document.getElementById(id);b.disabled=on;b.innerHTML=on?'<span style="opacity:.5;letter-spacing:3px">···</span>':lbl;}
function toggleEye(id,btn){const i=document.getElementById(id);const s=i.type==='password';i.type=s?'text':'password';btn.textContent=s?'🙈':'👁';}

function setStrength(fid,lid,p){
  const f=document.getElementById(fid),l=document.getElementById(lid);
  const sc=[p.length>=8,/[A-Z]/.test(p),/[0-9]/.test(p),p.length>=12,/[^a-zA-Z0-9]/.test(p)].filter(Boolean).length;
  const lv=[{w:'0%',bg:'transparent',t:''},{w:'20%',bg:'var(--rd)',t:'Very weak'},{w:'45%',bg:'var(--yw)',t:'Weak'},{w:'65%',bg:'var(--yw)',t:'Fair'},{w:'85%',bg:'var(--gr)',t:'Strong'},{w:'100%',bg:'var(--ac)',t:'Very strong 🔐'}];
  const lev=p.length===0?lv[0]:lv[Math.min(sc,5)];
  f.style.width=lev.w;f.style.background=lev.bg;l.textContent=lev.t;l.style.color=lev.bg==='transparent'?'var(--mu)':lev.bg;
}
function valPw(pid,cid,fid,lid,rid){
  const p=document.getElementById(pid).value,c=document.getElementById(cid)?.value||'';
  const ch={len:p.length>=8,up:/[A-Z]/.test(p),num:/[0-9]/.test(p),match:p.length>0&&p===c};
  const mp=rid==='reg-reqs'?{len:'req-len',up:'req-up',num:'req-num',match:'req-match'}:{len:'pwreq-len',up:'pwreq-up',num:'pwreq-num',match:'pwreq-match'};
  Object.entries(mp).forEach(([k,id])=>{const el=document.getElementById(id);if(!el)return;el.classList.toggle('ok',ch[k]);el.querySelector('.ic').textContent=ch[k]?'✓':'○';});
  setStrength(fid,lid,p);
}

function switchTab(t){
  document.getElementById('form-li').style.display=t==='li'?'block':'none';
  document.getElementById('form-reg').style.display=t==='reg'?'block':'none';
  document.getElementById('tab-li').classList.toggle('on',t==='li');
  document.getElementById('tab-reg').classList.toggle('on',t==='reg');
}
function switchSbTab(t){
  ['chats','friends','add'].forEach(n=>{
    document.getElementById('sbtab-'+n).classList.toggle('on',n===t);
    document.getElementById('sb-'+n).classList.toggle('hidden',n!==t);
  });
  if(t==='friends')renderFriendsTab();
  if(t==='add'){document.getElementById('search-inp').value='';document.getElementById('search-results').innerHTML='';}
}

function valReg(){
  const u=document.getElementById('reg-u').value.trim();
  if(u&&!/^[a-z0-9_]{3,20}$/.test(u))showErr('reg-uerr','3–20 chars: lowercase, numbers, _','reg-u');
  else hideErr('reg-uerr','reg-u');
  valPw('reg-p','reg-c','reg-sfill','reg-slbl','reg-reqs');
}

async function doRegister(){
  ['reg-uerr','reg-perr','reg-cerr'].forEach(id=>hideErr(id));
  const u=document.getElementById('reg-u').value.trim().toLowerCase(),p=document.getElementById('reg-p').value,c=document.getElementById('reg-c').value;
  if(!u){showErr('reg-uerr','Username is required','reg-u');return;}
  if(!/^[a-z0-9_]{3,20}$/.test(u)){showErr('reg-uerr','3–20 chars: lowercase, numbers, _','reg-u');return;}
  if(p.length<8){showErr('reg-perr','At least 8 characters required','reg-p');return;}
  if(!/[A-Z]/.test(p)){showErr('reg-perr','Needs at least one uppercase letter','reg-p');return;}
  if(!/[0-9]/.test(p)){showErr('reg-perr','Needs at least one number','reg-p');return;}
  if(p!==c){showErr('reg-cerr','Passwords do not match','reg-c');return;}
  setBtn('reg-btn',true);
  try{const d=await api('register',{username:u,password:p});startSession(d.token,d.username,d.color);}
  catch(e){showErr('reg-uerr',e.message,'reg-u');}
  finally{setBtn('reg-btn',false,'Create Account →');}
}

async function doLogin(){
  hideErr('li-err');
  const u=document.getElementById('li-u').value.trim().toLowerCase(),p=document.getElementById('li-p').value;
  if(!u||!p){showErr('li-err','Username and password required','li-u');return;}
  setBtn('li-btn',true);
  try{const d=await api('login',{username:u,password:p});startSession(d.token,d.username,d.color);}
  catch(e){showErr('li-err',e.message,'li-u');}
  finally{setBtn('li-btn',false,'Sign In →');}
}

function startSession(tok,username,color){
  token=tok;me=username;myColor=color;
  sessionStorage.setItem('fc_tok',tok);sessionStorage.setItem('fc_me',username);sessionStorage.setItem('fc_col',color);
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  const av=document.getElementById('sbav');av.textContent=inits(me);av.style.background=myColor+'33';av.style.color=myColor;
  document.getElementById('sbname').textContent=me;
  loadFriends();
  hbT=setInterval(()=>api('ping').catch(()=>{}),10000);
  setInterval(()=>{loadFriends();if(activePeer&&activePeer!=='__ai__')fetchMsgs();},5000);
}

function doLogout(){
  clearInterval(hbT);clearInterval(pollT);token=me=null;sessionStorage.clear();activePeer=null;
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('panel').style.display='none';
  document.getElementById('empty').style.display='flex';
  document.getElementById('li-u').value='';document.getElementById('li-p').value='';
}

async function loadFriends(){
  try{
    const d=await api('friends',null,'GET');fd=d;
    renderChats();
    const n=d.incoming.length,badge=document.getElementById('req-badge');
    badge.textContent=n;badge.classList.toggle('hidden',n===0);
    document.getElementById('online-n').textContent=d.friends.filter(f=>f.online).length;
  }catch(e){}
}

function renderChats(){
  const list=document.getElementById('chatlist');list.innerHTML='';
  if(!fd.friends.length){list.innerHTML='<div class="empty-state">No friends yet.<br>Go to "+ Add" to find people!</div>';return;}
  fd.friends.forEach(u=>{
    const el=document.createElement('div');el.className='ci'+(activePeer===u.username?' on':'');el.dataset.peer=u.username;
    el.innerHTML=\`<div class="av" style="background:\${u.color}33;color:\${u.color}">\${inits(u.username)}<span class="odot" style="background:\${u.online?'var(--gr)':'var(--bd)'}"></span></div>
      <div class="ciinfo"><div class="ciname">\${escH(u.username)}</div><div class="ciprev">\${u.online?'// online':'// offline'}</div></div>\`;
    el.onclick=()=>openChat(u.username,false);list.appendChild(el);
  });
  const ai=document.createElement('div');ai.className='ci'+(activePeer==='__ai__'?' on':'');ai.dataset.peer='__ai__';
  ai.innerHTML=\`<div class="av" style="background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff;font-size:16px">✦<span class="odot" style="background:\${apiKey?'var(--gr)':'var(--bd)'}"></span></div>
    <div class="ciinfo"><div class="ciname">Gemini AI</div><div class="ciprev">\${apiKey?'// connected':'// needs API key'}</div></div>\`;
  ai.onclick=()=>openChat('__ai__',true);list.appendChild(ai);
}

function renderFriendsTab(){
  const inc=document.getElementById('incoming-section'),out=document.getElementById('outgoing-section'),fl=document.getElementById('friends-list');
  inc.innerHTML='';out.innerHTML='';fl.innerHTML='';
  if(fd.incoming.length){
    inc.innerHTML='<div class="seclbl">Incoming Requests</div>';
    fd.incoming.forEach(u=>{
      const el=document.createElement('div');el.className='freq';
      el.innerHTML=\`<div class="freq-top"><div class="av" style="background:\${u.color}33;color:\${u.color};width:36px;height:36px;font-size:12px">\${inits(u.username)}</div>
        <div><div class="freq-name">\${escH(u.username)}</div><div class="freq-sub">// wants to be friends</div></div></div>
        <div class="freq-btns"><button class="btn btn-sm btn-gr" onclick="acceptFriend('\${u.username}')">✓ Accept</button>
        <button class="btn btn-sm btn-rd" onclick="removeFriend('\${u.username}')">✕ Decline</button></div>\`;
      inc.appendChild(el);
    });
  }
  if(fd.outgoing.length){
    out.innerHTML='<div class="seclbl">Sent Requests</div>';
    fd.outgoing.forEach(u=>{
      const el=document.createElement('div');el.className='freq';
      el.innerHTML=\`<div class="freq-top"><div class="av" style="background:\${u.color}33;color:\${u.color};width:36px;height:36px;font-size:12px">\${inits(u.username)}</div>
        <div><div class="freq-name">\${escH(u.username)}</div><div class="freq-sub">// request pending…</div></div></div>
        <div class="freq-btns"><button class="btn btn-sm btn-rd" onclick="removeFriend('\${u.username}')">✕ Cancel</button></div>\`;
      out.appendChild(el);
    });
  }
  if(fd.friends.length){
    fl.innerHTML='<div class="seclbl">Friends</div>';
    fd.friends.forEach(u=>{
      const el=document.createElement('div');el.className='ci';el.style.marginBottom='4px';
      el.innerHTML=\`<div class="av" style="background:\${u.color}33;color:\${u.color}">\${inits(u.username)}<span class="odot" style="background:\${u.online?'var(--gr)':'var(--bd)'}"></span></div>
        <div class="ciinfo"><div class="ciname">\${escH(u.username)}</div><div class="ciprev">\${u.online?'// online':'// offline'}</div></div>
        <button class="btn btn-sm btn-rd" style="padding:5px 9px;font-size:11px" onclick="removeFriend('\${u.username}')">Remove</button>\`;
      fl.appendChild(el);
    });
  } else if(!fd.incoming.length&&!fd.outgoing.length){
    fl.innerHTML='<div class="empty-state">No friends yet.<br>Use "+ Add" to search for people!</div>';
  }
}

async function acceptFriend(u){try{await api('friends/accept',{from:u});await loadFriends();renderFriendsTab();}catch(e){alert(e.message);}}
async function removeFriend(u){try{await api('friends/remove',{username:u});await loadFriends();renderFriendsTab();}catch(e){alert(e.message);}}

let searchTimer=null;
function searchUsers(){
  clearTimeout(searchTimer);
  const q=document.getElementById('search-inp').value.trim();
  if(q.length<2){document.getElementById('search-results').innerHTML='';return;}
  searchTimer=setTimeout(async()=>{
    try{
      const d=await api('users/search',{q},'GET');
      const res=document.getElementById('search-results');res.innerHTML='';
      if(!d.users.length){res.innerHTML='<div class="empty-state">No users found</div>';return;}
      d.users.forEach(u=>{
        const isFriend=fd.friends.some(f=>f.username===u.username);
        const isPending=fd.outgoing.some(f=>f.username===u.username)||fd.incoming.some(f=>f.username===u.username);
        const el=document.createElement('div');el.className='sr';
        el.innerHTML=\`<div class="av" style="background:\${u.color}33;color:\${u.color};width:36px;height:36px;font-size:12px;flex-shrink:0">\${inits(u.username)}</div>
          <div class="sr-info"><div class="sr-name">\${escH(u.username)}</div></div>
          \${isFriend?'<span class="sr-sent">friends ✓</span>':isPending?'<span class="sr-sent">pending…</span>':\`<button class="btn btn-sm btn-ac" onclick="sendRequest('\${u.username}',this)">+ Add</button>\`}\`;
        res.appendChild(el);
      });
    }catch(e){}
  },300);
}

async function sendRequest(username,btn){
  btn.disabled=true;btn.textContent='Sending…';
  try{await api('friends/request',{to:username});btn.textContent='Sent ✓';btn.style.background='rgba(59,224,154,.1)';btn.style.color='var(--gr)';await loadFriends();}
  catch(e){btn.disabled=false;btn.textContent='+ Add';alert(e.message);}
}

function openChat(p,isAI){
  activePeer=p;clearInterval(pollT);lastId=0;aiHist=[];
  document.querySelectorAll('.ci').forEach(e=>e.classList.remove('on'));
  document.querySelector(\`.ci[data-peer="\${p}"]\`)?.classList.add('on');
  document.getElementById('empty').style.display='none';
  document.getElementById('panel').style.display='flex';
  const av=document.getElementById('panav'),sd=document.getElementById('psdot');
  if(isAI){
    av.style.background='linear-gradient(135deg,var(--ac),var(--ac2))';av.style.color='#fff';av.textContent='✦';
    document.getElementById('panname').textContent='Gemini AI';
    document.getElementById('panst').textContent=apiKey?'AI · connected':'AI · needs API key';
    sd.style.background=apiKey?'var(--gr)':'var(--mu)';
    document.getElementById('aibanner').classList.toggle('hidden',!!apiKey);
  }else{
    const u=fd.friends.find(x=>x.username===p),c=u?.color||'#6c63ff';
    av.style.background=c+'33';av.style.color=c;av.textContent=inits(p);
    document.getElementById('panname').textContent=p;
    document.getElementById('panst').textContent=u?.online?'online':'offline';
    sd.style.background=u?.online?'var(--gr)':'var(--mu)';
    document.getElementById('aibanner').classList.add('hidden');
  }
  document.getElementById('msgs').innerHTML='';
  if(!isAI){fetchMsgs();pollT=setInterval(fetchMsgs,2000);}
  document.getElementById('msginp').focus();
}

async function fetchMsgs(){
  if(!activePeer||activePeer==='__ai__')return;
  try{const d=await api('messages',{peer:activePeer,since:lastId},'GET');
    if(d.messages.length){d.messages.forEach(m=>addBubble(m));lastId=d.messages[d.messages.length-1].id;}
  }catch(e){}
}

function addBubble(m,isAI=false){
  const box=document.getElementById('msgs');
  const isMine=(m.sender||m.from)===me,sender=m.sender||m.from;
  const u=fd.friends.find(x=>x.username===sender);
  const c=isAI?null:(u?.color||'#6c63ff');
  const epoch=m.created_at||Math.floor(Date.now()/1000);
  const dl=fmtDate(epoch);
  const lastDiv=box.querySelector('.datediv:last-of-type');
  if(!lastDiv||lastDiv.dataset.date!==dl){
    const dv=document.createElement('div');dv.className='datediv fi';dv.dataset.date=dl;
    dv.innerHTML=\`<span>\${dl}</span>\`;box.appendChild(dv);
  }
  const div=document.createElement('div');div.className='msg fi'+(isMine?' me':'');
  const avSt=isAI?'background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff':\`background:\${c}33;color:\${c}\`;
  div.innerHTML=\`<div class="mav" style="\${avSt}">\${isAI?'✦':inits(sender)}</div>
    <div class="mcont"><div class="mname">\${isAI?'Gemini AI':escH(sender)}</div>
    <div class="mbub\${isAI?' aibub':''}">\${escH(m.text)}</div>
    <div class="mtime">\${fmtTime(epoch)}</div></div>\`;
  box.appendChild(div);box.scrollTop=box.scrollHeight;
}

function showTyping(){
  const box=document.getElementById('msgs');
  const t=document.createElement('div');t.id='typing';t.className='msg fi';
  t.innerHTML=\`<div class="mav" style="background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff">✦</div>
    <div class="mcont"><div class="mname">Gemini AI</div>
    <div class="typingbub"><div class="td"></div><div class="td"></div><div class="td"></div></div></div>\`;
  box.appendChild(t);box.scrollTop=box.scrollHeight;
}

function onKey(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();}}
function resize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,120)+'px';}

async function sendMsg(){
  const inp=document.getElementById('msginp'),text=inp.value.trim();
  if(!text||!activePeer)return;
  inp.value='';inp.style.height='auto';
  if(activePeer==='__ai__'){await sendAI(text);return;}
  addBubble({sender:me,text,created_at:Math.floor(Date.now()/1000)});
  try{await api('send',{peer:activePeer,text});}catch(e){}
}

async function sendAI(text){
  if(!apiKey){openKeyModal();return;}
  aiHist.push({role:'user',content:text});
  addBubble({from:me,text,created_at:Math.floor(Date.now()/1000)});
  showTyping();
  try{
    const d=await api('ai',{api_key:apiKey,history:aiHist});
    document.getElementById('typing')?.remove();
    aiHist.push({role:'assistant',content:d.reply});
    addBubble({sender:'__ai__',text:d.reply,created_at:Math.floor(Date.now()/1000)},true);
  }catch(e){document.getElementById('typing')?.remove();addBubble({sender:'__ai__',text:'⚠️ '+e.message,created_at:Math.floor(Date.now()/1000)},true);}
}

function openPwModal(){
  document.getElementById('pw-modal').classList.remove('hidden');
  ['pw-cur','pw-new','pw-conf'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('pw-sfill').style.width='0%';document.getElementById('pw-slbl').textContent='';
  document.getElementById('pw-ok').classList.remove('show');document.getElementById('pw-reqs').classList.remove('show');
  ['pw-err','pw-nerr','pw-cerr'].forEach(id=>hideErr(id));
  setTimeout(()=>document.getElementById('pw-cur').focus(),100);
}
function closePwModal(){document.getElementById('pw-modal').classList.add('hidden');}

async function savePw(){
  ['pw-err','pw-nerr','pw-cerr'].forEach(id=>hideErr(id));
  const cur=document.getElementById('pw-cur').value,nw=document.getElementById('pw-new').value,conf=document.getElementById('pw-conf').value;
  if(!cur){showErr('pw-err','Current password required','pw-cur');return;}
  if(nw.length<8){showErr('pw-nerr','At least 8 characters required','pw-new');return;}
  if(!/[A-Z]/.test(nw)){showErr('pw-nerr','Needs at least one uppercase letter','pw-new');return;}
  if(!/[0-9]/.test(nw)){showErr('pw-nerr','Needs at least one number','pw-new');return;}
  if(nw!==conf){showErr('pw-cerr','Passwords do not match','pw-conf');return;}
  try{await api('change_password',{current:cur,newpw:nw});document.getElementById('pw-ok').classList.add('show');setTimeout(closePwModal,1600);}
  catch(e){showErr('pw-err',e.message,'pw-cur');}
}

function openKeyModal(){
  document.getElementById('key-modal').classList.remove('hidden');
  document.getElementById('key-err').classList.remove('show');
  document.getElementById('key-inp').value=apiKey||'';
  setTimeout(()=>document.getElementById('key-inp').focus(),100);
}
function closeKeyModal(){document.getElementById('key-modal').classList.add('hidden');}
function saveKey(){
  const k=document.getElementById('key-inp').value.trim();
  if(!k.startsWith('AIza')){showErr('key-err','Gemini key must start with AIza','key-inp');return;}
  apiKey=k;sessionStorage.setItem('fc_akey',k);closeKeyModal();renderChats();
  if(activePeer==='__ai__'){
    document.getElementById('aibanner').classList.add('hidden');
    document.getElementById('panst').textContent='AI · connected';
    document.getElementById('psdot').style.background='var(--gr)';
    aiHist=[];addBubble({sender:'__ai__',text:'Gemini connected! Ask me anything ✦',created_at:Math.floor(Date.now()/1000)},true);
  }
}

if(token&&me){api('ping').then(()=>startSession(token,me,myColor)).catch(()=>{sessionStorage.clear();});}
</script>
</body>
</html>`));

app.listen(PORT, () => {
  console.log(`\n✦ Flux Chat running!`);
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → Ports tab: set port ${PORT} to Public\n`);
});
