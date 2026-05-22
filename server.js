/**
 * NexaChat — Main Server
 * Express 4 + Socket.io 4 + SQLite (better-sqlite3)
 * ShieldWatch RASP sensor optional via SW_ENABLED env var
 *
 * ⚠️  INTENTIONAL VULNERABILITIES FOR DEMO:
 *   1. /api/login              — SQL Injection (raw string concat)
 *   2. /api/search             — Reflected XSS (innerHTML on client)
 *   3. /api/file               — Path Traversal (no jail check)
 *   4. /api/profile/update     — CSRF (no token, accepts form submissions)
 *   5. /api/user/:id           — IDOR (no ownership check, leaks password)
 *   6. /api/session/id+fix     — Session Fixation (exposes & accepts arbitrary session IDs)
 *   7. /api/tools/ping         — Command Injection (exec without sanitisation)
 *   8. /api/login (repeated)   — Brute Force (no lockout)
 */

const express        = require('express');
const http           = require('http');
const { Server }     = require('socket.io');
const session        = require('express-session');
const path           = require('path');
const fs             = require('fs');
const cors           = require('cors');
const rateLimit      = require('express-rate-limit');
const { exec }       = require('child_process');
const crypto         = require('crypto');
const { initDB, getDB, getPrepare, execVulnerable } = require('./database');

const app    = express();
app.set('trust proxy', 1); // Railway terminates SSL at load balancer
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT           = process.env.PORT || 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'nexachat-dev-secret-2024';

// ─── Session Middleware (shared with Socket.io) ───────────────────────────────
const sessionMiddleware = session({
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, secure: process.env.NODE_ENV === 'production' }
});

app.use(cors());

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Too many attempts — try again in a minute.' }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Too many registrations — slow down.' }
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);

// ─── ShieldWatch RASP Sensor (optional) ───────────────────────────────────────
let sw = null;
if (process.env.SW_ENABLED === 'true') {
  try {
    sw = require('./shieldwatch-sensor');
    app.use(sw.httpMiddleware);
    console.log('[ShieldWatch] ✅ RASP sensor ACTIVE — Cerebro:', process.env.SW_CEREBRO_ADDR || '127.0.0.1:50051');
  } catch (e) {
    console.warn('[ShieldWatch] ⚠️  Sensor not loaded:', e.message);
  }
} else {
  console.log('[ShieldWatch] ⛔ Sensor DISABLED — app is UNPROTECTED (set SW_ENABLED=true to enable)');
}

// ─── Static Files (index.html excluded — served dynamically to inject nonce) ──
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ─── Auth Guard ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  next();
}

// ─── Pages ────────────────────────────────────────────────────────────────────
// index.html is served dynamically so we can embed a one-time fingerprint nonce.
// The nonce is stored in the session and must be echoed back by sw-beacon.js.
// A raw curl attacker who never loads this page never gets a valid nonce.
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/chat');

  // Generate a fresh nonce for every login page load
  const fpNonce = crypto.randomBytes(16).toString('hex');
  req.session.fpNonce   = fpNonce;
  req.session.fpNonceAt = Date.now();

  // Inject the nonce into index.html via a <meta> tag
  const html     = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const injected = html.replace('</head>', `  <meta name="sw-nonce" content="${fpNonce}">\n</head>`);
  res.send(injected);
});

app.get('/chat', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/ping', (req, res) => {
  res.json({ status: 'online', app: 'nexachat', version: '2.0.0', shieldwatch: !!sw });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #1: SQL INJECTION
//     Username is concatenated directly into the SQL query.
//     Demo payload: username = admin'--  (any password)
//     SQL becomes:  SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ ok: false, error: 'Username and password are required.' });
  }

  // ─── ShieldWatch Fingerprint Gate ───────────────────────────────────────────
  // Block login until the browser fingerprint has been collected by the sensor.
  // This prevents automated scripts and bots that skip the JS fingerprint beacon.
  if (sw && !req.session.fpId) {
    return res.status(403).json({
      ok:    false,
      code:  'FP_REQUIRED',
      error: 'Security verification in progress. Please wait a moment and try again.'
    });
  }

  try {
    // !! INTENTIONALLY VULNERABLE — DO NOT USE IN PRODUCTION !!
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user  = execVulnerable(query);

    if (!user) {
      // Notify ShieldWatch of failed login (brute force tracking)
      if (sw && sw.trackLoginFailure) {
        const blocked = sw.trackLoginFailure(req);
        if (blocked) {
          return res.status(429).json({
            ok: false, blocked: true,
            error: 'Too many failed login attempts. Blocked by ShieldWatch.',
            threat: 'bruteforce',
          });
        }
      }
      return res.json({ ok: false, error: 'Invalid username or password.' });
    }

    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;

    res.json({
      ok: true,
      user: {
        id:           user.id,
        username:     user.username,
        role:         user.role,
        avatar_color: user.avatar_color,
        bio:          user.bio
      }
    });
  } catch (e) {
    // Return raw DB error to caller — intentional for demo (shows SQLi worked)
    res.json({ ok: false, error: e.message });
  }
});

// ─── Register ─────────────────────────────────────────────────────────────────
app.post('/api/register', registerLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ ok: false, error: 'Username and password are required.' });
  }
  if (username.length < 2 || username.length > 30) {
    return res.json({ ok: false, error: 'Username must be 2–30 characters.' });
  }
  if (password.length < 4) {
    return res.json({ ok: false, error: 'Password must be at least 4 characters.' });
  }

  const prepare = getPrepare();
  const palette = ['#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#06b6d4'];
  const color   = palette[Math.floor(Math.random() * palette.length)];

  try {
    prepare('INSERT INTO users (username, password, avatar_color) VALUES (?, ?, ?)').run(username.trim(), password, color);

    const user = prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;

    res.json({
      ok: true,
      user: { id: user.id, username: user.username, role: user.role, avatar_color: user.avatar_color, bio: '' }
    });
  } catch (e) {
    res.json({ ok: false, error: 'Username already taken.' });
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ─── ShieldWatch Status (for dashboard badge) ─────────────────────────────────
app.get('/api/sw/status', (req, res) => {
  res.json({ enabled: process.env.SW_ENABLED === 'true' });
});

// ─── Current User ─────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const prepare = getPrepare();
  const user    = prepare('SELECT id, username, role, avatar_color, bio FROM users WHERE id = ?').get(req.session.userId);
  res.json(user || {});
});

// ─── Rooms ────────────────────────────────────────────────────────────────────
app.get('/api/rooms', requireAuth, (req, res) => {
  const prepare = getPrepare();
  const rooms   = prepare('SELECT * FROM rooms ORDER BY id ASC').all();
  res.json(rooms);
});

// ─── Messages ─────────────────────────────────────────────────────────────────
// Fix: Only return messages for rooms the user has joined (via Socket.IO join_room).
// Admins can read all rooms. Regular users need to have explicitly joined first.
app.get('/api/messages/:roomId', requireAuth, (req, res) => {
  const rid        = parseInt(req.params.roomId, 10);
  const role       = req.session.role;
  const joined     = req.session.joinedRooms || [];

  if (role !== 'admin' && !joined.includes(rid)) {
    return res.status(403).json({
      ok:    false,
      error: 'You have not joined this room. Open the room in the chat UI first.',
    });
  }

  const prepare = getPrepare();
  // Join with users to get role; include deleted flag so client can render tombstone
  const msgs = prepare(`
    SELECT m.id, m.room_id, m.user_id, m.username, m.avatar_color, m.text,
           m.deleted, m.reply_to_id, m.reply_to_username, m.reply_to_text,
           m.created_at, u.role as role
    FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.room_id = ?
    ORDER BY m.created_at ASC LIMIT 100
  `).all(rid);
  res.json(msgs);
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #2: REFLECTED XSS
//     The search query `q` is returned as-is in the JSON response.
//     The client-side chat.js renders results.query using innerHTML.
//     Demo payload: q=<img src=x onerror=alert('XSS')>
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/search', requireAuth, (req, res) => {
  const { q, roomId } = req.query;
  if (!q) return res.json({ ok: true, results: [], query: '' });

  const prepare = getPrepare();
  const results = prepare(
    'SELECT * FROM messages WHERE room_id = ? AND text LIKE ? ORDER BY created_at DESC LIMIT 20'
  ).all(roomId || 1, `%${q}%`);

  // !! INTENTIONALLY returns raw `q` — client will innerHTML it !!
  res.json({ ok: true, results, query: q });
});

// ─── Pinned Message ───────────────────────────────────────────────────────────
app.get('/api/pinned/:roomId', requireAuth, (req, res) => {
  const prepare = getPrepare();
  const pin = prepare('SELECT * FROM pinned_messages WHERE room_id = ?').get(req.params.roomId);
  res.json({ ok: true, pin: pin || null });
});

// ─── Reactions for a message ──────────────────────────────────────────────────
app.get('/api/reactions/:msgId', requireAuth, (req, res) => {
  const prepare = getPrepare();
  const rows = prepare(
    'SELECT emoji, COUNT(*) as count, GROUP_CONCAT(username) as users FROM reactions WHERE message_id = ? GROUP BY emoji'
  ).all(req.params.msgId);
  res.json({ ok: true, reactions: rows });
});

// ─── Files List ───────────────────────────────────────────────────────────────
app.get('/api/files', requireAuth, (req, res) => {
  const dir = path.join(__dirname, 'uploads');
  try {
    const files = fs.readdirSync(dir).filter(f => !f.startsWith('.'));
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #3: PATH TRAVERSAL
//     `req.query.path` is joined to the uploads dir WITHOUT sanitisation.
//     Demo payload: path=../private/db_config.txt
//     Escapes uploads/ and reads the private config file.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/file', requireAuth, (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.json({ ok: false, error: 'No path specified.' });

  // !! INTENTIONALLY VULNERABLE — no path.resolve jail check !!
  const fullPath = path.join(__dirname, 'uploads', filePath);

  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    res.json({ ok: true, content, path: filePath });
  } catch (e) {
    res.json({ ok: false, error: `Cannot read file: ${filePath}`, path: filePath });
  }
});

// ──────────────────────────────────────────────────────────────��──────────────
// ShieldWatch Fingerprint Receiver
// sw-beacon.js POSTs here → sensor forwards to collector
// ───────────────────────────────────────────────���───────────────────────────���─
app.post('/api/sw/fingerprint', (req, res) => {
  // ── Nonce validation — kills the curl-bypass attack ─────────────────────────
  // The nonce is embedded in the login page HTML at serve time.
  // Only a real browser that loaded index.html has a valid nonce.
  // A curl attacker hitting this endpoint directly never loaded the page,
  // so they can't have the correct nonce → fingerprint rejected.
  const submittedNonce = req.body?.nonce;
  const sessionNonce   = req.session?.fpNonce;
  const nonceAge       = Date.now() - (req.session?.fpNonceAt || 0);
  const NONCE_TTL_MS   = 10 * 60 * 1000; // 10 minutes

  if (!submittedNonce || submittedNonce !== sessionNonce || nonceAge > NONCE_TTL_MS) {
    // Reject invalid / missing / expired nonce — do NOT set fpId
    return res.status(403).json({ ok: false, error: 'Invalid security token.' });
  }

  // Consume nonce (one-time use)
  req.session.fpNonce   = null;
  req.session.fpNonceAt = null;

  // Store fingerprint in session — used by the login gate check
  const fpId = req.body?.deviceId
            || req.body?.canvasHash
            || req.body?.canvas
            || req.body?.fingerprint?.deviceId
            || req.body?.fingerprint?.canvas;
  if (fpId && req.session) {
    req.session.fpId = fpId;
  }
  if (sw && sw.submitFingerprint) sw.submitFingerprint(req.body, req);
  res.json({ ok: true });
});

// ───────────────────────────────��─────────────────────────────────��───────────
// 🍯 HONEYPOT ENDPOINTS
// Not linked anywhere in the real UI. Any access triggers DECOY verdict.
// Returns convincing fake data to trap the attacker.
// ─────────────────────────────────────────────────────────────────────────────

// Fake admin user list
app.get('/api/admin/users', requireAuth, (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/admin/users', req);
  res.json({
    ok: true,
    users: [
      { id: 1, username: 'superadmin',  password: 'N3xaC0rp@2024!',  email: 'superadmin@nexacorp.com',  role: 'superadmin', lastLogin: '2024-04-01T09:14:22Z' },
      { id: 2, username: 'john.smith',  password: 'CEO_J0hn!2024',    email: 'ceo@nexacorp.com',         role: 'admin',      lastLogin: '2024-04-02T08:32:11Z' },
      { id: 3, username: 'it_admin',    password: 'ITSupp0rt#2024',   email: 'it@nexacorp.com',          role: 'admin',      lastLogin: '2024-04-02T10:05:44Z' },
      { id: 4, username: 'alice',       password: 'alice123',          email: 'alice@nexacorp.com',       role: 'user',       lastLogin: '2024-04-02T11:21:09Z' },
      { id: 5, username: 'bob',         password: 'bob123',            email: 'bob@nexacorp.com',         role: 'user',       lastLogin: '2024-04-01T16:44:30Z' },
    ],
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// Fake config dump
app.get('/api/admin/config', requireAuth, (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/admin/config', req);
  res.json({
    ok: true,
    config: {
      db_host:     'db.nexacorp.internal',
      db_port:     5432,
      db_name:     'nexachat_prod',
      db_user:     'nexachat_admin',
      db_password: 'Nx@Pr0d_S3cur3!2024',
      jwt_secret:  '8e3f92b1c4d5a6e7f8091234abcd5678ef90',
      api_key:     'sk-nexachat-a1b2c3d4e5f6789012345678',
      smtp_pass:   'M@il_N3xa_2024!',
      s3_secret:   'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    },
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// Fake database export — requires login; unauthenticated access blocked
app.get('/api/export', requireAuth, (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/export', req);
  res.json({
    ok: true,
    export: {
      format:    'json',
      timestamp: new Date().toISOString(),
      tables: {
        users:    [{ id:1, username:'superadmin', password_hash:'$2b$12$FakeBcryptHashForDemo', email:'ceo@nexacorp.com' }],
        sessions: [{ token: 'eyJfake.token.here', user_id: 1, expires: '2024-12-31' }],
        messages: [{ id: 1, text: 'Q1 revenue $4.8M — do not share outside finance', room: 'announcements' }],
      }
    },
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #4: CSRF
//     Profile update accepts form-encoded POST with no CSRF token.
//     Attack: csrf-attack.html auto-submits while victim is logged in.
//     With ShieldWatch ON: form-encoded POST to protected endpoint = BLOCKED.
//     Demo page: /csrf-attack.html
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/profile/update', requireAuth, express.urlencoded({ extended: false }), (req, res) => {
  const { bio, avatar_color, username } = req.body;
  const prepare = getPrepare();
  if (username && username.length >= 2 && username.length <= 30) {
    prepare('UPDATE users SET bio = ?, avatar_color = ?, username = ? WHERE id = ?')
      .run(bio || '', avatar_color || '#3b82f6', username, req.session.userId);
    req.session.username = username;
  } else {
    prepare('UPDATE users SET bio = ?, avatar_color = ? WHERE id = ?')
      .run(bio || '', avatar_color || '#3b82f6', req.session.userId);
  }
  const updated = prepare('SELECT id,username,role,avatar_color,bio FROM users WHERE id = ?')
    .get(req.session.userId);
  res.json({ ok: true, message: '✅ Profile updated successfully.', user: updated });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #5: INSECURE DIRECT OBJECT REFERENCE (IDOR)
//     No auth check — any user ID returns the full DB record including password.
//     Demo: fetch('/api/user/1') → gets admin's plain-text password.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/user/:id', requireAuth, (req, res) => {
  // !! INTENTIONALLY VULNERABLE — no ownership check (IDOR) !!
  const prepare = getPrepare();
  const user = prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  // Returns everything including the password field
  res.json({ ok: true, user });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #6: SESSION FIXATION
//     GET /api/session/id  → reveals the victim's session ID
//     POST /api/session/fix → attacker pre-sets a known session ID before login
//     Attack: attacker plants session ID → victim logs in → attacker now owns session
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/session/id', requireAuth, (req, res) => {
  // !! VULNERABLE: exposes session ID (IDOR — ShieldWatch detects) !!
  res.json({
    ok:        true,
    sessionId: req.sessionID,
    username:  req.session.username || null,
    role:      req.session.role     || null,
    userId:    req.session.userId   || null,
    _warning:  'This endpoint should NOT exist in production!'
  });
});

app.post('/api/session/fix', requireAuth, (req, res) => {
  // !! VULNERABLE: accepts attacker-controlled session ID (ShieldWatch detects) !!
  const { sessionId } = req.body;
  if (!sessionId) return res.json({ ok: false, error: 'sessionId required' });
  // Store attacker's desired session ID in the session data so it can be retrieved
  req.session.fixedId = sessionId;
  req.session.save(() => {
    res.json({
      ok:          true,
      message:     'Session fixation successful.',
      attackerSet: sessionId,
      activeSid:   req.sessionID,
      _note:       'Attacker now knows victim\'s session ID. When victim logs in, attacker can hijack the session using this SID.'
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #7: COMMAND INJECTION
//     POST /api/tools/ping — host parameter concatenated directly into exec().
//     Demo: host = "8.8.8.8 && id"  → runs `id` on the server
//           host = "8.8.8.8; ls /"  → lists root directory
//           host = "8.8.8.8 && cat /etc/hostname" → leaks server hostname
//     With ShieldWatch ON: cmdInjection patterns detected → BLOCKED.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/tools/ping', requireAuth, (req, res) => {
  const { host } = req.body;
  if (!host) return res.json({ ok: false, error: 'host is required' });

  // !! INTENTIONALLY VULNERABLE — no sanitisation of host parameter !!
  const cmd = process.platform === 'win32'
    ? `ping -n 1 ${host}`
    : `ping -c 1 ${host}`;

  exec(cmd, { timeout: 6000 }, (err, stdout, stderr) => {
    res.json({
      ok:     true,
      host,
      cmd,
      output: stdout || stderr || err?.message || 'No output',
      _warning: 'This endpoint is intentionally vulnerable to command injection!'
    });
  });
});

// ─── Admin Feature State ──────────────────────────────────────────────────────
const mutedUsers    = new Map(); // userId → { until: timestamp|Infinity, by: username }
const slowModeRooms = new Map(); // roomId → seconds
const lastMsgTime   = new Map(); // `${userId}:${roomId}` → ms timestamp

// ─── Online Users (REST fallback) ─────────────────────────────────────────────
const onlineUsers = new Map(); // socketId → userObj

app.get('/api/online', requireAuth, (req, res) => {
  res.json(Array.from(onlineUsers.values()));
});

// ─────────────────────────────────────────────────────────────────────────────
//  SOCKET.IO — Real-time chat engine
// ─────────────────────────────────────────────────────────────────────────────

// Share Express sessions with Socket.io
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

io.on('connection', (socket) => {
  const sess = socket.request.session;
  if (!sess || !sess.userId) {
    socket.disconnect(true);
    return;
  }

  const prepare = getPrepare();
  const user    = prepare('SELECT * FROM users WHERE id = ?').get(sess.userId);
  if (!user) { socket.disconnect(true); return; }

  const userObj = {
    socketId:     socket.id,
    userId:       user.id,
    username:     user.username,
    role:         user.role,
    avatar_color: user.avatar_color,
    roomId:       null
  };

  onlineUsers.set(socket.id, userObj);
  broadcastOnlineUsers();

  // ── Join Room ────────────────────────────────────────────────────────────────
  socket.on('join_room', (roomId) => {
    const rid = parseInt(roomId, 10);
    if (isNaN(rid)) return;

    // Leave old room
    const prev = onlineUsers.get(socket.id);
    if (prev && prev.roomId) {
      socket.leave(`room:${prev.roomId}`);
      socket.to(`room:${prev.roomId}`).emit('typing_stop', { username: prev.username });
    }

    // Join new room
    socket.join(`room:${rid}`);
    userObj.roomId = rid;
    onlineUsers.set(socket.id, userObj);

    // Track membership in session so REST /api/messages/:roomId can verify it
    const sess = socket.request.session;
    sess.joinedRooms = sess.joinedRooms || [];
    if (!sess.joinedRooms.includes(rid)) {
      sess.joinedRooms.push(rid);
      sess.save(() => {});   // persist immediately
    }

    broadcastOnlineUsers();
  });

  // ── Chat Message ─────────────────────────────────────────────────────────────
  socket.on('chat_message', ({ roomId, text, replyToId, replyToUsername, replyToText }) => {
    if (!text || typeof text !== 'string') return;
    const clean = text.trim().slice(0, 2000);
    if (!clean) return;

    const rid  = parseInt(roomId, 10);
    const u    = onlineUsers.get(socket.id);
    if (!u) return;

    // ── Mute check ────────────────────────────────────────────────────────────
    const muteInfo = mutedUsers.get(u.userId);
    if (muteInfo) {
      const stillMuted = muteInfo.until === Infinity || Date.now() < muteInfo.until;
      if (stillMuted) {
        socket.emit('message_blocked', { error: 'You have been muted by an admin.', threat: 'muted' });
        return;
      } else {
        mutedUsers.delete(u.userId); // expired
      }
    }

    // ── Slow mode check ───────────────────────────────────────────────────────
    const slowSec = slowModeRooms.get(rid);
    if (slowSec && u.role !== 'admin') {
      const key     = `${u.userId}:${rid}`;
      const lastAt  = lastMsgTime.get(key) || 0;
      const elapsed = (Date.now() - lastAt) / 1000;
      if (elapsed < slowSec) {
        const remainingMs = Math.ceil((slowSec - elapsed) * 1000);
        socket.emit('message_blocked', {
          error: `Slow mode active — wait ${Math.ceil(slowSec - elapsed)}s before sending.`,
          threat: 'slowmode',
          remainingMs,
        });
        return;
      }
      lastMsgTime.set(key, Date.now());
    }

    const prepare2 = getPrepare();
    const result   = prepare2(
      'INSERT INTO messages (room_id, user_id, username, avatar_color, text, reply_to_id, reply_to_username, reply_to_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(rid, u.userId, u.username, u.avatar_color, clean,
          replyToId || null, replyToUsername || null, replyToText ? replyToText.slice(0, 120) : null);

    const msg = {
      id:               result.lastInsertRowid,
      room_id:          rid,
      user_id:          u.userId,
      username:         u.username,
      role:             u.role,
      avatar_color:     u.avatar_color,
      text:             clean,
      deleted:          0,
      reply_to_id:      replyToId      || null,
      reply_to_username: replyToUsername || null,
      reply_to_text:    replyToText    || null,
      created_at:       new Date().toISOString()
    };

    // ShieldWatch Socket.io hook — runs BEFORE broadcast so it can block
    if (sw && sw.inspectMessage) {
      const blocked = sw.inspectMessage(msg, socket);
      if (blocked) {
        // Tell only the sender their message was blocked — don't broadcast it
        socket.emit('message_blocked', {
          ref:    crypto.randomUUID(),
          threat: blocked.type,
          error:  'Your message was blocked by ShieldWatch RASP.',
        });
        return;
      }
    }

    io.to(`room:${rid}`).emit('chat_message', msg);
  });

  // ── Delete Message ───────────────────────────────────────────────────────────
  socket.on('delete_message', ({ msgId, roomId }) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    const prepare2 = getPrepare();
    const msg = prepare2('SELECT * FROM messages WHERE id = ?').get(msgId);
    if (!msg) return;
    // Only message owner OR admin can delete
    if (msg.user_id !== u.userId && u.role !== 'admin') return;
    prepare2('UPDATE messages SET deleted = 1 WHERE id = ?').run(msgId);
    io.to(`room:${roomId}`).emit('message_deleted', { msgId });
  });

  // ── Add / Toggle Reaction ────────────────────────────────────────────────────
  socket.on('add_reaction', ({ msgId, roomId, emoji }) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    const prepare2 = getPrepare();
    const existing = prepare2('SELECT id FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?').get(msgId, u.userId, emoji);
    if (existing) {
      prepare2('DELETE FROM reactions WHERE id = ?').run(existing.id);
    } else {
      prepare2('INSERT INTO reactions (message_id, user_id, username, emoji) VALUES (?, ?, ?, ?)').run(msgId, u.userId, u.username, emoji);
    }
    const reactions = prepare2(
      'SELECT emoji, COUNT(*) as count, GROUP_CONCAT(username) as users FROM reactions WHERE message_id = ? GROUP BY emoji'
    ).all(msgId);
    io.to(`room:${roomId}`).emit('reaction_update', { msgId, reactions });
  });

  // ── Kick User (admin only) ───────────────────────────────────────────────────
  socket.on('kick_user', ({ targetUserId, targetUsername, roomId }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    // Disconnect all sockets belonging to target
    for (const [sid, usr] of onlineUsers) {
      if (usr.userId === targetUserId) {
        const tSocket = io.sockets.sockets.get(sid);
        if (tSocket) {
          tSocket.emit('kicked', { by: u.username });
          setTimeout(() => tSocket.disconnect(true), 600);
        }
      }
    }
    io.to(`room:${roomId}`).emit('system_message', {
      text: `${targetUsername} was removed from the chat by an admin.`,
      created_at: new Date().toISOString(),
    });
  });

  // ── Mute User (admin only) ───────────────────────────────────────────────────
  socket.on('mute_user', ({ targetUserId, targetUsername, durationMs }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    const until = durationMs === -1 ? Infinity : Date.now() + durationMs;
    mutedUsers.set(targetUserId, { until, by: u.username });
    for (const [sid, usr] of onlineUsers) {
      if (usr.userId === targetUserId) {
        const tSocket = io.sockets.sockets.get(sid);
        if (tSocket) tSocket.emit('you_are_muted', { until, by: u.username });
      }
    }
    socket.emit('admin_toast', { msg: `${targetUsername} has been muted.`, type: 'success' });
  });

  socket.on('unmute_user', ({ targetUserId, targetUsername }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    mutedUsers.delete(targetUserId);
    for (const [sid, usr] of onlineUsers) {
      if (usr.userId === targetUserId) {
        const tSocket = io.sockets.sockets.get(sid);
        if (tSocket) tSocket.emit('you_are_unmuted');
      }
    }
    socket.emit('admin_toast', { msg: `${targetUsername} has been unmuted.`, type: 'success' });
  });

  // ── Pin Message (admin only) ─────────────────────────────────────────────────
  socket.on('pin_message', ({ msgId, roomId }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    const prepare2 = getPrepare();
    const msg = prepare2('SELECT * FROM messages WHERE id = ?').get(msgId);
    if (!msg || msg.deleted) return;
    prepare2(
      'INSERT OR REPLACE INTO pinned_messages (room_id, message_id, message_text, message_username, pinned_by) VALUES (?, ?, ?, ?, ?)'
    ).run(roomId, msgId, msg.text, msg.username, u.username);
    io.to(`room:${roomId}`).emit('message_pinned', {
      msgId, text: msg.text, username: msg.username, pinnedBy: u.username,
    });
  });

  socket.on('unpin_message', ({ roomId }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    const prepare2 = getPrepare();
    prepare2('DELETE FROM pinned_messages WHERE room_id = ?').run(roomId);
    io.to(`room:${roomId}`).emit('message_unpinned', { roomId });
  });

  // ── Slow Mode (admin only) ───────────────────────────────────────────────────
  socket.on('set_slow_mode', ({ roomId, seconds }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    const sec = Math.max(0, parseInt(seconds, 10) || 0);
    if (sec > 0) slowModeRooms.set(roomId, sec);
    else         slowModeRooms.delete(roomId);
    io.to(`room:${roomId}`).emit('slow_mode_update', { roomId, seconds: sec });
    socket.emit('admin_toast', {
      msg: sec > 0 ? `Slow mode set to ${sec}s.` : 'Slow mode disabled.',
      type: 'success',
    });
  });

  // ── Global Broadcast (admin only) ────────────────────────────────────────────
  socket.on('broadcast_announcement', ({ text }) => {
    const u = onlineUsers.get(socket.id);
    if (!u || u.role !== 'admin') return;
    const clean = (text || '').trim().slice(0, 500);
    if (!clean) return;
    io.emit('global_announcement', { text: clean, by: u.username, at: new Date().toISOString() });
  });

  // ── Typing Indicators ────────────────────────────────────────────────────────
  socket.on('typing_start', (roomId) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    socket.to(`room:${roomId}`).emit('typing_start', { username: u.username });
  });

  socket.on('typing_stop', (roomId) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    socket.to(`room:${roomId}`).emit('typing_stop', { username: u.username });
  });

  // ── Disconnect ───────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const u = onlineUsers.get(socket.id);
    if (u && u.roomId) {
      socket.to(`room:${u.roomId}`).emit('typing_stop', { username: u.username });
    }
    onlineUsers.delete(socket.id);
    broadcastOnlineUsers();
    console.log(`[-] ${user.username} disconnected`);
  });

  console.log(`[+] ${user.username} connected (${socket.id})`);
});

function broadcastOnlineUsers() {
  io.emit('users_update', Array.from(onlineUsers.values()));
}


// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 NexaChat running → http://localhost:${PORT}\n`);
  });
}).catch(err => {
  console.error('[Fatal] DB init failed:', err);
  process.exit(1);
});

module.exports = { app, server };
