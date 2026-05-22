/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║              ShieldWatch Sensor  ·  v1.0.0                             ║
 * ║    Runtime Application Self-Protection (RASP) for Node.js / Express   ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * QUICK START — add to any Express app in 3 lines:
 *
 *   const ShieldWatch = require('shieldwatch-sensor');
 *   const sw = ShieldWatch.create({ collectorUrl: 'http://localhost:3002' });
 *   app.use(sw.middleware);
 *
 * WHAT IT PROTECTS AGAINST:
 *   SQL Injection · XSS · Path Traversal · Command Injection
 *   CSRF · IDOR · Session Fixation · DDoS/Flood · Brute Force · SSRF · CRLF
 *
 * PLATFORMS: Any OS that runs Node.js — Windows · macOS · Linux
 *
 * OPTIONS (all optional — works with zero config):
 *   collectorUrl         string    URL of the Cerebro dashboard backend (default: http://localhost:3002)
 *   appId                string    Label shown in Cerebro for this app   (default: 'app')
 *   logOnly              boolean   Detect but never block — passive mode  (default: false)
 *   csrfProtectedPaths   string[]  Paths that reject form-encoded POSTs   (default: [])
 *   sessionFixationPaths string[]  Paths that should never be accessible  (default: [])
 *   honeypotPaths        string[]  Decoy paths — access = attacker flagged (default: common paths)
 *   idorChecker          function  Custom IDOR logic (req) => threat|null (default: null)
 *   ddosThreshold        number    Max requests per window before flood    (default: 20)
 *   ddosWindowMs         number    Sliding window in ms                    (default: 10000)
 *   bruteForceThreshold  number    Failed logins before block              (default: 5)
 *   apiPathPrefix        string    Path prefix to apply DDoS checks on    (default: '/api')
 */

'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

// ─── Attack Patterns ──────────────────────────────────────────────────────────
// These patterns are the core of ShieldWatch — fully generic, not app-specific
const PATTERNS = {
  sqli: [
    /'\s*(--|#|\/\*)/i,
    /'\s*(OR|AND)\s+['"\d]/i,
    /\bunion\b[\s\S]+\bselect\b/i,
    /\bselect\b.+\bfrom\b/i,
    /\bdrop\s+table\b/i,
    /\binsert\s+into\b/i,
    /'\s*=\s*'/i,
    /;\s*(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE)\b/i,
    /\bsleep\s*\(/i,
    /\bwaitfor\s+delay\b/i,
    /0x[0-9a-f]{4,}/i,
  ],
  xss: [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /on\w+\s*=\s*['"`]?/i,
    /<img[^>]+onerror/i,
    /<iframe[\s>]/i,
    /\balert\s*\(/i,
    /document\.cookie/i,
    /eval\s*\(/i,
    /<svg[\s\S]{0,50}on\w+/i,
    /vbscript\s*:/i,
    /data\s*:\s*text\/html/i,
    /&#x?[0-9a-f]+;[\s\S]{0,30}(?:script|alert|onerror)/i,
  ],
  pathTraversal: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e%2f/i,
    /%2e%2e\//i,
    /\.\.%2f/i,
    /%252e%252e/i,
    /\/etc\/passwd/i,
    /\/proc\/self/i,
    /%00/,
    /%c0%ae|%c0%2e/i,
  ],
  cmdInjection: [
    /[;&|`$]\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
    /\|\s*(?:nc|netcat|ncat)\b/i,
    /\$\{IFS\}/,
    /&&\s*(?:cat|ls|id|whoami|curl|wget|bash|sh)\b/i,
  ],
  ssrf: [
    /169\.254\.169\.254/,
    /127\.0+\.0+\.\d+/,
    /(?:^|[^a-z0-9\-])localhost(?:[:/]|$)/i,
    /(?:^|[^\d])10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/,
    /192\.168\.\d{1,3}\.\d{1,3}/,
    /gopher:\/\//i,
    /dict:\/\//i,
    /file:\/\//i,
  ],
  crlf: [
    /%0d%0a/i,
    /\r\n(?:set-cookie|location|content-type):/i,
    /%0a(?:set-cookie|location|content-type):/i,
    /%e5%98%8a|%e5%98%8d|%u000d|%u000a/i,
  ],
};

// Default honeypot paths — universal "low-hanging fruit" that attackers probe
const DEFAULT_HONEYPOT_PATHS = new Set([
  '/admin', '/wp-admin', '/wp-login.php', '/phpmyadmin',
  '/.env', '/.git/config', '/config.php', '/web.config',
  '/api/admin', '/api/config', '/api/backup', '/api/db-dump',
  '/api/secret', '/api/export', '/api/debug',
]);

// ─── Pure helper functions ────────────────────────────────────────────────────
function stripSqlComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '');
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1')
    .split(',')[0].trim().replace(/^::ffff:/, '');
}

function parseCollectorUrl(url) {
  try {
    const parsed = new URL(url);
    return {
      host:     parsed.hostname,
      port:     parseInt(parsed.port, 10) || (parsed.protocol === 'https:' ? 443 : 80),
      useHttps: parsed.protocol === 'https:',
    };
  } catch {
    // Fallback: treat as host:port or plain domain
    if (url.includes(':')) {
      const [host, portStr] = url.split(':');
      return { host, port: parseInt(portStr, 10), useHttps: false };
    }
    return { host: url, port: 443, useHttps: true };
  }
}

// ─── detectThreats — the core detection engine ────────────────────────────────
// Pure function — no side effects, no state. Safe to call from anywhere.
function detectThreats(value) {
  if (value == null || typeof value !== 'string') return null;
  const variants = [value];
  try {
    const d1 = decodeURIComponent(value.replace(/\+/g, ' '));
    if (d1 !== value) variants.push(d1);
    const d2 = decodeURIComponent(d1.replace(/\+/g, ' '));
    if (d2 !== d1) variants.push(d2);
  } catch {}
  const extra = [];
  for (const v of variants) {
    const stripped = stripSqlComments(v);
    if (stripped !== v) extra.push(stripped);
  }
  variants.push(...extra);

  for (const [type, patterns] of Object.entries(PATTERNS)) {
    for (const re of patterns) {
      for (const v of variants) {
        if (re.test(v)) {
          return { type, matched: re.toString(), raw: value.slice(0, 200) };
        }
      }
    }
  }
  return null;
}

function scanRequest(req) {
  const vals = [
    ...Object.values(req.query  || {}),
    ...Object.values(req.body   || {}),
    ...Object.values(req.params || {}),
  ].filter(v => typeof v === 'string');
  for (const val of vals) {
    const t = detectThreats(val);
    if (t) return t;
  }
  return null;
}

// ─── ShieldWatch.create(options) — the main factory ──────────────────────────
function create(options = {}) {

  // ── Resolve config with defaults ───────────────────────────────────────────
  const collectorUrl  = options.collectorUrl  || process.env.SW_CEREBRO_URL || 'http://localhost:3002';
  const appId         = options.appId         || process.env.SW_APP_ID      || 'app';
  const logOnly       = options.logOnly       ?? (process.env.SW_LOG_ONLY === 'true') ?? false;
  const apiPrefix     = options.apiPathPrefix || '/api';

  const csrfPaths    = new Set(options.csrfProtectedPaths   || []);
  const sfPaths      = new Map(
    (options.sessionFixationPaths || []).map(p => [p, `session fixation path accessed: ${p}`])
  );
  const honeypotPaths = options.honeypotPaths
    ? new Set(options.honeypotPaths)
    : DEFAULT_HONEYPOT_PATHS;

  const idorChecker         = typeof options.idorChecker === 'function' ? options.idorChecker : null;
  const ddosThreshold       = options.ddosThreshold       || 20;
  const ddosWindowMs        = options.ddosWindowMs        || 10_000;
  const bruteForceThreshold = options.bruteForceThreshold || 5;
  const bfWindowMs          = options.bruteForceWindowMs  || 60_000;

  const COLLECTOR = parseCollectorUrl(collectorUrl);

  // ── Internal state ─────────────────────────────────────────────────────────
  const blockedIPs          = new Set();
  const blockedFingerprints = new Set();
  const requestTracker      = new Map(); // ip → [timestamps]
  const loginFailTracker    = new Map(); // ip → [timestamps]

  console.log(`[ShieldWatch] ✅ Sensor initialized — app: "${appId}" | collector: ${collectorUrl} | mode: ${logOnly ? 'LOG_ONLY' : 'BLOCKING'}`);

  // ── Startup connectivity check — pings Cerebro 3 s after boot ─────────────
  let _cerebroReachable = false;
  setTimeout(() => {
    const mod_ = COLLECTOR.useHttps ? https : http;
    const r = mod_.request(
      { hostname: COLLECTOR.host, port: COLLECTOR.port, path: '/api/events', method: 'GET', timeout: 3000 },
      res => {
        _cerebroReachable = true;
        console.log(`[ShieldWatch] 🟢 Cerebro reachable at ${collectorUrl} (HTTP ${res.statusCode})`);
        res.resume();
      }
    );
    r.on('error', err => {
      console.error(`[ShieldWatch] 🔴 Cannot reach Cerebro at ${collectorUrl} — ${err.message}`);
      console.error(`[ShieldWatch]    ↳ Check SW_CEREBRO_URL in ecosystem.config.js and restart with --update-env`);
    });
    r.on('timeout', () => { r.destroy(); console.error(`[ShieldWatch] 🔴 Cerebro ping timed out at ${collectorUrl}`); });
    r.end();
  }, 3000);

  // ── HTTP reporter — fail-open: if Cerebro is down, app keeps running ───────
  function report(endpoint, payload) {
    const body = JSON.stringify(payload);
    const mod_ = COLLECTOR.useHttps ? https : http;
    const opts = {
      hostname: COLLECTOR.host, port: COLLECTOR.port,
      path: endpoint, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 4000,
    };
    const r = mod_.request(opts, res => { res.resume(); });
    r.on('error', err => {
      // Log once if Cerebro was never reachable to help diagnose misconfiguration
      if (!_cerebroReachable) {
        console.error(`[ShieldWatch] ⚠️  Event lost — Cerebro unreachable (${collectorUrl}): ${err.message}`);
      }
    });
    r.on('timeout', () => r.destroy());
    r.write(body); r.end();
  }

  function buildEvent(req, threat, verdict) {
    return {
      id:        crypto.randomUUID(),
      app:       appId,
      timestamp: new Date().toISOString(),
      ip:        getIP(req),
      method:    req.method,
      path:      req.path || req.url || '/',
      ua:        req.headers['user-agent'] || '',
      threat,
      verdict,
      session:   req.session?.username || 'anonymous',
    };
  }

  // ── Blocklist sync (every 30 s) ────────────────────────────────────────────
  function syncBlocklist(path, target, label) {
    const mod_ = COLLECTOR.useHttps ? https : http;
    const opts = { hostname: COLLECTOR.host, port: COLLECTOR.port, path, method: 'GET', timeout: 4000 };
    const r = mod_.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const list = JSON.parse(data);
          target.clear();
          list.forEach(v => target.add(v));
          if (list.length > 0) console.log(`[ShieldWatch] 🔄 ${label} synced: ${list.length} entries`);
        } catch {}
      });
    });
    r.on('error', err => console.error(`[ShieldWatch] ⚠️  Blocklist sync failed (${collectorUrl}): ${err.message}`));
    r.on('timeout', () => r.destroy()); r.end();
  }

  syncBlocklist('/api/blocked',    blockedIPs,          'IP blocklist');
  syncBlocklist('/api/blocked-fp', blockedFingerprints, 'Fingerprint blocklist');
  const _syncInterval = setInterval(() => {
    syncBlocklist('/api/blocked',    blockedIPs,          'IP blocklist');
    syncBlocklist('/api/blocked-fp', blockedFingerprints, 'Fingerprint blocklist');
  }, 30_000).unref(); // unref: don't keep the process alive if nothing else is running

  // Purge stale DDoS tracker entries
  const _purgeInterval = setInterval(() => {
    const cutoff = Date.now() - ddosWindowMs;
    for (const [ip, times] of requestTracker) {
      const fresh = times.filter(t => t > cutoff);
      if (!fresh.length) requestTracker.delete(ip);
      else requestTracker.set(ip, fresh);
    }
  }, 30_000).unref(); // unref: don't keep the process alive if nothing else is running

  // ── Individual threat checks ───────────────────────────────────────────────
  function checkDDoS(ip, rawPath) {
    if (!rawPath.startsWith(apiPrefix)) return null;
    const now  = Date.now();
    const prev = (requestTracker.get(ip) || []).filter(t => now - t < ddosWindowMs);
    prev.push(now);
    requestTracker.set(ip, prev);
    if (prev.length > ddosThreshold) {
      return { type: 'ddos', matched: `>${ddosThreshold} req/${ddosWindowMs / 1000}s`, raw: `${prev.length} requests in ${ddosWindowMs / 1000}s from ${ip}` };
    }
    return null;
  }

  function checkCSRF(req, rawPath) {
    if (!csrfPaths.has(rawPath)) return null;
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return null;
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
      return {
        type:    'csrf',
        matched: 'form-encoded POST to CSRF-protected endpoint',
        raw:     `${req.method} ${rawPath} | Origin: ${req.headers['origin'] || 'none'}`,
      };
    }
    return null;
  }

  function checkSessionFixation(rawPath) {
    const desc = sfPaths.get(rawPath);
    if (!desc) return null;
    return { type: 'sessionFixation', matched: desc, raw: rawPath };
  }

  // ── The Express middleware ─────────────────────────────────────────────────
  function middleware(req, res, next) {
    const rawPath = (req.path || req.url || '/').split('?')[0];
    const ip      = getIP(req);

    // 1. Blocked IP
    if (blockedIPs.has(ip)) {
      console.log(`[ShieldWatch] 🚫 BLOCKED IP: ${ip} → ${rawPath}`);
      return res.status(403).json({ ok: false, blocked: true, error: `IP ${ip} blocked by ShieldWatch.`, threat: 'blocked_ip' });
    }

    // 2. Blocked fingerprint (survives VPN / IP rotation)
    const fpId = req.session?.fpId;
    if (fpId && blockedFingerprints.has(fpId)) {
      console.log(`[ShieldWatch] 🔒 BLOCKED FP: ${fpId.slice(0, 12)}… | ip: ${ip}`);
      return res.status(403).json({ ok: false, blocked: true, error: 'Device blocked by ShieldWatch. Changing IP will not help.', threat: 'blocked_fingerprint' });
    }

    // 3. IDOR (custom checker from app config)
    if (idorChecker) {
      const t = idorChecker(req);
      if (t) {
        const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
        const event   = buildEvent(req, t, verdict);
        console.log(`[ShieldWatch] 🔓 IDOR | ${rawPath} | ${verdict}`);
        report('/api/event', event);
        if (!logOnly) return res.status(403).json({ ok: false, blocked: true, error: 'IDOR attack blocked by ShieldWatch.', threat: 'idor', ref: event.id });
      }
    }

    // 4. Session Fixation
    const sfThreat = checkSessionFixation(rawPath);
    if (sfThreat) {
      const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, sfThreat, verdict);
      console.log(`[ShieldWatch] 🔑 SESSION FIXATION | ${rawPath} | ${verdict}`);
      report('/api/event', event);
      if (!logOnly) return res.status(403).json({ ok: false, blocked: true, error: 'Session fixation blocked by ShieldWatch.', threat: 'sessionFixation', ref: event.id });
    }

    // 5. CSRF
    const csrfThreat = checkCSRF(req, rawPath);
    if (csrfThreat) {
      const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, csrfThreat, verdict);
      console.log(`[ShieldWatch] 🎭 CSRF | ${req.method} ${rawPath} | ${verdict}`);
      report('/api/event', event);
      if (!logOnly) return res.status(403).json({ ok: false, blocked: true, error: 'CSRF attack blocked by ShieldWatch.', threat: 'csrf', ref: event.id });
    }

    // 6. DDoS / flood
    const floodThreat = checkDDoS(ip, rawPath);
    if (floodThreat) {
      const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, floodThreat, verdict);
      console.log(`[ShieldWatch] 🌊 DDOS | ${ip} | ${floodThreat.raw} | ${verdict}`);
      report('/api/event', event);
      if (!logOnly) return res.status(429).json({ ok: false, blocked: true, error: 'DDoS flood detected and blocked by ShieldWatch.', threat: 'ddos', ref: event.id });
    }

    // 7. Honeypot
    if (honeypotPaths.has(rawPath)) {
      const event = buildEvent(req, { type: 'honeypot', raw: rawPath }, 'DECOY');
      console.log(`[ShieldWatch] 🍯 HONEYPOT: ${rawPath} | user: ${event.session} | ip: ${ip}`);
      report('/api/event', event);
      req._swHoneypot = true;
      return next();
    }

    // 8. Pattern scan (SQLi, XSS, Path Traversal, Command Injection, SSRF, CRLF)
    const threat = scanRequest(req);
    if (!threat) return next();

    const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, threat, verdict);
    console.log(`[ShieldWatch] 🚨 ${threat.type.toUpperCase()} | ${req.method} ${rawPath} | ${verdict} | user: ${event.session} | ip: ${ip}`);
    report('/api/event', event);

    if (logOnly) return next();
    return res.status(403).json({ ok: false, blocked: true, error: 'Request blocked by ShieldWatch RASP.', threat: threat.type, ref: event.id });
  }

  // ── Socket.io message hook ─────────────────────────────────────────────────
  // Call this inside your socket.on('message') handler.
  // Returns the threat if the message should be blocked, null if clean.
  function inspectMessage(msg, socket) {
    const text   = typeof msg === 'string' ? msg : msg?.text || '';
    const threat = detectThreats(text);
    if (!threat) return null;

    const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
    const event = {
      id:        crypto.randomUUID(),
      app:       appId,
      timestamp: new Date().toISOString(),
      ip:        socket.handshake?.address || '127.0.0.1',
      method:    'WS',
      path:      '/socket/message',
      ua:        socket.handshake?.headers?.['user-agent'] || '',
      threat, verdict,
      session:   (typeof msg === 'object' ? msg.username : null) || 'unknown',
    };
    console.log(`[ShieldWatch] 🚨 WS ${threat.type.toUpperCase()} | ${verdict}`);
    report('/api/event', event);
    return logOnly ? null : threat;
  }

  // ── Brute force tracker ────────────────────────────────────────────────────
  // Call this on every failed login attempt.
  // Returns true when the IP should be blocked (>= threshold in window).
  function trackLoginFailure(req) {
    const ip  = getIP(req);
    const now = Date.now();
    const prev = (loginFailTracker.get(ip) || []).filter(t => now - t < bfWindowMs);
    prev.push(now);
    loginFailTracker.set(ip, prev);

    if (prev.length >= bruteForceThreshold) {
      const threat  = { type: 'bruteforce', matched: `>=${bruteForceThreshold} failed logins/${bfWindowMs / 1000}s`, raw: `${prev.length} failures from ${ip}` };
      const verdict = logOnly ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, threat, verdict);
      console.log(`[ShieldWatch] 🔐 BRUTE FORCE | ${ip} | ${prev.length} failures | ${verdict}`);
      report('/api/event', event);
      return !logOnly;
    }
    return false;
  }

  // ── Fingerprint forwarding ─────────────────────────────────────────────────
  function submitFingerprint(fingerprintData, req) {
    report('/api/fingerprint', {
      session:     req.session?.username || 'anonymous',
      ip:          getIP(req),
      fingerprint: fingerprintData,
    });
  }

  // ── Manual honeypot trigger ────────────────────────────────────────────────
  function honeypotHit(path, req) {
    const event = buildEvent(req, { type: 'honeypot', raw: path }, 'DECOY');
    console.log(`[ShieldWatch] 🍯 Manual honeypot: ${path}`);
    report('/api/event', event);
  }

  // ── Expose the public API ──────────────────────────────────────────────────
  return {
    middleware,           // Express middleware: app.use(sw.middleware)
    inspectMessage,       // WebSocket hook:     if (sw.inspectMessage(msg, socket)) return;
    detectThreats,        // Pure scan function: sw.detectThreats(string)
    trackLoginFailure,    // Login hook:         if (sw.trackLoginFailure(req)) return 429
    submitFingerprint,    // Fingerprint:        sw.submitFingerprint(data, req)
    honeypotHit,          // Manual honeypot:    sw.honeypotHit('/path', req)
    // Aliases for backwards compatibility
    httpMiddleware: middleware,
  };
}

module.exports = { create, detectThreats };
