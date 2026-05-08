/**
 * ShieldWatch RASP Sensor — NexaChat Integration v2
 * ─────────────────────────────────────────────────────────────────────────────
 * Environment variables:
 *
 *   SW_ENABLED=true
 *   SW_CEREBRO_ADDR=abc123.ngrok-free.app     ← ngrok HTTP tunnel (no port)
 *                OR localhost:3002             ← local testing
 *   SW_APP_ID=nexachat
 *   SW_LOG_ONLY=false   (true = detect but never block — passive mode)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

const RAW_ADDR  = process.env.SW_CEREBRO_ADDR || 'localhost:3002';
const APP_ID    = process.env.SW_APP_ID       || 'nexachat';
const LOG_ONLY  = process.env.SW_LOG_ONLY === 'true';

// ─── Parse the collector address ──────────────────────────────────────────────
// Supports:
//   localhost:3002          → http, port 3002
//   abc123.ngrok-free.app  → https, port 443  (ngrok HTTP tunnel)
//   0.tcp.ngrok.io:12345   → http, port 12345 (ngrok TCP tunnel)
function parseAddr(addr) {
  if (addr.includes(':')) {
    const [host, portStr] = addr.split(':');
    return { host, port: parseInt(portStr, 10), useHttps: false };
  }
  // No port = ngrok HTTPS domain
  return { host: addr, port: 443, useHttps: true };
}

const COLLECTOR = parseAddr(RAW_ADDR);

// ─── Honeypot paths ──────────────────────────────────────────────────────────
const HONEYPOT_PATHS = new Set([
  '/api/admin/users', '/api/admin/config', '/api/export',
  '/api/export/database', '/api/backup', '/api/db-dump',
  '/api/config', '/api/secret', '/admin', '/phpmyadmin',
  '/wp-admin', '/.env',
]);

// ─── Attack Patterns ─────────────────────────────────────────────────────────
const PATTERNS = {
  sqli: [
    /'\s*(--|#|\/\*)/i,
    /'\s*(OR|AND)\s+['"\d]/i,
    /\bunion\b.+\bselect\b/i,
    /\bselect\b.+\bfrom\b/i,
    /\bdrop\s+table\b/i,
    /\binsert\s+into\b/i,
    /'\s*=\s*'/i,
    /;\s*(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE)\b/i,
    /\bsleep\s*\(/i,
    /\bwaitfor\s+delay\b/i,
  ],
  xss: [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /on\w+\s*=\s*['"`]/i,
    /<img[^>]+onerror/i,
    /<iframe[\s>]/i,
    /\balert\s*\(/i,
    /document\.cookie/i,
    /eval\s*\(/i,
    /<svg[^>]+on\w+/i,
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
  ],
  cmdInjection: [
    /[;&|`$]\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
  ],
};

// ─── Detect threat ────────────────────────────────────────────────────────────
function detectThreats(value) {
  if (value == null || typeof value !== 'string') return null;
  let decoded = value;
  try { decoded = decodeURIComponent(value); } catch {}

  for (const [type, patterns] of Object.entries(PATTERNS)) {
    for (const re of patterns) {
      if (re.test(value) || re.test(decoded)) {
        return { type, matched: re.toString(), raw: value.slice(0, 200) };
      }
    }
  }
  return null;
}

// ─── Scan request inputs ──────────────────────────────────────────────────────
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

// ─── Send to ShieldWatch Collector ───────────────────────────────────────────
// Non-blocking, fail-open — if ShieldWatch is down NexaChat keeps running
function report(endpoint, payload) {
  const body    = JSON.stringify(payload);
  const module_ = COLLECTOR.useHttps ? https : http;

  const options = {
    hostname: COLLECTOR.host,
    port:     COLLECTOR.port,
    path:     endpoint,
    method:   'POST',
    headers:  {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
    timeout: 4000,
  };

  const req = module_.request(options, res => { res.resume(); });
  req.on('error',   () => {}); // fail open
  req.on('timeout', () => req.destroy());
  req.write(body);
  req.end();
}

// ─── Build event ──────────────────────────────────────────────────────────────
function buildEvent(req, threat, verdict) {
  return {
    id:        crypto.randomUUID(),
    app:       APP_ID,
    timestamp: new Date().toISOString(),
    ip:        (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1')
               .split(',')[0].trim(),
    method:    req.method,
    path:      req.path || req.url || '/',
    ua:        req.headers['user-agent'] || '',
    threat,
    verdict,
    session:   req.session?.username || 'anonymous',
  };
}

// ─── HTTP Middleware ───────────────────────────────────────────────────────────
function httpMiddleware(req, res, next) {
  const rawPath = (req.path || req.url || '/').split('?')[0];

  // Honeypot check
  if (HONEYPOT_PATHS.has(rawPath)) {
    const event = buildEvent(req, { type: 'honeypot', raw: rawPath }, 'DECOY');
    console.log(`[ShieldWatch] 🍯 HONEYPOT: ${rawPath} | user:${event.session} | ip:${event.ip}`);
    report('/api/event', event);
    req._swHoneypot = true;
    return next(); // Let honeypot handler serve fake data
  }

  const threat = scanRequest(req);
  if (!threat) return next();

  const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
  const event   = buildEvent(req, threat, verdict);

  console.log(`[ShieldWatch] 🚨 ${threat.type.toUpperCase()} | ${req.method} ${rawPath} | ${verdict} | user:${event.session} | ip:${event.ip}`);
  report('/api/event', event);

  if (LOG_ONLY) return next();

  return res.status(403).json({
    ok: false, blocked: true,
    error:  'Request blocked by ShieldWatch RASP.',
    threat: threat.type,
    ref:    event.id,
  });
}

// ─── Socket.io Message Hook ───────────────────────────────────────────────────
function inspectMessage(msg, socket) {
  const threat = detectThreats(msg.text);
  if (!threat) return;

  const event = {
    id:        crypto.randomUUID(),
    app:       APP_ID,
    timestamp: new Date().toISOString(),
    ip:        socket.handshake?.address || '127.0.0.1',
    method:    'WS',
    path:      '/socket/chat_message',
    ua:        socket.handshake?.headers?.['user-agent'] || '',
    threat,
    verdict:   LOG_ONLY ? 'LOGGED' : 'BLOCKED',
    session:   msg.username || 'unknown',
  };

  console.log(`[ShieldWatch] 🚨 WS ${threat.type.toUpperCase()} from ${msg.username}`);
  report('/api/event', event);
}

// ─── Fingerprint Forwarding ───────────────────────────────────────────────────
function submitFingerprint(fingerprintData, req) {
  const ip      = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1')
                  .split(',')[0].trim();
  const session = req.session?.username || 'anonymous';
  report('/api/fingerprint', { session, ip, fingerprint: fingerprintData });
}

// ─── Honeypot Hit (manual) ────────────────────────────────────────────────────
function honeypotHit(path, req) {
  const event = buildEvent(req, { type: 'honeypot', raw: path }, 'DECOY');
  console.log(`[ShieldWatch] 🍯 Manual honeypot: ${path}`);
  report('/api/event', event);
}

module.exports = { httpMiddleware, inspectMessage, detectThreats, submitFingerprint, honeypotHit };
