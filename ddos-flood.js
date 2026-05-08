/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║          ShieldWatch — DDoS Demo Flood Script                ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  Simulates a login-endpoint flood attack (50 rapid requests) ║
 * ║                                                              ║
 * ║  Phase 1 (SW OFF):  All requests go through → server drowns  ║
 * ║  Phase 2 (SW ON):   ShieldWatch blocks after 20 req/10s      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node ddos-flood.js                                   ← hits Render
 *   node ddos-flood.js https://nexachat-aj89.onrender.com
 *   node ddos-flood.js http://localhost:3000  100        ← 100 requests
 */

const https  = require('https');
const http   = require('http');

const TARGET = process.argv[2] || 'https://nexachat-aj89.onrender.com';
const COUNT  = parseInt(process.argv[3]) || 50;

const url  = new URL('/api/login', TARGET);
const mod  = url.protocol === 'https:' ? https : http;

console.log('\n┌─────────────────────────────────────────────────┐');
console.log('│       🌊  ShieldWatch DDoS Demo Flood            │');
console.log('└─────────────────────────────────────────────────┘');
console.log(`Target  : ${url.href}`);
console.log(`Requests: ${COUNT} parallel\n`);

let done = 0, blocked429 = 0, ok200 = 0, other = 0, failed = 0;

function sendRequest(i) {
  return new Promise(resolve => {
    const body = JSON.stringify({ username: `flood_${i}`, password: 'ddos_test' });
    const opts = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Demo-Source':  'ddos-flood-script',
      },
      timeout: 8000,
    };

    const req = mod.request(opts, res => {
      res.resume();
      done++;
      if      (res.statusCode === 429) { blocked429++; process.stdout.write('🛡 '); }
      else if (res.statusCode === 200) { ok200++;      process.stdout.write('✓ ');  }
      else                             { other++;       process.stdout.write(`${res.statusCode} `); }
      resolve(res.statusCode);
    });

    req.on('error',   () => { failed++; process.stdout.write('✗ '); resolve(0); });
    req.on('timeout', () => { req.destroy(); });

    req.write(body);
    req.end();
  });
}

(async () => {
  const start = Date.now();
  await Promise.all(Array.from({ length: COUNT }, (_, i) => sendRequest(i)));
  const elapsed = ((Date.now() - start) / 1000).toFixed(2);

  console.log('\n\n┌─────────────────────────────────────────────────┐');
  console.log('│                  📊 Results                      │');
  console.log('├─────────────────────────────────────────────────┤');
  console.log(`│  Total sent   : ${String(COUNT).padEnd(31)}│`);
  console.log(`│  ✓  Passed    : ${String(ok200).padEnd(31)}│`);
  console.log(`│  🛡  Blocked   : ${String(blocked429).padEnd(30)}│`);
  console.log(`│  ?  Other     : ${String(other).padEnd(31)}│`);
  console.log(`│  ✗  Failed    : ${String(failed).padEnd(31)}│`);
  console.log(`│  ⏱  Time      : ${String(elapsed + 's').padEnd(31)}│`);
  console.log('└─────────────────────────────────────────────────┘');

  if (blocked429 > 0) {
    console.log('\n✅  ShieldWatch DDoS protection is ACTIVE');
    console.log(`    Blocked ${blocked429}/${COUNT} flood requests (429 Too Many Requests)\n`);
  } else if (ok200 > 0) {
    console.log('\n⚠️   ShieldWatch is OFF — all requests went through unprotected');
    console.log('    Enable SW_ENABLED=true on Render and re-run to see blocking\n');
  } else {
    console.log('\n❓  Unexpected results — check the target URL is correct\n');
  }
})();
