/**
 * PM2 Ecosystem File — NexaChat (AWS EC2)
 *
 * USAGE:
 *   pm2 start ecosystem.config.js
 *   pm2 save
 *
 * UPDATE after a code change:
 *   cd ~/nexachat && git pull && pm2 restart nexachat
 */

module.exports = {
  apps: [{
    name:   'nexachat',
    script: 'server.js',

    env: {
      NODE_ENV:       'production',
      PORT:           '3001',

      // Change this to a strong random string
      SESSION_SECRET: 'nexachat-prod-change-me-2024',

      // ── ShieldWatch ──────────────────────────────────────────────────────
      // SW_ENABLED: 'true'  → sensor active, attacks blocked, events sent to Cerebro
      // SW_ENABLED: 'false' → sensor off, all vulnerabilities exposed (use for demo contrast)
      //
      // SW_CEREBRO_URL: the address where your Cerebro dashboard is reachable from this server.
      // If Cerebro is on your laptop, you need a tunnel so EC2 can reach it.
      // If Cerebro is on another server with a public IP, paste that IP:port here.
      SW_ENABLED:     'true',
      SW_CEREBRO_URL: 'http://localhost:3002',
      SW_APP_ID:      'nexachat-ec2',
      SW_LOG_ONLY:    'false',
    }
  }]
};
