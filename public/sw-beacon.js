/**
 * ShieldWatch Silent Beacon
 * ─────────────────────────────────────────────────────────────────────────────
 * Injected into every NexaChat page. Silently collects browser fingerprint
 * and sends it to the ShieldWatch sensor. Fails silently if anything errors.
 *
 * Data collected: browser, OS, screen, timezone, language, GPU, CPU cores,
 *                 device memory, touch capability, canvas hash.
 * ─────────────────────────────────────────────────────────────────────────────
 */
(function () {
  'use strict';

  // ── Wait 1.5s after page load so it doesn't slow the UI ──
  function run() {
    var fp = {};

    // Basic navigator info
    fp.ua        = navigator.userAgent        || '';
    fp.platform  = navigator.platform         || '';
    fp.language  = navigator.language         || '';
    fp.languages = (navigator.languages || []).join(',');
    fp.cores     = navigator.hardwareConcurrency || null;
    fp.memory    = navigator.deviceMemory        || null;
    fp.touch     = navigator.maxTouchPoints > 0;
    fp.cookie    = navigator.cookieEnabled;
    fp.dnt       = navigator.doNotTrack;

    // Screen
    fp.screen      = screen.width + 'x' + screen.height;
    fp.colorDepth  = screen.colorDepth;
    fp.pixelRatio  = window.devicePixelRatio || 1;

    // Timezone
    try { fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) {}
    fp.tzOffset = new Date().getTimezoneOffset();

    // Parse OS + browser from UA
    var ua = fp.ua;
    fp.os      = 'Unknown';
    fp.browser = 'Unknown';

    if (/Windows NT 10|Windows NT 11/.test(ua))        fp.os = 'Windows 11/10';
    else if (/Windows NT 6\.1/.test(ua))               fp.os = 'Windows 7';
    else if (/Mac OS X/.test(ua))                      fp.os = 'macOS';
    else if (/Android ([0-9.]+)/.test(ua))             fp.os = 'Android ' + RegExp.$1;
    else if (/iPhone|iPad/.test(ua))                   fp.os = 'iOS';
    else if (/Linux/.test(ua))                         fp.os = 'Linux';

    var edge = ua.match(/Edg\/([0-9]+)/);
    var chr  = ua.match(/Chrome\/([0-9]+)/);
    var ff   = ua.match(/Firefox\/([0-9]+)/);
    var saf  = ua.match(/Version\/([0-9]+).+Safari/);

    if (edge)      fp.browser = 'Edge '    + edge[1];
    else if (chr)  fp.browser = 'Chrome '  + chr[1];
    else if (ff)   fp.browser = 'Firefox ' + ff[1];
    else if (saf)  fp.browser = 'Safari '  + saf[1];

    // GPU via WebGL
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          fp.gpu = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
          fp.gpuVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
        }
      }
    } catch (e) {}

    // Canvas fingerprint (unique per browser/font combination)
    try {
      var c2 = document.createElement('canvas');
      c2.width = 200; c2.height = 40;
      var ctx2 = c2.getContext('2d');
      ctx2.textBaseline = 'top';
      ctx2.font = '14px Arial';
      ctx2.fillStyle = '#f60';
      ctx2.fillRect(125, 1, 62, 20);
      ctx2.fillStyle = '#069';
      ctx2.fillText('ShieldWatch🔒', 2, 15);
      ctx2.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx2.fillText('ShieldWatch🔒', 4, 17);
      fp.canvasHash = c2.toDataURL().slice(-32); // last 32 chars as fingerprint
    } catch (e) {}

    // ── Stable device ID — hardware signals, not rendering ───────────────────
    // Combines platform, CPU cores, RAM, screen, GPU into one compact hash.
    // Stays constant across browser switches, VPN rotations, cookie clears.
    // On a Mac: MacIntel/MacARM + core count + RAM + Retina res + GPU model.
    (function buildDeviceId() {
      var hwParts = [
        fp.platform   || '',   // "MacIntel" / "MacARM" / "Win32" / "Linux x86_64"
        fp.cores      || '',   // CPU logical cores (e.g. 10 for M3 Pro)
        fp.memory     || '',   // Device RAM in GB (e.g. 16)
        fp.screen     || '',   // e.g. "2560x1600"
        fp.pixelRatio || '',   // e.g. 2 for Retina
        fp.colorDepth || '',   // e.g. 30
        fp.gpu        || '',   // e.g. "Apple M3 Pro"
        fp.gpuVendor  || ''    // e.g. "Apple"
      ];
      var raw = hwParts.join('|');
      // FNV-1a 32-bit hash → compact 8-char hex device fingerprint
      var h = 0x811c9dc5;
      for (var i = 0; i < raw.length; i++) {
        h ^= raw.charCodeAt(i);
        h  = Math.imul(h, 0x01000193) >>> 0;
      }
      fp.deviceId  = h.toString(16).padStart(8, '0');
      fp.deviceRaw = raw; // human-readable for dashboard display
    })();

    // Current page
    fp.page = window.location.pathname;

    // Send to sensor — dispatch swFingerprintReady when done (or on error)
    // so the login gate is unlocked regardless of network outcome.
    function notifyReady() {
      window.dispatchEvent(new CustomEvent('swFingerprintReady'));
    }
    try {
      fetch('/api/sw/fingerprint', {
        method:    'POST',
        headers:   { 'Content-Type': 'application/json' },
        body:      JSON.stringify(fp),
        keepalive: true
      }).then(notifyReady).catch(notifyReady);
    } catch (e) { notifyReady(); }
  }

  // 800ms delay — fast enough to complete before the user can type credentials
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(run, 800); });
  } else {
    setTimeout(run, 800);
  }

})();
