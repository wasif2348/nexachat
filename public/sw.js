/* NexaChat Service Worker
 * Caches static assets for faster loads.
 * Socket.io and API calls always go to the network.
 */

const CACHE_NAME = 'nexachat-v1';
const STATIC_ASSETS = [
  '/chat.css',
  '/chat.js',
  '/login.css',
  '/login.js',
  '/sw-beacon.js',
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
});

self.addEventListener('activate', event => {
  // Remove old caches
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Never intercept socket.io, API calls, or non-GET requests
  if (
    event.request.method !== 'GET' ||
    url.pathname.startsWith('/socket.io') ||
    url.pathname.startsWith('/api/')
  ) {
    return;
  }

  // For static assets: cache-first strategy
  event.respondWith(
    caches.match(event.request).then(cached => cached || fetch(event.request))
  );
});
