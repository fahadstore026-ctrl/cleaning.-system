// public/sw.js
const CACHE_NAME = 'cleaning-system-v1';
const ASSETS = ['/', '/index.html'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS)));
});

self.addEventListener('fetch', e => {
  if (e.request.url.includes('/api')) return; // لا تخزن طلبات API
  e.respondWith(
    caches.match(e.request).then(res => res || fetch(e.request).catch(() => caches.match('/index.html')))
  );
});