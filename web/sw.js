// wosh service worker: version-keyed atomic precache of the whole
// client tree (issue #10). The tree is runtime-linked at load (deltic
// resolves the composed wasm against the page bundle), so a cache that
// mixes files from two deploys is a subtle-breakage generator — the
// design rule here is: a version's cache is complete before it serves
// anything (addAll on install), lookups are cache-first WITHIN that
// version, and misses fall through to the network WITHOUT being cached
// (an uncached file can be slow, never incoherent).
//
// The two placeholders are injected by scripts/web-deploy-tree.sh when
// the deploy tree is assembled (Pages or any static host):
//   __WOSH_VERSION__   — deploy identity (commit SHA); names the cache.
//   __WOSH_PRECACHE__  — JSON array of every file in the tree.
// The raw web/ dir keeps the placeholders; registration is https-gated
// in index.html, so dev serving (http://localhost) never installs this.

const VERSION = "__WOSH_VERSION__";
const PRECACHE = __WOSH_PRECACHE__;
const CACHE = `wosh-${VERSION}`;

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(["./", ...PRECACHE]))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k.startsWith("wosh-") && k !== CACHE).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin) return;
  event.respondWith(
    caches.match(event.request, { cacheName: CACHE }).then((hit) => hit ?? fetch(event.request)),
  );
});
