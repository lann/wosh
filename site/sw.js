// irsh service worker: version-keyed atomic precache of the whole site.
//
// Caching earns its place here more than in most PWAs: the tree ships
// the composed SSH client component (~8.6 MB) and deltic's translator
// (~3.8 MB), so a warm visit avoids re-fetching about twelve megabytes.
//
// Coherence is the design constraint. The page is runtime-linked at
// load -- deltic resolves the composed wasm against the page bundle --
// so a cache that mixes files from two deploys is a subtle-breakage
// generator. Hence: a version's cache is complete before it serves
// anything (addAll on install), lookups are cache-first WITHIN that
// version, and misses fall through to the network WITHOUT being cached
// (an uncached file can be slow, never incoherent).
//
// The two placeholders are injected by scripts/site-deploy-tree.sh when
// the deploy tree is assembled:
//   __IRSH_VERSION__   -- deploy identity (commit SHA); names the cache.
//   __IRSH_PRECACHE__  -- JSON array of every file in the tree.
// The raw site/ dir keeps the placeholders, and registration is
// https-gated in index.html, so local serving over http never installs
// this and cannot confuse development or the browser gate.

const VERSION = "__IRSH_VERSION__";
const PRECACHE = __IRSH_PRECACHE__;
const CACHE = `irsh-${VERSION}`;

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
        Promise.all(
          keys.filter((k) => k.startsWith("irsh-") && k !== CACHE).map((k) => caches.delete(k)),
        ),
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
