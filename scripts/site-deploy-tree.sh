#!/usr/bin/env bash
# Assemble the static site into a directory any file server can serve.
#
# The tree is self-contained: page, modules, xterm assets, the polyengine
# bundle, the polyengine translator, and the composed client component. The
# .wasm shipped here is byte-for-byte the one the native gates run --
# polyengine is a runtime linker, so there is no transpiled variant to drift.
#
#   scripts/site-deploy-tree.sh out/
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

dest="${1:?usage: scripts/site-deploy-tree.sh <dest-dir>}"
mkdir -p "$dest/xterm" "$dest/dist" "$dest/icons" "$dest/vendor"

bundle="$ROOT/site/dist/polyengine.js"
client="$ROOT/target/components/wosh-ssh-client.wasm"

# The translator wasm ships INSIDE the @polyengine/translator release -- the
# versioned peer of the @polyengine/runtime the bundle pins (deno.json), so
# the two cannot skew. Fetched once from jsr, digest-pinned, cached
# under .deps/. Bump TRANSLATOR_VERSION together with the deno.json pins.
TRANSLATOR_VERSION=0.5.0
TRANSLATOR_SHA256=034747e0bd2961b002174734f7d1f47b9c1e59f7864a3a0d566070940be873a0
translator="$ROOT/.deps/translator_shim-$TRANSLATOR_VERSION.wasm"
if ! sha256sum -c --status <<<"$TRANSLATOR_SHA256  $translator" 2>/dev/null; then
  mkdir -p "$ROOT/.deps"
  curl -fsSL -o "$translator" \
    "https://jsr.io/@polyengine/translator/$TRANSLATOR_VERSION/translator_shim.wasm"
  sha256sum -c --status <<<"$TRANSLATOR_SHA256  $translator" || {
    echo "translator_shim.wasm digest mismatch (expected $TRANSLATOR_SHA256)" >&2
    exit 1
  }
fi

for f in "$bundle" "$client"; do
  [ -f "$f" ] || { echo "missing $f -- run: just web-bundle compose" >&2; exit 1; }
done

cp site/index.html site/app.mjs site/boot.mjs site/overlay.mjs site/mobile.mjs \
   site/lifecycle.mjs site/links.mjs site/separator.mjs site/qr.mjs \
   site/touch-select.mjs site/esc-watch.mjs \
   site/buffer-store.mjs site/sessions.mjs site/authorized-keys.mjs \
   site/transfer-ui.mjs site/transfer-worker.mjs "$dest/"
cp site/manifest.json "$dest/"
cp site/icons/*.png "$dest/icons/"

# xterm ships as npm packages; copy the files the page loads.
# jsQR rides along from the same place: it is the QR fallback for the
# browsers without a native BarcodeDetector (iOS Safari, Firefox), and
# site/qr.mjs fetches it by this path, only when it needs it.
XTERM="$ROOT/site/node_modules"
if [ -d "$XTERM" ]; then
  cp "$XTERM/@xterm/xterm/css/xterm.css"      "$dest/xterm/"
  cp "$XTERM/@xterm/xterm/lib/xterm.js"       "$dest/xterm/"
  cp "$XTERM/@xterm/addon-fit/lib/addon-fit.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-unicode11/lib/addon-unicode11.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-clipboard/lib/addon-clipboard.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-web-links/lib/addon-web-links.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-image/lib/addon-image.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-webgl/lib/addon-webgl.js" "$dest/xterm/"
  cp "$XTERM/@xterm/addon-serialize/lib/addon-serialize.js" "$dest/xterm/"
  cp "$XTERM/jsqr/dist/jsQR.js"               "$dest/vendor/jsqr.js"
else
  echo "note: site/node_modules missing; run 'npm install' in site/ for xterm + jsQR assets" >&2
fi

cp "$bundle"     "$dest/dist/polyengine.js"
cp "$client"     "$dest/dist/wosh-ssh-client.wasm"
cp "$translator" "$dest/dist/polyengine-translator-shim.wasm"

# The service worker's precache manifest is generated FROM the assembled
# tree, so it cannot drift from what actually ships: a new file is
# picked up here without anyone editing sw.js. The version keys the
# cache, so one deploy is one complete cache and a client can never mix
# files from two deploys -- load-bearing, because polyengine runtime-links
# the wasm against the page bundle.
version="${WOSH_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || date +%s)}"
# The build number is the commit count: deterministic from the commit
# alone (the same commit always numbers the same, deployed from
# anywhere), monotonic along main, and zero CI state involved. The
# pages workflow fetches full history so this is right in CI too.
build="${WOSH_BUILD:-$(git rev-list --count HEAD 2>/dev/null || echo 0)}"

# The page shows its own deploy identity (home/settings footers):
# "build N (hash)", where hash is the SAME version string that keys
# the cache below. Substituted here so the raw site/ tree keeps its
# placeholders (which boot.mjs renders as a dev build).
sed -e "s|__WOSH_VERSION__|$version|" -e "s|__WOSH_BUILD__|$build|" \
    site/index.html > "$dest/index.html"
if grep -q '__WOSH_' "$dest/index.html"; then
  echo "index.html still contains unreplaced placeholders" >&2
  exit 1
fi

files=$(cd "$dest" && find . -type f ! -name sw.js | LC_ALL=C sort | sed 's|^\./||')
precache=$(printf '"%s",' $files)
precache="[${precache%,}]"
sed -e "s|__WOSH_VERSION__|$version|" -e "s|__WOSH_PRECACHE__|$precache|" site/sw.js > "$dest/sw.js"

if grep -q '__WOSH_' "$dest/sw.js"; then
  echo "sw.js still contains unreplaced placeholders" >&2
  exit 1
fi

echo "site tree ready: $dest (sw version $version, $(wc -w <<<"$files") files precached)"
echo "serve it with any static file server, e.g.:  python3 -m http.server -d $dest 8080"
