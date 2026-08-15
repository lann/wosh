#!/usr/bin/env bash
# Assemble the static site into a directory any file server can serve.
#
# The tree is self-contained: page, modules, xterm assets, the deltic
# bundle, the deltic translator, and the composed client component. The
# .wasm shipped here is byte-for-byte the one the native gates run --
# deltic is a runtime linker, so there is no transpiled variant to drift.
#
#   scripts/site-deploy-tree.sh out/
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

dest="${1:?usage: scripts/site-deploy-tree.sh <dest-dir>}"
mkdir -p "$dest/xterm" "$dest/dist" "$dest/icons" "$dest/vendor"

bundle="$ROOT/site/dist/deltic.js"
client="$ROOT/target/components/wosh-ssh-client.wasm"
translator="$ROOT/.deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm"

for f in "$bundle" "$client" "$translator"; do
  [ -f "$f" ] || { echo "missing $f -- run: just web-bundle compose" >&2; exit 1; }
done

cp site/index.html site/app.mjs site/boot.mjs site/overlay.mjs site/mobile.mjs \
   site/lifecycle.mjs site/links.mjs site/separator.mjs site/qr.mjs "$dest/"
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
  cp "$XTERM/jsqr/dist/jsQR.js"               "$dest/vendor/jsqr.js"
else
  echo "note: site/node_modules missing; run 'npm install' in site/ for xterm + jsQR assets" >&2
fi

cp "$bundle"     "$dest/dist/deltic.js"
cp "$client"     "$dest/dist/wosh-ssh-client.wasm"
cp "$translator" "$dest/dist/deltic-translator-shim.wasm"

# The service worker's precache manifest is generated FROM the assembled
# tree, so it cannot drift from what actually ships: a new file is
# picked up here without anyone editing sw.js. The version keys the
# cache, so one deploy is one complete cache and a client can never mix
# files from two deploys -- load-bearing, because deltic runtime-links
# the wasm against the page bundle.
version="${WOSH_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || date +%s)}"
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
