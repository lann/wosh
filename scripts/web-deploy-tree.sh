#!/usr/bin/env bash
# Assemble the deployable static tree of the web client into <dest>
# (the Pages workflow's _site, or any static-host dir). The
# tree is mount-point-agnostic: everything in web/ is referenced
# relatively, so it serves from / (dev) and from a pages subdir alike.
#
# The static tree carries the REAL client: the deltic page bundle plus
# the composed client component and the translator shim under dist/ —
# a QR/fragment connect works from plain static hosting (relay +
# WebRTC paths; no dev bridge, so the M2 bridge mode simply idles).
#
# Deliberately excluded:
#   - dist/main.wasm (the bare engine): only reachable through the
#     same-origin /ws dev bridge, which static hosting cannot provide.
#   - prf-probe/ (deployed separately, own subdir on the pages site).
#   - node_modules/, package*.json (xterm assets are copied out below).
set -euo pipefail
cd "$(dirname "$0")/../web"

dest="${1:?usage: web-deploy-tree.sh <dest-dir>}"

bundle=dist/deltic.js
client=../client-core/composed-client.wasm
translator=../.deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm
for f in "$bundle" "$client" "$translator"; do
  [ -f "$f" ] || { echo "missing $f — run: just web-bundle compose-client (and scripts/setup.sh for the translator)" >&2; exit 1; }
done

mkdir -p "$dest/xterm" "$dest/dist" "$dest/icons"

cp index.html app.mjs boot.mjs connstring.mjs storage.mjs idb-keys.mjs prf-wrap.mjs passkey.mjs overlay.mjs mobile.mjs "$dest/"
cp manifest.json "$dest/"
cp icons/*.png "$dest/icons/"
cp node_modules/@xterm/xterm/css/xterm.css "$dest/xterm/"
cp node_modules/@xterm/xterm/lib/xterm.js "$dest/xterm/"
cp node_modules/@xterm/addon-fit/lib/addon-fit.js "$dest/xterm/"
cp "$bundle" "$dest/dist/"
cp "$client" "$dest/dist/composed-client.wasm"
cp "$translator" "$dest/dist/deltic-translator-shim.wasm"

# PWA service worker (issue #10): the precache manifest is generated
# FROM the assembled tree, so it can never drift from what ships — new
# files (from any branch) are picked up here without touching sw.js.
# The version keys the cache: one deploy = one complete cache, so a
# client can never mix files from two deploys (deltic runtime-links the
# wasm set against the page bundle; coherency is load-bearing).
version="${WOSH_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || date +%s)}"
files=$(cd "$dest" && find . -type f ! -name sw.js | LC_ALL=C sort | sed 's|^\./||')
precache=$(printf '"%s",' $files)
precache="[${precache%,}]"
sed -e "s|__WOSH_VERSION__|$version|" -e "s|__WOSH_PRECACHE__|$precache|" sw.js > "$dest/sw.js"

echo "web client tree -> $dest (sw version $version, $(wc -w <<<"$files") precached)"
