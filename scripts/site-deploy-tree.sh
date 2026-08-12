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
mkdir -p "$dest/xterm" "$dest/dist"

bundle="$ROOT/site/dist/deltic.js"
client="$ROOT/target/components/irsh-ssh-client.wasm"
translator="$ROOT/.deps/deltic/target/wasm32-unknown-unknown/release/translator_shim.wasm"

for f in "$bundle" "$client" "$translator"; do
  [ -f "$f" ] || { echo "missing $f -- run: just web-bundle compose" >&2; exit 1; }
done

cp site/index.html site/app.mjs site/boot.mjs site/overlay.mjs site/mobile.mjs "$dest/"

# xterm ships as npm packages; copy the three files the page loads.
XTERM="$ROOT/site/node_modules"
if [ -d "$XTERM" ]; then
  cp "$XTERM/@xterm/xterm/css/xterm.css"      "$dest/xterm/"
  cp "$XTERM/@xterm/xterm/lib/xterm.js"       "$dest/xterm/"
  cp "$XTERM/@xterm/addon-fit/lib/addon-fit.js" "$dest/xterm/"
else
  echo "note: site/node_modules missing; run 'npm install' in site/ for xterm assets" >&2
fi

cp "$bundle"     "$dest/dist/deltic.js"
cp "$client"     "$dest/dist/irsh-ssh-client.wasm"
cp "$translator" "$dest/dist/deltic-translator-shim.wasm"

echo "site tree ready: $dest"
echo "serve it with any static file server, e.g.:  python3 -m http.server -d $dest 8080"
