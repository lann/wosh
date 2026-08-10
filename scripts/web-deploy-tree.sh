#!/usr/bin/env bash
# Assemble the deployable static tree of the web client into <dest>
# (e.g. a checkout of lann.github.io, subdir wosh/). The
# tree is mount-point-agnostic: everything in web/ is referenced
# relatively, so it serves from / (dev) and from a pages subdir alike.
#
# Deliberately excluded:
#   - generated/ + shim/ (the jco-transpiled engine and preview2-shim):
#     only reachable after a same-origin /ws bridge hello, which static
#     hosting cannot provide — the page idles on its no-bridge path.
#   - prf-probe/ (deployed separately, own subdir on the pages site).
#   - node_modules/, package*.json (xterm assets are copied out below).
set -euo pipefail
cd "$(dirname "$0")/../web"

dest="${1:?usage: web-deploy-tree.sh <dest-dir>}"
mkdir -p "$dest/xterm"

cp index.html app.mjs boot.mjs connstring.mjs storage.mjs idb-keys.mjs prf-wrap.mjs "$dest/"
cp node_modules/@xterm/xterm/css/xterm.css "$dest/xterm/"
cp node_modules/@xterm/xterm/lib/xterm.js "$dest/xterm/"
cp node_modules/@xterm/addon-fit/lib/addon-fit.js "$dest/xterm/"

echo "web client tree -> $dest"
