#!/usr/bin/env node
// Generate the PWA icons (site/icons/*.png) — a shell-prompt chevron ❯
// plus an underscore cursor block, terminal green on black, drawn
// parametrically and encoded as PNG by hand (no imagemagick/canvas
// dependency; node only). The maskable variant shrinks the art into
// the central safe zone so any platform mask crop keeps it intact.
//
//   node scripts/gen-icons.mjs
//
// Idempotent; output is deterministic for a given size set.
import { deflateSync, inflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "site", "icons");

const BG = [0x00, 0x00, 0x00];
const FG = [0x3f, 0xbf, 0x6f]; // terminal green

// --- art: coverage in [0,1] of the prompt glyph at unit coords -------------
const segDist = (px, py, ax, ay, bx, by) => {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
};

const coverage = (u, v, aa) => {
  // chevron ❯: two strokes meeting at the tip
  const t = 0.055;
  const d = Math.min(
    segDist(u, v, 0.30, 0.32, 0.52, 0.50),
    segDist(u, v, 0.52, 0.50, 0.30, 0.68),
  );
  const chev = Math.max(0, Math.min(1, (t - d) / aa + 0.5));
  // underscore cursor block
  const inset = (lo, hi, x) => Math.max(0, Math.min(1, (Math.min(x - lo, hi - x)) / aa + 0.5));
  const cur = Math.min(inset(0.60, 0.78, u), inset(0.60, 0.68, v));
  return Math.max(chev, cur);
};

// --- minimal PNG encoder (truecolor, no interlace) ---------------------------
const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "latin1");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
};

const png = (size, maskable) => {
  const raw = Buffer.alloc(size * (1 + 3 * size));
  const aa = 1 / size; // ~1px soft edge
  for (let y = 0; y < size; y++) {
    const row = y * (1 + 3 * size);
    raw[row] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      // maskable: art shrunk into the central safe zone, full-bleed bg
      const s = maskable ? 0.72 : 1;
      const u = (x / size - 0.5) / s + 0.5;
      const v = (y / size - 0.5) / s + 0.5;
      const a = coverage(u, v, aa / s);
      const o = row + 1 + 3 * x;
      for (let i = 0; i < 3; i++) raw[o + i] = Math.round(BG[i] * (1 - a) + FG[i] * a);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: truecolor
  const file = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
  // self-check: decode round-trip, spot-assert cursor green / corner black
  const body = inflateSync(file.subarray(file.indexOf("IDAT") + 4, file.lastIndexOf("IEND") - 8));
  if (body.length !== raw.length) throw new Error("IDAT round-trip length mismatch");
  const px = (x, y) => body.subarray(y * (1 + 3 * size) + 1 + 3 * x).subarray(0, 3);
  const mid = (lo, hi) => Math.round(((lo + hi) / 2 - 0.5) * (maskable ? 0.72 : 1) * size + size / 2);
  if (px(mid(0.6, 0.78), mid(0.6, 0.68))[1] < 0x80) throw new Error("cursor pixel not green");
  if (px(1, 1).some((b) => b !== 0)) throw new Error("corner not black");
  return file;
};

mkdirSync(OUT, { recursive: true });
for (const [name, size, maskable] of [
  ["icon-192.png", 192, false],
  ["icon-512.png", 512, false],
  ["icon-512-maskable.png", 512, true],
]) {
  writeFileSync(join(OUT, name), png(size, maskable));
  console.log(`${name}: ${size}×${size}${maskable ? " (maskable)" : ""}`);
}
