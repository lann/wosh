// Chrome/Chromium discovery for the conformance jco-browser leg, which
// prefers a system Chrome. (The WPT parity browser legs do not use this:
// they always launch Playwright's own pinned build, so the recorded loss
// set measures one engine everywhere.) Node-only.
import { access, readdir } from "node:fs/promises";
import { join } from "node:path";

/**
 * A Chrome/Chromium binary path (137+ for JSPI), or undefined. CI can
 * override with CHROME_PATH; a playwright-managed Chromium is also
 * discovered (newest revision wins), platform-gated because existence
 * checks alone misfire on phantom cross-platform mounts.
 */
export async function findChrome() {
  const platformPaths =
    process.platform === "darwin"
      ? [
          "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
          "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
      : [
          "/usr/bin/google-chrome",
          "/usr/bin/google-chrome-stable",
          "/usr/bin/chromium",
          "/usr/bin/chromium-browser",
        ];
  const explicit = [
    process.env.CHROME_PATH,
    process.env.CHROME_BIN,
    process.env.PUPPETEER_EXECUTABLE_PATH,
    ...platformPaths,
  ];
  for (const p of explicit) {
    if (!p) continue;
    try {
      await access(p);
      return p;
    } catch {
      // keep looking
    }
  }
  try {
    const cache = join(
      process.env.PLAYWRIGHT_BROWSERS_PATH ?? join(process.env.HOME ?? "", ".cache", "ms-playwright"),
    );
    const revisions = (await readdir(cache))
      .filter((name) => /^chromium-\d+$/.test(name))
      .sort((a, b) => Number(b.split("-")[1]) - Number(a.split("-")[1]));
    const suffix =
      process.platform === "darwin"
        ? ["chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium"]
        : ["chrome-linux", "chrome"];
    for (const revision of revisions) {
      const candidate = join(cache, revision, ...suffix);
      try {
        await access(candidate);
        return candidate;
      } catch {
        // keep looking
      }
    }
  } catch {
    // no cache
  }
  return undefined;
}
