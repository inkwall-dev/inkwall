// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Exports rendered Archify diagrams for the docs: for each checked HTML
// artifact, the viewer's own dual-theme SVG export (it follows the reader's
// light or dark preference) is written to docs/diagrams/<name>.svg. The
// interactive HTML (~800 KB each, not rendered by GitHub) stays in .archify/.
//
//   node hack/docs/export-diagrams.mjs [--png DIR] <artifact.html>...
//
// --png also writes the viewer's PNG export to DIR, for reviewing a diagram
// before publishing it. Chrome is found the way Archify finds it
// (ARCHIFY_CHROME overrides). Run through `make diagrams`.
import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { ChromeVisualBrowser, findChrome } from '../../.claude/skills/archify/bin/visual-check.mjs';

const OUT = 'docs/diagrams';

function parseArgs(argv) {
  const files = [];
  let png = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--png') png = argv[++i];
    else files.push(argv[i]);
  }
  if (files.length === 0 || (png !== null && !png)) {
    console.error('usage: export-diagrams.mjs [--png DIR] <artifact.html>...');
    process.exit(2);
  }
  return { files, png };
}

async function evaluate(browser, sessionId, expression) {
  const res = await browser.cdp.send('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  }, sessionId, 60000);
  if (res.exceptionDetails) {
    throw new Error(res.exceptionDetails.exception?.description || res.exceptionDetails.text);
  }
  return res.result.value;
}

// waitForDownload returns the single finished file with the extension in dir.
async function waitForDownload(dir, ext, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const done = readdirSync(dir).filter((f) => f.endsWith(ext));
    if (done.length === 1 && !readdirSync(dir).some((f) => f.endsWith('.crdownload'))) {
      return path.join(dir, done[0]);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no ${ext} download within ${timeoutMs} ms`);
}

async function exportOne(browser, sessionId, artifact, format, dest) {
  const dir = mkdtempSync(path.join(tmpdir(), 'inkwall-diagram-'));
  try {
    await browser.cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir });
    const loaded = browser.cdp.waitFor('Page.loadEventFired', sessionId, 60000);
    loaded.catch(() => {});
    const nav = await browser.cdp.send('Page.navigate', { url: pathToFileURL(artifact).href }, sessionId);
    if (nav.errorText) throw new Error(`navigation failed: ${nav.errorText}`);
    await loaded;
    // Still motion and loaded fonts, so the export is the static diagram.
    await evaluate(browser, sessionId, `(async function () {
      document.documentElement.setAttribute('data-motion', 'still');
      if (document.fonts && document.fonts.ready) await document.fonts.ready;
      for (let i = 0; i < 100 && !(window.Archify && Archify.exportMenu); i++) {
        await new Promise((r) => setTimeout(r, 50));
      }
      if (!(window.Archify && Archify.exportMenu)) throw new Error('Archify viewer did not load');
      await Archify.exportMenu.run(${JSON.stringify(format)});
      var err = document.documentElement.getAttribute('data-last-export-error-format');
      if (err) throw new Error('viewer export failed: ' + err);
    })()`);
    const file = await waitForDownload(dir, format === 'svg' ? '.svg' : `.${format}`);
    mkdirSync(path.dirname(dest), { recursive: true });
    renameSync(file, dest);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  const { files, png } = parseArgs(process.argv.slice(2));
  const chrome = findChrome();
  if (!chrome) {
    console.error('Chrome not found; set ARCHIFY_CHROME to its path');
    process.exit(1);
  }
  const browser = new ChromeVisualBrowser(chrome);
  try {
    const sessionId = await browser.sessionPromise;
    await browser.cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false,
    }, sessionId);
    for (const artifact of files) {
      const name = path.basename(artifact, '.html');
      const svg = path.join(OUT, `${name}.svg`);
      await exportOne(browser, sessionId, artifact, 'svg', svg);
      console.log(`${artifact} -> ${svg}`);
      if (png) {
        const out = path.join(png, `${name}.png`);
        await exportOne(browser, sessionId, artifact, 'png', out);
        console.log(`${artifact} -> ${out}`);
      }
    }
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
