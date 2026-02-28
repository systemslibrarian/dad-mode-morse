/**
 * test_e2e_wav.mjs
 * ----------------
 * End-to-end browser test: Encrypt → Download WAV → Refresh → Upload WAV → Decode → Decrypt.
 * Uses Playwright to drive a real Chromium browser against a local HTTP server.
 *
 * Run with:
 *   node test_e2e_wav.mjs
 */

import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync, existsSync, readdirSync, unlinkSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const MIME_TYPES = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.png':  'image/png',
  '.mp4':  'video/mp4',
  '.wav':  'audio/wav',
  '.json': 'application/json',
};

// Simple static file server
function startServer(root, port = 0) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let filePath = join(root, req.url === '/' ? 'index.html' : req.url);
      try {
        const data = readFileSync(filePath);
        const ext = extname(filePath);
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(data);
      } catch {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

const MESSAGE   = "End-to-end WAV round-trip test! 🐢🔐";
const PASSWORD  = "e2e-test-password-14chars!";
const DOWNLOAD_DIR = join(__dirname, '_e2e_downloads');

async function run() {
  // Clean up old downloads
  if (existsSync(DOWNLOAD_DIR)) {
    for (const f of readdirSync(DOWNLOAD_DIR)) unlinkSync(join(DOWNLOAD_DIR, f));
  }

  const { server, url } = await startServer(__dirname);
  console.log(`  Server: ${url}`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();

  // Collect console errors
  const consoleErrors = [];
  page.on('console', msg => { 
    if (msg.type() === 'error' || msg.type() === 'warning') consoleErrors.push(`[${msg.type()}] ${msg.text()}`);
  });
  page.on('pageerror', err => consoleErrors.push(`[pageerror] ${err.message}`));
  page.on('requestfailed', req => consoleErrors.push(`[reqfail] ${req.url()} ${req.failure()?.errorText}`));

  let exitCode = 0;

  try {
    // ── STEP 1: Load page ──
    console.log('  [1/8] Loading page...');
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#txBtn');

    // ── STEP 2: Enter message + password ──
    console.log('  [2/8] Entering message and password...');
    await page.fill('#message', MESSAGE);
    await page.fill('#password', PASSWORD);

    // ── STEP 3: Click Transmit and wait for output ──
    console.log('  [3/8] Clicking Transmit (encrypting with Argon2id)...');
    // Override alert to capture it
    await page.evaluate(() => { window._alerts = []; window.alert = (m) => window._alerts.push(m); });

    await page.click('#txBtn');
    // Wait for the Morse output to appear (Argon2id can take a few seconds)
    await page.waitForSelector('#morseOutput', { timeout: 60000 });
    console.log('         Encryption complete, Morse generated.');

    // ── STEP 4: Download the WAV file ──
    console.log('  [4/8] Downloading WAV file...');
    // Find the "Download Morse WAV" button
    const wavBtn = page.locator('button', { hasText: 'Download Morse WAV' });
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 30000 }),
      wavBtn.click(),
    ]);
    const wavPath = join(DOWNLOAD_DIR, download.suggestedFilename());
    await download.saveAs(wavPath);
    const wavSize = readFileSync(wavPath).length;
    console.log(`         WAV saved: ${download.suggestedFilename()} (${wavSize} bytes)`);

    if (wavSize < 1000) throw new Error(`WAV file too small (${wavSize} bytes) — likely empty`);

    // ── STEP 5: Refresh the page (simulates recipient opening fresh) ──
    console.log('  [5/8] Refreshing page (fresh session)...');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#txBtn');
    // Re-override alert
    await page.evaluate(() => { window._alerts = []; window.alert = (m) => window._alerts.push(m); });

    // ── STEP 6: Upload the WAV file ──
    console.log('  [6/8] Uploading WAV file...');
    const fileInput = page.locator('#audioUpload');
    await fileInput.setInputFiles(wavPath);
    // Wait for "Decode WAV → Morse" button to become enabled
    await page.waitForFunction(() => !document.getElementById('decodeWavBtn').disabled, { timeout: 5000 });

    // ── STEP 7: Decode WAV → Morse ──
    console.log('  [7/8] Decoding WAV → Morse...');
    await page.click('#decodeWavBtn');
    // Wait for decode to finish (progress bar reaches "Done")
    await page.waitForFunction(
      () => {
        const label = document.getElementById('decodeProgressLabel');
        return label && label.textContent.includes('Done');
      },
      { timeout: 30000 }
    );
    // Verify morse was populated
    const morseValue = await page.inputValue('#morseInput');
    if (!morseValue || morseValue.length < 10) {
      throw new Error(`Morse input is empty or too short after decode: "${morseValue.slice(0, 50)}"`);
    }
    console.log(`         Morse decoded (${morseValue.length} chars)`);

    // ── STEP 8: Enter password and Decrypt ──
    console.log('  [8/8] Entering password and decrypting...');
    await page.fill('#decryptPassword', PASSWORD);
    await page.click('#decBtn');

    // Wait for the alert with the decrypted message
    await page.waitForFunction(
      () => window._alerts.length > 0,
      { timeout: 60000 }
    );

    const alerts = await page.evaluate(() => window._alerts);
    const successAlert = alerts.find(a => a.includes('Success'));

    if (!successAlert) {
      throw new Error(`Decryption failed. Alerts received:\n${alerts.join('\n')}`);
    }

    if (!successAlert.includes(MESSAGE)) {
      throw new Error(`Decrypted message doesn't match!\nExpected: "${MESSAGE}"\nAlert: "${successAlert.slice(0, 200)}"`);
    }

    console.log('\n  ✅ E2E WAV ROUND-TRIP PASSED');
    console.log(`     Message: "${MESSAGE}"`);
    console.log('     Encrypt → Download WAV → Refresh → Upload → Decode → Decrypt = SUCCESS');

  } catch (err) {
    console.error(`\n  ❌ E2E TEST FAILED: ${err.message}`);
    if (consoleErrors.length) {
      console.error('  Browser console errors:', consoleErrors);
    }
    exitCode = 1;
  } finally {
    await browser.close();
    server.close();
    // Clean up downloaded files
    try {
      if (existsSync(DOWNLOAD_DIR)) {
        for (const f of readdirSync(DOWNLOAD_DIR)) unlinkSync(join(DOWNLOAD_DIR, f));
        const { rmdirSync } = await import('fs');
        rmdirSync(DOWNLOAD_DIR);
      }
    } catch {}
  }

  process.exit(exitCode);
}

run().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
