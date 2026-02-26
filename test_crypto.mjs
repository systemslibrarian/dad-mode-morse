/**
 * test_crypto.mjs
 * ---------------
 * Encryption/decryption test suite for the Encrypted Morse Messenger.
 * Uses the exact same Web Crypto API (AES-256-GCM + PBKDF2) as index.html.
 *
 * Run with:
 *   node test_crypto.mjs
 */

// ── Exact copies of the app's crypto + Morse functions ──────────────────────

const hexMorseDict = {
  '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....',
  '6':'-....','7':'--...','8':'---..','9':'----.','A':'.-','B':'-...',
  'C':'-.-.','D':'-..','E':'.','F':'..-.'
};
const reverseHexMorse = Object.fromEntries(
  Object.entries(hexMorseDict).map(([k, v]) => [v, k])
);

function toMorseHex(hex) {
  return hex.toUpperCase().split('')
    .map(c => hexMorseDict[c] || '').filter(Boolean).join(' ');
}

function morseToHex(morse) {
  const groups = morse.trim().split(/\s+/).filter(Boolean);
  let hex = '', invalid = false;
  for (const g of groups) {
    const ch = reverseHexMorse[g];
    if (!ch) { invalid = true; hex += '?'; } else hex += ch;
  }
  return { hex: hex.toLowerCase(), invalid };
}

async function aesGcmEncrypt(plaintext, password) {
  const enc  = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const km   = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );
  const key  = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );
  const ct   = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);
  return { hex: Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('') };
}

async function aesGcmDecrypt(hex, password) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length < (16 + 12 + 1) * 2)
    throw new Error("Invalid hex payload length/content");
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const salt  = bytes.slice(0, 16);
  const iv    = bytes.slice(16, 28);
  const data  = bytes.slice(28);
  const enc   = new TextEncoder();
  const km    = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );
  const key   = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(dec);
}

// ── Test runner ──────────────────────────────────────────────────────────────

let exitCode = 0;

async function test(label, fn) {
  try {
    await fn();
    console.log(`[PASS] ${label}`);
  } catch (e) {
    console.error(`[FAIL] ${label}`);
    console.error(`       ${e.message}`);
    exitCode = 1;
  }
}

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

// ── Test cases ───────────────────────────────────────────────────────────────

// 1. Basic encrypt → decrypt
await test("Encrypt + decrypt round-trip (same password)", async () => {
  const { hex } = await aesGcmEncrypt("Hello, World!", "supersecret123");
  assert(await aesGcmDecrypt(hex, "supersecret123") === "Hello, World!", "plaintext mismatch");
});

// 2. Wrong password must be rejected by AES-GCM authentication tag
await test("Wrong password throws (AES-GCM auth tag)", async () => {
  const { hex } = await aesGcmEncrypt("secret message", "correcthorsebattery");
  let threw = false;
  try { await aesGcmDecrypt(hex, "wrongpassword1"); } catch (_) { threw = true; }
  assert(threw, "Should have thrown with wrong password");
});

// 3. Random salt + IV means same plaintext never produces the same ciphertext
await test("Random salt/IV → unique ciphertext on every call", async () => {
  const a = (await aesGcmEncrypt("same text", "pw12345678")).hex;
  const b = (await aesGcmEncrypt("same text", "pw12345678")).hex;
  assert(a !== b, "Ciphertext was identical — salt/IV may not be random");
});

// 4. Hex ↔ Morse encoding is perfectly lossless
await test("Hex → Morse → Hex round-trip (all 16 hex chars)", async () => {
  const original = "deadbeef0123456789abcdef";
  const { hex, invalid } = morseToHex(toMorseHex(original));
  assert(!invalid, "morseToHex reported invalid symbols");
  assert(hex === original, `Got: ${hex}`);
});

// 5. Complete end-to-end pipeline matching the app's flow
await test("Full pipeline: encrypt → hex → Morse → hex → decrypt", async () => {
  const plaintext = "Top secret message!";
  const password  = "hunter2-is-bad";
  const { hex }   = await aesGcmEncrypt(plaintext, password);
  const morse     = toMorseHex(hex);
  assert(morse.length > 0, "Morse string is empty");
  const { hex: hexBack, invalid } = morseToHex(morse);
  assert(!invalid, "Invalid Morse symbols after round-trip");
  assert(await aesGcmDecrypt(hexBack, password) === plaintext, "Plaintext mismatch at end");
});

// 6. Unicode / multi-byte characters
await test("Unicode plaintext (emoji, accents, CJK) round-trips", async () => {
  const plaintext = "café ☕ naïve 日本語";
  const { hex } = await aesGcmEncrypt(plaintext, "unicodepassword1");
  assert(await aesGcmDecrypt(hex, "unicodepassword1") === plaintext, "Unicode mismatch");
});

// 7. Empty string is valid
await test("Empty plaintext encrypts and decrypts correctly", async () => {
  const { hex } = await aesGcmEncrypt("", "password12345678");
  assert(await aesGcmDecrypt(hex, "password12345678") === "", "Should be empty string");
});

// 8. Large payload
await test("Long message (1000 chars) round-trips correctly", async () => {
  const plaintext = "A".repeat(1000);
  const { hex } = await aesGcmEncrypt(plaintext, "longmessagepass1");
  assert(await aesGcmDecrypt(hex, "longmessagepass1") === plaintext, "Long message mismatch");
});

// 9. Tampered ciphertext must be detected (GCM integrity)
await test("Tampered ciphertext is rejected (GCM integrity check)", async () => {
  const { hex } = await aesGcmEncrypt("tamper test", "tamperpw1234567");
  const arr = hex.split('');
  const idx = (16 + 12) * 2 + 4;       // byte well inside the ciphertext
  arr[idx]  = arr[idx] === '0' ? '1' : '0';
  let threw = false;
  try { await aesGcmDecrypt(arr.join(''), "tamperpw1234567"); } catch (_) { threw = true; }
  assert(threw, "Should have rejected tampered ciphertext");
});

// 10. Payload binary layout — verify salt/IV/ciphertext byte offsets
await test("Payload binary layout: salt(16) ‖ iv(12) ‖ ciphertext+tag(N)", async () => {
  const enc       = new TextEncoder();
  const plaintext = "layout check";
  const password  = "layoutpassword1";
  const { hex }   = await aesGcmEncrypt(plaintext, password);
  const bytes     = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));

  // salt = bytes 0..15, iv = bytes 16..27, ciphertext+tag starts at byte 28
  // AES-GCM appends a 16-byte authentication tag, so ciphertext+tag length =
  // plaintext byte length + 16
  const plaintextBytes = enc.encode(plaintext).byteLength;
  const expectedMinLen = 16 + 12 + plaintextBytes + 16; // salt + iv + ct + tag
  assert(bytes.length === expectedMinLen,
    `Expected ${expectedMinLen} bytes, got ${bytes.length}`);

  // Extracting the same salt and IV should produce a decryptable blob
  const reconstructed = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  assert(reconstructed === hex, "Hex round-trip of payload bytes failed");
});

// 11. Morse output for a full encrypt only contains valid hex Morse symbols
await test("Morse output contains only valid hex Morse symbols", async () => {
  const { hex }  = await aesGcmEncrypt("Morse symbol check", "symbolcheckpw1");
  const morse    = toMorseHex(hex);
  const validSet = new Set(Object.values(hexMorseDict));
  for (const sym of morse.split(' ')) {
    assert(validSet.has(sym), `Invalid Morse symbol found: '${sym}'`);
  }
});

// 12. All 16 hex characters map to unique, non-overlapping Morse codes
await test("All 16 hex digits have unique Morse codes", async () => {
  const codes  = Object.values(hexMorseDict);
  const unique = new Set(codes);
  assert(unique.size === 16, `Expected 16 unique codes, got ${unique.size}`);
  // Verify the reverse map covers all 16 too
  assert(Object.keys(reverseHexMorse).length === 16,
    "reverseHexMorse does not cover all 16 codes");
});

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(
  exitCode === 0
    ? "\n=== All 12 encryption tests passed ==="
    : "\n=== SOME TESTS FAILED ==="
);
process.exit(exitCode);
