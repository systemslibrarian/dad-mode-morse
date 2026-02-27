/**
 * test_crypto.mjs
 * ---------------
 * Encryption/decryption test suite for the Encrypted Morse Messenger.
 * Uses the exact same DMM1 v2 container format (AES-256-GCM + PBKDF2 +
 * HKDF + AAD + optional Signal Key) as index.html.
 *
 * Run with:
 *   node test_crypto.mjs
 */

// ── Exact copies of the app's Morse + crypto functions ──────────────────────

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

// ── DMM1 Container (v2) constants and helpers ───────────────────────────────

const DMM1_MAGIC     = [0x44, 0x4d, 0x4d, 0x31]; // "DMM1"
const DMM1_VERSION   = 0x01;
const KDF_PBKDF2     = 0x01;
const FLAG_PEPPER    = 0x01;

const PBKDF2_MIN_ITERS = 50_000;
const PBKDF2_MAX_ITERS = 1_200_000;
const TEST_ITERS       = 100_000; // fixed for fast tests

function u32le(n) {
  const b = new Uint8Array(4);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, n >>> 0, true);
  return b;
}

function readU32le(bytes, off) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(off, true);
}

function concatPwPepper(password, pepper) {
  const p = password || "";
  const x = pepper || "";
  return x ? (p + "\u0000" + x) : p;
}

function hexFromBytes(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesFromHex(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) throw new Error("Invalid hex payload");
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function deriveMasterPBKDF2(pwPep, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(pwPep), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function hkdfSplit(masterBytes, salt, infoStr, out) {
  const baseKey = await crypto.subtle.importKey("raw", masterBytes, "HKDF", false, ["deriveBits", "deriveKey"]);
  const info = new TextEncoder().encode(infoStr);
  if (out === "aes") {
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } else {
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }
}

function buildDmm1Header({ kdfId, flags, iters, salt, iv }) {
  const header = new Uint8Array(40);
  header.set(DMM1_MAGIC, 0);
  header[4] = DMM1_VERSION;
  header[5] = kdfId;
  header[6] = flags;
  header[7] = 0x00;
  header.set(u32le(iters), 8);
  header.set(salt, 12);
  header.set(iv, 28);
  return header;
}

function isDmm1(bytes) {
  if (!bytes || bytes.length < 40) return false;
  for (let i = 0; i < 4; i++) if (bytes[i] !== DMM1_MAGIC[i]) return false;
  return true;
}

// ── Encrypt / Decrypt (v2 + legacy v1 fallback) ─────────────────────────────

async function dmmEncryptV2(plaintext, password, pepper, iters = TEST_ITERS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  const pwPep  = concatPwPepper(password, pepper);
  const master = await deriveMasterPBKDF2(pwPep, salt, iters);
  const kEnc   = await hkdfSplit(master, salt, "dad-mode-morse:v2:enc", "aes");

  const flags  = pepper ? FLAG_PEPPER : 0x00;
  const header = buildDmm1Header({ kdfId: KDF_PBKDF2, flags, iters, salt, iv });
  const additionalData = header;

  const enc   = new TextEncoder();
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 },
    kEnc,
    enc.encode(plaintext)
  );

  const ct       = new Uint8Array(ctBuf);
  const combined = new Uint8Array(header.length + ct.length);
  combined.set(header, 0);
  combined.set(ct, header.length);

  return { hex: hexFromBytes(combined), meta: { iters, pepperUsed: !!pepper } };
}

async function dmmDecryptAny(hex, password, pepper) {
  const bytes = bytesFromHex(hex);

  if (isDmm1(bytes)) {
    const ver   = bytes[4];
    if (ver !== DMM1_VERSION) throw new Error("Unsupported DMM version");
    const kdfId = bytes[5];
    const flags = bytes[6];
    const iters = readU32le(bytes, 8);
    const salt  = bytes.slice(12, 28);
    const iv    = bytes.slice(28, 40);
    const data  = bytes.slice(40);
    const pepperUsed = (flags & FLAG_PEPPER) !== 0;

    if (kdfId !== KDF_PBKDF2)
      throw new Error("This build supports PBKDF2 only (Argon2id is reserved for a future build).");
    if (!Number.isFinite(iters) || iters < PBKDF2_MIN_ITERS || iters > PBKDF2_MAX_ITERS)
      throw new Error("Invalid KDF parameters");
    if (pepperUsed && !pepper)
      throw new Error("Signal Key required (sender used a Signal Key).");

    const pwPep  = concatPwPepper(password, pepperUsed ? pepper : "");
    const master = await deriveMasterPBKDF2(pwPep, salt, iters);
    const kEnc   = await hkdfSplit(master, salt, "dad-mode-morse:v2:enc", "aes");

    const headerSlice    = bytes.slice(0, 40);
    const additionalData = headerSlice;

    const ptBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData, tagLength: 128 },
      kEnc,
      data
    );
    return new TextDecoder().decode(ptBuf);
  }

  // legacy v1 fallback (no container, fixed 150 000 iterations, no pepper)
  if (bytes.length < (16 + 12 + 1)) throw new Error("Invalid payload length");
  const salt = bytes.slice(0, 16);
  const iv   = bytes.slice(16, 28);
  const data = bytes.slice(28);

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, ["decrypt"]
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(pt);
}

// Legacy v1 encrypt (used only to produce v1 blobs for backward-compat tests)
async function legacyV1Encrypt(plaintext, password) {
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
  const ct       = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);
  return { hex: Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('') };
}

// Public wrappers (mirror index.html)
async function aesGcmEncrypt(plaintext, password, pepper) {
  return dmmEncryptV2(plaintext, password, pepper);
}
async function aesGcmDecrypt(hex, password, pepper) {
  return dmmDecryptAny(hex, password, pepper);
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

// 1. Basic v2 encrypt → decrypt round-trip
await test("DMM1 v2 encrypt + decrypt round-trip (same password)", async () => {
  const { hex } = await aesGcmEncrypt("Hello, World!", "supersecret12345");
  assert(await aesGcmDecrypt(hex, "supersecret12345") === "Hello, World!", "plaintext mismatch");
});

// 2. Wrong password must be rejected (AES-GCM authentication tag + AAD)
await test("Wrong password throws (AES-GCM auth tag + AAD)", async () => {
  const { hex } = await aesGcmEncrypt("secret message", "correcthorsebatterystaple");
  let threw = false;
  try { await aesGcmDecrypt(hex, "wrongpassword12345"); } catch (_) { threw = true; }
  assert(threw, "Should have thrown with wrong password");
});

// 3. Random salt + IV → unique ciphertext every time
await test("Random salt/IV → unique ciphertext on every call", async () => {
  const a = (await aesGcmEncrypt("same text", "pw123456789012345")).hex;
  const b = (await aesGcmEncrypt("same text", "pw123456789012345")).hex;
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
  const password  = "hunter2-is-bad-but-long";
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
  const { hex } = await aesGcmEncrypt(plaintext, "unicodepassword12345");
  assert(await aesGcmDecrypt(hex, "unicodepassword12345") === plaintext, "Unicode mismatch");
});

// 7. Empty string is valid
await test("Empty plaintext encrypts and decrypts correctly", async () => {
  const { hex } = await aesGcmEncrypt("", "password1234567890");
  assert(await aesGcmDecrypt(hex, "password1234567890") === "", "Should be empty string");
});

// 8. Large payload
await test("Long message (1000 chars) round-trips correctly", async () => {
  const plaintext = "A".repeat(1000);
  const { hex } = await aesGcmEncrypt(plaintext, "longmessagepass12345");
  assert(await aesGcmDecrypt(hex, "longmessagepass12345") === plaintext, "Long message mismatch");
});

// 9. Tampered ciphertext must be detected (GCM + AAD integrity)
await test("Tampered ciphertext is rejected (GCM + AAD integrity check)", async () => {
  const { hex } = await aesGcmEncrypt("tamper test", "tamperpw123456789");
  const arr = hex.split('');
  const idx = 40 * 2 + 4; // byte well inside the ciphertext (past the 40-byte header)
  arr[idx] = arr[idx] === '0' ? '1' : '0';
  let threw = false;
  try { await aesGcmDecrypt(arr.join(''), "tamperpw123456789"); } catch (_) { threw = true; }
  assert(threw, "Should have rejected tampered ciphertext");
});

// 10. DMM1 v2 payload binary layout (40-byte header + ciphertext + tag)
await test("DMM1 v2 payload layout: header(40) ‖ ciphertext+tag(N)", async () => {
  const enc       = new TextEncoder();
  const plaintext = "layout check";
  const password  = "layoutpassword12345";
  const { hex }   = await aesGcmEncrypt(plaintext, password);
  const bytes     = bytesFromHex(hex);

  // Verify DMM1 magic
  assert(isDmm1(bytes), "Missing DMM1 magic header");
  assert(bytes[4] === DMM1_VERSION, `Expected version ${DMM1_VERSION}, got ${bytes[4]}`);
  assert(bytes[5] === KDF_PBKDF2, `Expected KDF ID ${KDF_PBKDF2}`);

  // header(40) + ciphertext(len) + GCM tag(16)
  const plaintextBytes = enc.encode(plaintext).byteLength;
  const expectedLen = 40 + plaintextBytes + 16;
  assert(bytes.length === expectedLen,
    `Expected ${expectedLen} bytes, got ${bytes.length}`);
});

// 11. Morse output contains only valid hex Morse symbols
await test("Morse output contains only valid hex Morse symbols", async () => {
  const { hex } = await aesGcmEncrypt("Morse symbol check", "symbolcheckpw12345");
  const morse   = toMorseHex(hex);
  const validSet = new Set(Object.values(hexMorseDict));
  for (const sym of morse.split(' ')) {
    assert(validSet.has(sym), `Invalid Morse symbol found: '${sym}'`);
  }
});

// 12. All 16 hex digits have unique Morse codes
await test("All 16 hex digits have unique Morse codes", async () => {
  const codes  = Object.values(hexMorseDict);
  const unique = new Set(codes);
  assert(unique.size === 16, `Expected 16 unique codes, got ${unique.size}`);
  assert(Object.keys(reverseHexMorse).length === 16,
    "reverseHexMorse does not cover all 16 codes");
});

// 13. Signal Key (pepper) round-trip
await test("Signal Key (pepper) encrypt + decrypt round-trip", async () => {
  const plaintext = "pepper secret!";
  const password  = "passwordWithPepper1234";
  const pepper    = "my-signal-key-42";
  const { hex, meta } = await aesGcmEncrypt(plaintext, password, pepper);
  assert(meta.pepperUsed === true, "meta.pepperUsed should be true");
  assert(await aesGcmDecrypt(hex, password, pepper) === plaintext, "plaintext mismatch with pepper");
});

// 14. Pepper flag set → decrypt without pepper must fail
await test("Pepper used → decrypt without pepper throws", async () => {
  const { hex } = await aesGcmEncrypt("need pepper", "pepperPw1234567890", "secret-signal");
  let threw = false;
  try { await aesGcmDecrypt(hex, "pepperPw1234567890"); } catch (_) { threw = true; }
  assert(threw, "Should have thrown when pepper required but missing");
});

// 15. Wrong pepper must fail (key derivation mismatch)
await test("Wrong pepper → decrypt fails", async () => {
  const { hex } = await aesGcmEncrypt("wrong pepper test", "pepperPw1234567890", "correct-signal");
  let threw = false;
  try { await aesGcmDecrypt(hex, "pepperPw1234567890", "wrong-signal"); } catch (_) { threw = true; }
  assert(threw, "Should have thrown with wrong pepper");
});

// 16. No-pepper payload does NOT have FLAG_PEPPER set
await test("No pepper → FLAG_PEPPER bit is 0", async () => {
  const { hex } = await aesGcmEncrypt("no pepper", "noPepperPassword12345");
  const bytes = bytesFromHex(hex);
  assert((bytes[6] & FLAG_PEPPER) === 0, "FLAG_PEPPER should not be set");
});

// 17. With-pepper payload has FLAG_PEPPER set
await test("With pepper → FLAG_PEPPER bit is 1", async () => {
  const { hex } = await aesGcmEncrypt("has pepper", "hasPepperPassword12345", "mypepper");
  const bytes = bytesFromHex(hex);
  assert((bytes[6] & FLAG_PEPPER) !== 0, "FLAG_PEPPER should be set");
});

// 18. Tampered AAD (header bytes) → decrypt fails
await test("Tampered header (AAD) is rejected", async () => {
  const { hex } = await aesGcmEncrypt("AAD test message", "aadTestPassword12345");
  const arr = hex.split('');
  // Flip a bit in byte 7 (reserved field) — still inside the 40-byte header / AAD
  const headerIdx = 7 * 2; // hex char index for byte 7
  arr[headerIdx] = arr[headerIdx] === '0' ? '1' : '0';
  let threw = false;
  try { await aesGcmDecrypt(arr.join(''), "aadTestPassword12345"); } catch (_) { threw = true; }
  assert(threw, "Should have rejected tampered AAD (header)");
});

// 19. Legacy v1 payload decrypts via backward-compat path
await test("Legacy v1 payload decrypts correctly (backward compat)", async () => {
  const plaintext = "legacy message";
  const password  = "legacyPassword12345";
  const { hex }   = await legacyV1Encrypt(plaintext, password);
  // v1 payload does NOT start with DMM1 magic
  const bytes = bytesFromHex(hex);
  assert(!isDmm1(bytes), "v1 payload should not have DMM1 magic");
  // dmmDecryptAny should still handle it
  assert(await dmmDecryptAny(hex, password) === plaintext, "Legacy v1 decrypt failed");
});

// 20. Iterations stored in header match what was used
await test("PBKDF2 iterations stored in header match encrypt params", async () => {
  const { hex } = await dmmEncryptV2("iter test", "iterPassword12345", "", TEST_ITERS);
  const bytes = bytesFromHex(hex);
  const storedIters = readU32le(bytes, 8);
  assert(storedIters === TEST_ITERS,
    `Expected ${TEST_ITERS} iters in header, got ${storedIters}`);
});

// 21. concatPwPepper helper works correctly
await test("concatPwPepper combines password + pepper with NUL separator", () => {
  assert(concatPwPepper("pw", "pep") === "pw\u0000pep", "Should join with NUL");
  assert(concatPwPepper("pw", "") === "pw", "Empty pepper should return password only");
  assert(concatPwPepper("pw", null) === "pw", "Null pepper should return password only");
  assert(concatPwPepper("", "pep") === "\u0000pep", "Empty password with pepper");
});

// 22. HKDF produces different keys for different info strings
await test("HKDF key separation: different info → different keys", async () => {
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const master = crypto.getRandomValues(new Uint8Array(32));
  const k1     = await hkdfSplit(master, salt, "dad-mode-morse:v2:enc", "raw");
  const k2     = await hkdfSplit(master, salt, "dad-mode-morse:v2:meta", "raw");
  assert(hexFromBytes(k1) !== hexFromBytes(k2), "HKDF must produce different keys for different info strings");
});

// 23. isDmm1 rejects short / non-DMM1 inputs
await test("isDmm1 rejects invalid inputs", () => {
  assert(!isDmm1(null), "null");
  assert(!isDmm1(new Uint8Array(0)), "empty");
  assert(!isDmm1(new Uint8Array(39)), "too short (39 bytes)");
  assert(!isDmm1(new Uint8Array(40)), "valid length but wrong magic");
  const valid = new Uint8Array(40);
  valid.set(DMM1_MAGIC, 0);
  assert(isDmm1(valid), "Valid DMM1 magic should pass");
});

// 24. bytesFromHex rejects invalid hex strings
await test("bytesFromHex rejects invalid hex", () => {
  let threw = false;
  try { bytesFromHex("ZZZZ"); } catch (_) { threw = true; }
  assert(threw, "Should reject non-hex chars");
  threw = false;
  try { bytesFromHex("abc"); } catch (_) { threw = true; }
  assert(threw, "Should reject odd-length hex");
});

// 25. Full end-to-end pipeline with pepper + Morse
await test("Full pipeline with pepper: encrypt → Morse → decrypt", async () => {
  const plaintext = "Signal Key pipeline test!";
  const password  = "pipelinePassword12345";
  const pepper    = "radio-alpha-bravo";
  const { hex }   = await aesGcmEncrypt(plaintext, password, pepper);
  const morse     = toMorseHex(hex);
  const { hex: hexBack, invalid } = morseToHex(morse);
  assert(!invalid, "Invalid Morse symbols");
  assert(await aesGcmDecrypt(hexBack, password, pepper) === plaintext, "Plaintext mismatch");
});

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(
  exitCode === 0
    ? "\n=== All 25 encryption tests passed ==="
    : "\n=== SOME TESTS FAILED ==="
);
process.exit(exitCode);
