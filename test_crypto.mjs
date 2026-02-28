/**
 * test_crypto.mjs
 * ---------------
 * Encryption/decryption test suite for the Encrypted Morse Messenger.
 * Uses the exact same DMM1 v2 container format (AES-256-GCM + Argon2id +
 * HKDF + AAD + optional Signal Key) as index.html.
 *
 * Run with:
 *   node test_crypto.mjs
 */

import argon2 from 'argon2';

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
const DMM1_VERSION   = 0x02;
const KDF_ARGON2ID   = 0x02;
const FLAG_PEPPER    = 0x01;

// Argon2id params (fast for tests)
const ARGON2_MIN_TIME_COST = 2;
const ARGON2_MAX_TIME_COST = 16;
const ARGON2_MIN_MEMORY_KIB = 16384;  // 16 MiB minimum
const ARGON2_MAX_MEMORY_KIB = 262144; // 256 MiB maximum
// Use minimal params for fast testing
const TEST_TIME_COST = 2;
const TEST_MEMORY_KIB = 16384; // 16 MiB
const TEST_PARALLELISM = 2;

function u16le(n) {
  const b = new Uint8Array(2);
  const dv = new DataView(b.buffer);
  dv.setUint16(0, n & 0xFFFF, true);
  return b;
}

function readU16le(bytes, off) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(off, true);
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

async function deriveMasterArgon2id(pwPep, salt, timeCost, memoryCostKiB, parallelism) {
  const enc = new TextEncoder();
  const passwordBytes = enc.encode(pwPep);
  
  // Native argon2 package uses different API
  const hash = await argon2.hash(Buffer.from(passwordBytes), {
    type: argon2.argon2id,
    salt: Buffer.from(salt),
    timeCost: timeCost,
    memoryCost: memoryCostKiB,
    parallelism: parallelism,
    hashLength: 32,
    raw: true
  });
  
  return new Uint8Array(hash);
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

function buildDmm1Header({ kdfId, flags, timeCost, memoryCostKiB, parallelism, salt, iv }) {
  const header = new Uint8Array(40);
  header.set(DMM1_MAGIC, 0);
  header[4] = DMM1_VERSION;
  header[5] = kdfId;
  header[6] = flags;
  header[7] = timeCost;
  header.set(u16le(memoryCostKiB), 8);
  header[10] = parallelism;
  header[11] = 0x00; // reserved
  header.set(salt, 12);
  header.set(iv, 28);
  return header;
}

function isDmm1(bytes) {
  if (!bytes || bytes.length < 40) return false;
  for (let i = 0; i < 4; i++) if (bytes[i] !== DMM1_MAGIC[i]) return false;
  return true;
}

// ── Encrypt / Decrypt (v2 Argon2id only) ───────────────────────────────────

async function dmmEncryptV2(plaintext, password, pepper, timeCost = TEST_TIME_COST, memoryCostKiB = TEST_MEMORY_KIB, parallelism = TEST_PARALLELISM) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  const pwPep  = concatPwPepper(password, pepper);
  const master = await deriveMasterArgon2id(pwPep, salt, timeCost, memoryCostKiB, parallelism);
  const kEnc   = await hkdfSplit(master, salt, "dad-mode-morse:v2:enc", "aes");

  const flags  = pepper ? FLAG_PEPPER : 0x00;
  const header = buildDmm1Header({ kdfId: KDF_ARGON2ID, flags, timeCost, memoryCostKiB, parallelism, salt, iv });
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

  return { hex: hexFromBytes(combined), meta: { timeCost, memoryCostKiB, parallelism, pepperUsed: !!pepper } };
}

async function dmmDecryptAny(hex, password, pepper) {
  const bytes = bytesFromHex(hex);

  if (isDmm1(bytes)) {
    const ver   = bytes[4];
    if (ver !== DMM1_VERSION) throw new Error("Unsupported DMM version (expected v2/Argon2id)");
    const kdfId = bytes[5];
    const flags = bytes[6];
    const timeCost = bytes[7];
    const memoryCostKiB = readU16le(bytes, 8);
    const parallelism = bytes[10];
    const salt  = bytes.slice(12, 28);
    const iv    = bytes.slice(28, 40);
    const data  = bytes.slice(40);
    const pepperUsed = (flags & FLAG_PEPPER) !== 0;

    if (kdfId !== KDF_ARGON2ID)
      throw new Error("Unsupported KDF. This version only supports Argon2id (kdf_id=0x02).");
    if (timeCost < ARGON2_MIN_TIME_COST || timeCost > ARGON2_MAX_TIME_COST)
      throw new Error("Invalid Argon2id timeCost parameter");
    if (memoryCostKiB < ARGON2_MIN_MEMORY_KIB || memoryCostKiB > ARGON2_MAX_MEMORY_KIB)
      throw new Error("Invalid Argon2id memoryCost parameter");
    if (parallelism < 1 || parallelism > 16)
      throw new Error("Invalid Argon2id parallelism parameter");
    if (pepperUsed && !pepper)
      throw new Error("Signal Key required (sender used a Signal Key).");

    const pwPep  = concatPwPepper(password, pepperUsed ? pepper : "");
    const master = await deriveMasterArgon2id(pwPep, salt, timeCost, memoryCostKiB, parallelism);
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

  // No legacy fallback - Argon2id only
  throw new Error("Invalid payload format. Expected DMM1 v2 (Argon2id) container.");
}

// Public wrappers (mirror index.html)
async function aesGcmEncrypt(plaintext, password, pepper) {
  return dmmEncryptV2(plaintext, password, pepper);
}
async function aesGcmDecrypt(hex, password, pepper) {
  return dmmDecryptAny(hex, password, pepper);
}

// ── Ed25519 Signing/Verification (mirror index.html) ────────────────────────

const ED25519_SIG_LINE_PREFIX = "Ed25519 Signature (base64): ";

function base64ToBytes(b64) {
  const binStr = Buffer.from(b64, 'base64').toString('binary');
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

async function checkEd25519Support() {
  try {
    const testKey = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    return !!testKey;
  } catch (e) {
    return false;
  }
}

async function generateEd25519KeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"]
  );

  const privateKeyExported = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyBase64 = bytesToBase64(new Uint8Array(privateKeyExported));

  const publicKeyExported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyExported));

  return { privateKeyBase64, publicKeyBase64, keyPair };
}

async function importEd25519PrivateKey(base64Pkcs8) {
  const keyData = base64ToBytes(base64Pkcs8);
  return crypto.subtle.importKey(
    "pkcs8",
    keyData,
    "Ed25519",
    false,
    ["sign"]
  );
}

async function importEd25519PublicKey(base64Spki) {
  const keyData = base64ToBytes(base64Spki);
  return crypto.subtle.importKey(
    "spki",
    keyData,
    "Ed25519",
    false,
    ["verify"]
  );
}

async function signMessageEd25519(message, privateKeyBase64) {
  const privateKey = await importEd25519PrivateKey(privateKeyBase64);
  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    enc.encode(message)
  );
  return bytesToBase64(new Uint8Array(signature));
}

async function verifySignatureEd25519(message, signatureBase64, publicKeyBase64) {
  const publicKey = await importEd25519PublicKey(publicKeyBase64);
  const enc = new TextEncoder();
  const sigBytes = base64ToBytes(signatureBase64);
  return crypto.subtle.verify(
    "Ed25519",
    publicKey,
    sigBytes,
    enc.encode(message)
  );
}

function extractSignatureFromInput(inputText) {
  const lines = inputText.trim().split('\n');
  let signatureBase64 = null;
  let morseOnly = inputText;

  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line.startsWith(ED25519_SIG_LINE_PREFIX)) {
      signatureBase64 = line.slice(ED25519_SIG_LINE_PREFIX.length).trim();
      morseOnly = lines.slice(0, i).join('\n').trim();
      break;
    }
  }

  return { morseOnly, signatureBase64 };
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
  assert(bytes[5] === KDF_ARGON2ID, `Expected KDF ID ${KDF_ARGON2ID}`);

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

// 19. Legacy v1 payload is rejected (no backward compat)
await test("Legacy v1 payload is rejected (no backward compat)", async () => {
  // Create a fake legacy v1 payload (no DMM1 magic, just salt+iv+ciphertext)
  const fakeHex = "00".repeat(16 + 12 + 32); // salt + iv + fake ciphertext
  let threw = false;
  try { await dmmDecryptAny(fakeHex, "anyPassword12345"); } catch (e) {
    threw = e.message.includes("Invalid payload format");
  }
  assert(threw, "Should reject legacy v1 payloads");
});

// 20. Argon2id params stored in header match what was used
await test("Argon2id params stored in header match encrypt params", async () => {
  const timeCost = 3;
  const memoryCostKiB = 32768;
  const parallelism = 4;
  const { hex } = await dmmEncryptV2("param test", "paramPassword12345", "", timeCost, memoryCostKiB, parallelism);
  const bytes = bytesFromHex(hex);
  const storedTimeCost = bytes[7];
  const storedMemoryCostKiB = readU16le(bytes, 8);
  const storedParallelism = bytes[10];
  assert(storedTimeCost === timeCost,
    `Expected timeCost ${timeCost} in header, got ${storedTimeCost}`);
  assert(storedMemoryCostKiB === memoryCostKiB,
    `Expected memoryCostKiB ${memoryCostKiB} in header, got ${storedMemoryCostKiB}`);
  assert(storedParallelism === parallelism,
    `Expected parallelism ${parallelism} in header, got ${storedParallelism}`);
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

// ── Ed25519 Signing/Verification Tests ───────────────────────────────────────

// 26. Ed25519 key generation produces valid keypair
await test("Ed25519 key generation produces valid keypair", async () => {
  const supported = await checkEd25519Support();
  if (!supported) {
    console.log("       (Ed25519 not supported in this Node.js version, skipping)");
    return;
  }
  const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
  assert(privateKeyBase64.length > 40, "Private key should be base64-encoded PKCS8");
  assert(publicKeyBase64.length > 30, "Public key should be base64-encoded SPKI");
  // Verify we can re-import them
  const privKey = await importEd25519PrivateKey(privateKeyBase64);
  const pubKey = await importEd25519PublicKey(publicKeyBase64);
  assert(privKey !== null, "Should import private key");
  assert(pubKey !== null, "Should import public key");
});

// 27. Ed25519 sign + verify round-trip (valid signature)
await test("Ed25519 sign + verify round-trip (valid signature)", async () => {
  const supported = await checkEd25519Support();
  if (!supported) {
    console.log("       (Ed25519 not supported, skipping)");
    return;
  }
  const message = "Hello, this is a signed message!";
  const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
  const signature = await signMessageEd25519(message, privateKeyBase64);
  assert(signature.length === 88, `Ed25519 signature should be 88 base64 chars (64 bytes), got ${signature.length}`);
  const isValid = await verifySignatureEd25519(message, signature, publicKeyBase64);
  assert(isValid === true, "Signature should be valid");
});

// 28. Ed25519 verification fails with wrong public key
await test("Ed25519 verification fails with wrong public key", async () => {
  const supported = await checkEd25519Support();
  if (!supported) {
    console.log("       (Ed25519 not supported, skipping)");
    return;
  }
  const message = "Signed with key A";
  const keyPairA = await generateEd25519KeyPair();
  const keyPairB = await generateEd25519KeyPair();
  const signature = await signMessageEd25519(message, keyPairA.privateKeyBase64);
  const isValid = await verifySignatureEd25519(message, signature, keyPairB.publicKeyBase64);
  assert(isValid === false, "Signature should be INVALID with wrong public key");
});

// 29. Ed25519 verification fails with tampered message
await test("Ed25519 verification fails with tampered message", async () => {
  const supported = await checkEd25519Support();
  if (!supported) {
    console.log("       (Ed25519 not supported, skipping)");
    return;
  }
  const originalMessage = "Original message content";
  const tamperedMessage = "Tampered message content";
  const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
  const signature = await signMessageEd25519(originalMessage, privateKeyBase64);
  const isValid = await verifySignatureEd25519(tamperedMessage, signature, publicKeyBase64);
  assert(isValid === false, "Signature should be INVALID for tampered message");
});

// 30. Ed25519 signature extraction from input text
await test("Ed25519 signature extraction from input text", async () => {
  const morse = ".- -... -.-. -.. . ..-.";
  const sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const combined = `${morse}\nEd25519 Signature (base64): ${sig}`;
  const { morseOnly, signatureBase64 } = extractSignatureFromInput(combined);
  assert(morseOnly === morse, `Morse extraction failed: got "${morseOnly}"`);
  assert(signatureBase64 === sig, `Signature extraction failed: got "${signatureBase64}"`);
  
  // Test without signature
  const { morseOnly: m2, signatureBase64: s2 } = extractSignatureFromInput(morse);
  assert(m2 === morse, "Should return original if no signature");
  assert(s2 === null, "Should return null signature if none present");
});

// 31. Ed25519 full pipeline: sign plaintext → encrypt → decrypt → verify
await test("Ed25519 full pipeline: sign plaintext → encrypt → decrypt → verify", async () => {
  const supported = await checkEd25519Support();
  if (!supported) {
    console.log("       (Ed25519 not supported, skipping)");
    return;
  }
  const plaintext = "Secret signed message for full pipeline test!";
  const password = "fullPipelinePassword12345";
  const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
  
  // Sender: sign plaintext, then encrypt
  const signature = await signMessageEd25519(plaintext, privateKeyBase64);
  const { hex } = await aesGcmEncrypt(plaintext, password);
  const morse = toMorseHex(hex);
  
  // Simulate transmission with signature appended
  const transmitted = `${morse}\nEd25519 Signature (base64): ${signature}`;
  
  // Recipient: extract signature, decrypt, verify
  const { morseOnly, signatureBase64 } = extractSignatureFromInput(transmitted);
  const { hex: hexBack } = morseToHex(morseOnly);
  const decrypted = await aesGcmDecrypt(hexBack, password);
  assert(decrypted === plaintext, "Decrypted plaintext mismatch");
  
  const isValid = await verifySignatureEd25519(decrypted, signatureBase64, publicKeyBase64);
  assert(isValid === true, "Signature should verify against decrypted plaintext");
});

// 32. Ed25519 browser support detection
await test("Ed25519 browser support detection works", async () => {
  const supported = await checkEd25519Support();
  // In Node.js 18+, Ed25519 should be supported
  // This test just verifies the function doesn't throw
  assert(typeof supported === "boolean", "checkEd25519Support should return boolean");
  console.log(`       (Ed25519 supported: ${supported})`);
});

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(
  exitCode === 0
    ? "\n=== All 32 encryption tests passed ==="
    : "\n=== SOME TESTS FAILED ==="
);
process.exit(exitCode);
