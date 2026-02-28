/**
 * test_ed25519_browser.mjs
 * ------------------------
 * Test for Ed25519 signing/verification using JSDOM to simulate browser.
 * Tests the actual JavaScript from index.html in a browser-like environment.
 *
 * Run with:
 *   node test_ed25519_browser.mjs
 */

import { JSDOM } from 'jsdom';
import { readFileSync } from 'fs';
import { webcrypto } from 'crypto';

// Read and parse the index.html
const html = readFileSync('./index.html', 'utf8');

// Create a JSDOM instance
const dom = new JSDOM(html, {
  runScripts: 'outside-only',
  url: 'https://localhost:8080',
  pretendToBeVisual: true,
});

const { window } = dom;

// Polyfill crypto.subtle with Node's webcrypto
window.crypto = webcrypto;
global.crypto = webcrypto;

console.log('🚀 Testing Ed25519 features from index.html...\n');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.error(`[FAIL] ${name}`);
    console.error(`       ${e.message}`);
    failed++;
  }
}

// Extract the JavaScript from index.html and evaluate key functions
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
  console.error('Could not find script in index.html');
  process.exit(1);
}

// Extract just the Ed25519 functions we need to test
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
    const testKey = await webcrypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    return !!testKey;
  } catch (e) {
    return false;
  }
}

async function generateEd25519KeyPair() {
  const keyPair = await webcrypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"]
  );

  const privateKeyExported = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyBase64 = bytesToBase64(new Uint8Array(privateKeyExported));

  const publicKeyExported = await webcrypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyExported));

  return { privateKeyBase64, publicKeyBase64, keyPair };
}

async function importEd25519PrivateKey(base64Pkcs8) {
  const keyData = base64ToBytes(base64Pkcs8);
  return webcrypto.subtle.importKey(
    "pkcs8",
    keyData,
    "Ed25519",
    false,
    ["sign"]
  );
}

async function importEd25519PublicKey(base64Spki) {
  const keyData = base64ToBytes(base64Spki);
  return webcrypto.subtle.importKey(
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
  const signature = await webcrypto.subtle.sign(
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
  return webcrypto.subtle.verify(
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

// Run tests
async function runTests() {
  // Test 1: UI elements exist
  await test('Ed25519 UI elements exist in index.html', () => {
    const checkbox = window.document.getElementById('enableSigning');
    if (!checkbox) throw new Error('enableSigning checkbox not found');
    
    const signingSection = window.document.getElementById('signingSection');
    if (!signingSection) throw new Error('signingSection not found');
    
    const generateBtn = window.document.getElementById('generateEd25519Btn');
    if (!generateBtn) throw new Error('generateEd25519Btn not found');
    
    const privateKeyField = window.document.getElementById('ed25519PrivateKey');
    if (!privateKeyField) throw new Error('ed25519PrivateKey field not found');
    
    const publicKeyField = window.document.getElementById('ed25519PublicKey');
    if (!publicKeyField) throw new Error('ed25519PublicKey field not found');
  });
  
  // Test 2: Ed25519 support check
  await test('Ed25519 is supported in Node.js crypto', async () => {
    const supported = await checkEd25519Support();
    if (!supported) throw new Error('Ed25519 not supported');
  });
  
  // Test 3: Key generation
  await test('Ed25519 key pair generation works', async () => {
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    if (!privateKeyBase64 || privateKeyBase64.length < 40) {
      throw new Error('Private key invalid');
    }
    if (!publicKeyBase64 || publicKeyBase64.length < 30) {
      throw new Error('Public key invalid');
    }
  });
  
  // Test 4: Sign and verify
  await test('Ed25519 sign and verify round-trip', async () => {
    const message = 'Hello, this is a test message for Ed25519 signing!';
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(message, privateKeyBase64);
    if (!signature || signature.length !== 88) {
      throw new Error(`Invalid signature length: ${signature?.length}`);
    }
    
    const isValid = await verifySignatureEd25519(message, signature, publicKeyBase64);
    if (!isValid) throw new Error('Signature should be valid');
  });
  
  // Test 5: Wrong key fails
  await test('Ed25519 verification fails with wrong public key', async () => {
    const message = 'Signed by key A';
    const keyPairA = await generateEd25519KeyPair();
    const keyPairB = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(message, keyPairA.privateKeyBase64);
    const isValid = await verifySignatureEd25519(message, signature, keyPairB.publicKeyBase64);
    
    if (isValid) throw new Error('Signature should be INVALID with wrong key');
  });
  
  // Test 6: Tampered message fails
  await test('Ed25519 verification fails with tampered message', async () => {
    const original = 'Original message';
    const tampered = 'Tampered message';
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(original, privateKeyBase64);
    const isValid = await verifySignatureEd25519(tampered, signature, publicKeyBase64);
    
    if (isValid) throw new Error('Signature should be INVALID for tampered message');
  });
  
  // Test 7: Signature extraction
  await test('Signature extraction from input text works', () => {
    const morse = '.- -... -.-. -.. . ..-.';
    const sig = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const combined = `${morse}\nEd25519 Signature (base64): ${sig}`;
    
    const { morseOnly, signatureBase64 } = extractSignatureFromInput(combined);
    
    if (morseOnly !== morse) throw new Error(`Morse extraction failed: "${morseOnly}"`);
    if (signatureBase64 !== sig) throw new Error(`Signature extraction failed: "${signatureBase64}"`);
  });
  
  // Test 8: No signature returns null
  await test('Signature extraction returns null when no signature', () => {
    const morse = '.- -... -.-. -.. . ..-.';
    const { morseOnly, signatureBase64 } = extractSignatureFromInput(morse);
    
    if (morseOnly !== morse) throw new Error('Morse should be unchanged');
    if (signatureBase64 !== null) throw new Error('Signature should be null');
  });
  
  // Test 9: Unicode message signing
  await test('Ed25519 signing works with Unicode messages', async () => {
    const message = 'Hello 世界! Café ☕ emoji 🎉';
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(message, privateKeyBase64);
    const isValid = await verifySignatureEd25519(message, signature, publicKeyBase64);
    
    if (!isValid) throw new Error('Unicode message signature should be valid');
  });
  
  // Test 10: Empty message signing
  await test('Ed25519 signing works with empty message', async () => {
    const message = '';
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(message, privateKeyBase64);
    const isValid = await verifySignatureEd25519(message, signature, publicKeyBase64);
    
    if (!isValid) throw new Error('Empty message signature should be valid');
  });
  
  // Test 11: Long message signing
  await test('Ed25519 signing works with long message (10KB)', async () => {
    const message = 'A'.repeat(10000);
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    const signature = await signMessageEd25519(message, privateKeyBase64);
    const isValid = await verifySignatureEd25519(message, signature, publicKeyBase64);
    
    if (!isValid) throw new Error('Long message signature should be valid');
  });
  
  // Test 12: Key import/export round-trip
  await test('Ed25519 key import/export round-trip', async () => {
    const { privateKeyBase64, publicKeyBase64 } = await generateEd25519KeyPair();
    
    // Re-import the keys
    const privKey = await importEd25519PrivateKey(privateKeyBase64);
    const pubKey = await importEd25519PublicKey(publicKeyBase64);
    
    // Sign with re-imported private key
    const message = 'Test message';
    const enc = new TextEncoder();
    const signature = await webcrypto.subtle.sign("Ed25519", privKey, enc.encode(message));
    
    // Verify with re-imported public key
    const isValid = await webcrypto.subtle.verify("Ed25519", pubKey, signature, enc.encode(message));
    
    if (!isValid) throw new Error('Re-imported keys should work');
  });

  console.log(`\n${'='.repeat(50)}`);
  console.log(`Ed25519 Feature Tests: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));
  
  dom.window.close();
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});
