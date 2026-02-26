# Encrypted Morse Messenger (Offline Web Tool)

A tiny **offline-friendly** single-page web app that:

- Encrypts a message with **AES-256-GCM**
- Encodes the ciphertext (salt + IV + ciphertext+tag) as **hex → Morse**
- Lets you **copy/paste** the Morse string or **play it as audio beeps**
- Decrypts the Morse back to the original message using the same password

> No servers. No accounts. Everything runs locally in your browser.

---

## Demo / Screenshot

- After you enable GitHub Pages, your live URL will look like: `https://<your-user>.github.io/<repo-name>/`

---

## How it works

**Transmit (Encrypt → Morse):**
1. Type a message
2. Enter a password
3. Click **Transmit**
4. Copy the generated Morse (or play it as beeps)

**Receive (Morse → Decrypt):**
1. Paste the received Morse string
2. Enter the same password
3. Click **Decrypt**

---

## Cryptography details

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** PBKDF2-HMAC-SHA256  
  - salt: 16 bytes (random)
  - iterations: 150,000
- **IV/nonce:** 12 bytes (random)
- **Payload format (binary):** `salt (16) || iv (12) || ciphertext+tag (N)`
- **Export format:** hex string → Morse mapping for hex digits (`0-9`, `A-F`)

---

## Files

This repo is intentionally minimal:

- `index.html` — the entire app (HTML + CSS + JS)

---

## Run locally

### Option A: just open the file
1. Download / clone the repo
2. Double-click `index.html` to open it in your browser

### Option B: run a tiny local server (recommended)
Some browsers restrict clipboard/audio in `file://` mode.

**Python:**
```bash
python -m http.server 8000
