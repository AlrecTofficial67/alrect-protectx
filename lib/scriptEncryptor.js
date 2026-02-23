/**
 * lib/scriptEncryptor.js
 * Alrect Protect v2 — Script Encryptor
 *
 * Enkripsi script menggunakan dua layer:
 * Layer 1: XOR dengan key yang di-derive dari API key + request nonce (dynamic key!)
 * Layer 2: Base64 encode hasil XOR
 *
 * "Dynamic key" berarti setiap pengiriman script menghasilkan ciphertext berbeda
 * meskipun plaintext sama. Ini mencegah attacker membandingkan dua response
 * untuk mencari pola.
 *
 * Key derivation: HMAC-SHA256(SCRIPT_ENC_KEY, apiKey + ":" + nonce) → 32 bytes
 * XOR seed: integer dari SCRIPT_XOR_SEED env var
 *
 * KEJUJURAN: Ini adalah obfuscation, bukan enkripsi kuat (AES-GCM level).
 * Cukup untuk mencegah casual snooping dan mempersulit static analysis.
 * Client yang jujur bisa mendekripsi dengan key yang sama.
 */

const crypto = require("crypto");

/**
 * Derive encryption key dari SCRIPT_ENC_KEY + konteks request.
 * Key berbeda tiap request karena menggunakan nonce.
 * @param {string} apiKey
 * @param {string} nonce
 * @returns {Buffer} 32-byte derived key
 */
function deriveKey(apiKey, nonce) {
  const baseKey = process.env.SCRIPT_ENC_KEY || "";
  const context = `${apiKey}:${nonce}`;
  return crypto.createHmac("sha256", baseKey).update(context).digest();
}

/**
 * XOR buffer dengan key (repeating key XOR).
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {number} xorSeed - tambahan seed dari env untuk extra layer
 * @returns {Buffer}
 */
function xorBuffer(data, key, xorSeed) {
  const result = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    // XOR dengan byte dari derived key, lalu XOR lagi dengan seed modifikasi
    result[i] = data[i] ^ key[i % key.length] ^ ((xorSeed + i) & 0xff);
  }
  return result;
}

/**
 * Enkripsi script content untuk pengiriman ke client.
 * @param {string} plaintext  - Isi script asli
 * @param {string} apiKey     - API key dari request (untuk derive key)
 * @param {string} nonce      - Nonce dari request (untuk dynamic key)
 * @returns {{ ciphertext: string, keyHint: string }}
 *   ciphertext: Base64(XOR(plaintext))
 *   keyHint: HMAC dari derived key, dikirim ke client untuk verifikasi integritas
 */
function encryptScript(plaintext, apiKey, nonce) {
  const xorSeed = parseInt(process.env.SCRIPT_XOR_SEED || "42", 10);
  const derivedKey = deriveKey(apiKey, nonce);

  const plaintextBuf = Buffer.from(plaintext, "utf-8");
  const encrypted = xorBuffer(plaintextBuf, derivedKey, xorSeed);
  const ciphertext = encrypted.toString("base64");

  // Key hint memungkinkan client memverifikasi key derivation tanpa expose key
  const keyHint = crypto
    .createHmac("sha256", derivedKey)
    .update("alrect-verify")
    .digest("hex")
    .substring(0, 16); // Hanya 8 byte pertama sebagai hint

  return { ciphertext, keyHint };
}

/**
 * Dekripsi di sisi client (Python) — logika yang sama.
 * Diexport untuk dokumentasi/testing, tidak dipakai server.
 *
 * Di client Python:
 *   derived_key = hmac_sha256(SCRIPT_ENC_KEY, f"{api_key}:{nonce}")
 *   xor_seed = int(SCRIPT_XOR_SEED)
 *   encrypted = base64.b64decode(ciphertext)
 *   plaintext = bytes(b ^ derived_key[i % 32] ^ ((xor_seed + i) & 0xFF)
 *                     for i, b in enumerate(encrypted))
 */

module.exports = { encryptScript, deriveKey, xorBuffer };
