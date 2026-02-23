/**
 * lib/crypto.js
 * Alrect Protect - Modul kriptografi
 * Berisi fungsi HMAC SHA256 signing dan verification
 */

const crypto = require("crypto");

/**
 * Buat HMAC SHA256 signature dari data yang diberikan.
 * @param {string} data   - String yang akan di-sign
 * @param {string} secret - Secret key HMAC
 * @returns {string}        Hex digest signature
 */
function createSignature(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

/**
 * Verifikasi signature dengan cara constant-time comparison
 * untuk mencegah timing attack.
 * @param {string} data      - String yang di-sign
 * @param {string} secret    - Secret key HMAC
 * @param {string} signature - Signature yang diterima dari client
 * @returns {boolean}
 */
function verifySignature(data, secret, signature) {
  if (!signature || typeof signature !== "string") return false;
  const expected = createSignature(data, secret);
  try {
    // timingSafeEqual mencegah attacker menebak signature karakter per karakter
    return crypto.timingSafeEqual(
      Buffer.from(expected, "hex"),
      Buffer.from(signature, "hex")
    );
  } catch {
    return false;
  }
}

module.exports = { createSignature, verifySignature };
