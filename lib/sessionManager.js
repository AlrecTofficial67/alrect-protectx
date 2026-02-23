/**
 * lib/sessionManager.js
 * Alrect Protect v2 — Session Token Manager
 *
 * Flow session:
 * 1. Client request session token via POST /session
 *    (autentikasi penuh HMAC diperlukan)
 * 2. Server buat session token (sekali pakai, expire TTL detik)
 * 3. Client pakai session token untuk GET /script/:name
 *    Setelah dipakai → token HANGUS otomatis
 *
 * Ini OPSIONAL di atas HMAC. Memberi window akses yang sangat sempit.
 *
 * CATATAN: In-memory. Di Vercel serverless, gunakan Upstash Redis
 * untuk persistence across instances. Lihat TUTORIAL.md.
 */

const crypto = require("crypto");

// Map: token → { apiKey, deviceFp, expiresAt, used }
const sessionStore = new Map();

// Cleanup interval — hapus token expired setiap 60 detik
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessionStore.entries()) {
    if (now > session.expiresAt || session.used) {
      sessionStore.delete(token);
    }
  }
}, 60 * 1000);

/**
 * Buat session token baru untuk kombinasi apiKey + device.
 * @param {string} apiKey
 * @param {string} deviceFp
 * @returns {string} token
 */
function createSession(apiKey, deviceFp) {
  const ttlMs = parseInt(process.env.SESSION_TTL || "300", 10) * 1000;
  const token = crypto.randomBytes(32).toString("hex"); // 64-char hex token

  sessionStore.set(token, {
    apiKey,
    deviceFp,
    expiresAt: Date.now() + ttlMs,
    used: false,
    createdAt: new Date().toISOString(),
  });

  return token;
}

/**
 * Validasi dan konsumsi session token.
 * Token langsung ditandai 'used' sehingga tidak bisa dipakai lagi.
 * @param {string} token
 * @param {string} apiKey
 * @param {string} deviceFp
 * @returns {{ ok: boolean, reason?: string }}
 */
function consumeSession(token, apiKey, deviceFp) {
  if (!token || token.length !== 64) {
    return { ok: false, reason: "Format token tidak valid" };
  }

  const session = sessionStore.get(token);
  if (!session) {
    return { ok: false, reason: "Token tidak ditemukan atau sudah expired" };
  }

  if (session.used) {
    return { ok: false, reason: "Token sudah pernah digunakan (sekali pakai)" };
  }

  if (Date.now() > session.expiresAt) {
    sessionStore.delete(token);
    return { ok: false, reason: "Token sudah expired" };
  }

  if (session.apiKey !== apiKey) {
    return { ok: false, reason: "Token bukan milik API key ini" };
  }

  if (session.deviceFp !== deviceFp) {
    return { ok: false, reason: "Device fingerprint tidak cocok dengan session" };
  }

  // Tandai sebagai sudah dipakai
  session.used = true;
  return { ok: true };
}

/**
 * Informasi session aktif untuk API key tertentu (admin use).
 * @param {string} apiKey
 * @returns {number} jumlah session aktif
 */
function getActiveSessionCount(apiKey) {
  let count = 0;
  const now = Date.now();
  for (const [, session] of sessionStore.entries()) {
    if (session.apiKey === apiKey && !session.used && now <= session.expiresAt) {
      count++;
    }
  }
  return count;
}

module.exports = { createSession, consumeSession, getActiveSessionCount };
