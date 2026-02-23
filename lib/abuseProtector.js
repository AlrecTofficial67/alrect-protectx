/**
 * lib/abuseProtector.js
 * Alrect Protect v2 — Abuse Protection System
 *
 * Fitur:
 * - Counter kegagalan per-IP
 * - Counter kegagalan per-API-Key
 * - Auto blacklist setelah threshold terlampaui
 * - Blacklist dengan TTL (bukan permanen, tapi bisa dikonfigurasi panjang)
 * - Berbeda dari express-rate-limit yang hanya cek frequency:
 *   ini cek FAILURE count, lebih tepat untuk deteksi brute-force
 */

// ============================================================
// KONFIGURASI
// ============================================================
const CONFIG = {
  // Berapa kali boleh gagal sebelum di-blacklist
  MAX_FAILURES_PER_IP: 10,
  MAX_FAILURES_PER_KEY: 5,

  // Berapa lama blacklist berlaku (ms)
  BLACKLIST_TTL_MS: 15 * 60 * 1000, // 15 menit

  // Window waktu penghitungan failure (ms)
  FAILURE_WINDOW_MS: 5 * 60 * 1000, // 5 menit

  // Reset failure counter setelah berhasil
  RESET_ON_SUCCESS: true,
};

// Map: identifier (IP/key) → { count, firstFailAt, blacklistedUntil? }
const ipTracker  = new Map();
const keyTracker = new Map();

/**
 * Catat kegagalan untuk IP dan API key.
 * @param {string} ip
 * @param {string|null} apiKey
 * @returns {{ blacklisted: boolean, reason?: string }}
 */
function recordFailure(ip, apiKey = null) {
  const now = Date.now();

  // Track by IP
  const ipResult = trackFailure(ipTracker, ip, CONFIG.MAX_FAILURES_PER_IP, now);

  // Track by API key (jika tersedia)
  let keyResult = { blacklisted: false };
  if (apiKey) {
    keyResult = trackFailure(keyTracker, apiKey, CONFIG.MAX_FAILURES_PER_KEY, now);
  }

  if (ipResult.blacklisted) {
    return { blacklisted: true, reason: `IP ${ip} di-blacklist: terlalu banyak percobaan gagal` };
  }
  if (keyResult.blacklisted) {
    return { blacklisted: true, reason: `API key di-blacklist: terlalu banyak percobaan gagal` };
  }

  return { blacklisted: false };
}

/**
 * Internal: tambah counter kegagalan dan cek threshold.
 */
function trackFailure(tracker, id, maxFailures, now) {
  let entry = tracker.get(id);

  if (!entry) {
    entry = { count: 0, firstFailAt: now, blacklistedUntil: null };
    tracker.set(id, entry);
  }

  // Reset window jika sudah lewat window time
  if (now - entry.firstFailAt > CONFIG.FAILURE_WINDOW_MS) {
    entry.count = 0;
    entry.firstFailAt = now;
    entry.blacklistedUntil = null;
  }

  entry.count++;

  if (entry.count >= maxFailures) {
    entry.blacklistedUntil = now + CONFIG.BLACKLIST_TTL_MS;
    return { blacklisted: true };
  }

  return { blacklisted: false };
}

/**
 * Cek apakah IP atau API key sedang di-blacklist.
 * @param {string} ip
 * @param {string|null} apiKey
 * @returns {{ blocked: boolean, reason?: string, retryAfterMs?: number }}
 */
function isBlacklisted(ip, apiKey = null) {
  const now = Date.now();

  const ipEntry = ipTracker.get(ip);
  if (ipEntry?.blacklistedUntil && now < ipEntry.blacklistedUntil) {
    return {
      blocked: true,
      reason: "IP sementara diblokir karena terlalu banyak percobaan",
      retryAfterMs: ipEntry.blacklistedUntil - now,
    };
  }

  if (apiKey) {
    const keyEntry = keyTracker.get(apiKey);
    if (keyEntry?.blacklistedUntil && now < keyEntry.blacklistedUntil) {
      return {
        blocked: true,
        reason: "API key sementara diblokir",
        retryAfterMs: keyEntry.blacklistedUntil - now,
      };
    }
  }

  return { blocked: false };
}

/**
 * Reset counter setelah request berhasil.
 * @param {string} ip
 * @param {string|null} apiKey
 */
function recordSuccess(ip, apiKey = null) {
  if (!CONFIG.RESET_ON_SUCCESS) return;
  ipTracker.delete(ip);
  if (apiKey) keyTracker.delete(apiKey);
}

/**
 * Bersihkan entries lama (panggil periodik atau saat startup).
 */
function cleanup() {
  const now = Date.now();
  for (const [id, entry] of ipTracker.entries()) {
    if (
      now - entry.firstFailAt > CONFIG.FAILURE_WINDOW_MS &&
      (!entry.blacklistedUntil || now > entry.blacklistedUntil)
    ) {
      ipTracker.delete(id);
    }
  }
  for (const [id, entry] of keyTracker.entries()) {
    if (
      now - entry.firstFailAt > CONFIG.FAILURE_WINDOW_MS &&
      (!entry.blacklistedUntil || now > entry.blacklistedUntil)
    ) {
      keyTracker.delete(id);
    }
  }
}

// Cleanup setiap 10 menit
setInterval(cleanup, 10 * 60 * 1000);

module.exports = { recordFailure, isBlacklisted, recordSuccess };
