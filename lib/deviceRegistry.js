/**
 * lib/deviceRegistry.js
 * Alrect Protect v2 — Device Registry dengan Revoke Support
 *
 * Mengikat API key ke fingerprint perangkat (HWID concept).
 * Mendukung: auto-register, reset perangkat, revoke permanen.
 *
 * Untuk produksi: ganti Map dengan Upstash Redis / database.
 */

// Map: apiKey → { fingerprint, registeredAt }
const deviceRegistry = new Map();

// Set: API key yang direvoke secara permanen
const revokedKeys = new Set();

// Load revoked keys dari env var saat startup
// Format env: REVOKED_KEYS="key1,key2,key3"
const envRevoked = (process.env.REVOKED_KEYS || "").split(",").filter(Boolean);
for (const k of envRevoked) revokedKeys.add(k.trim());

/**
 * Validasi atau daftarkan fingerprint untuk API key.
 * Fingerprint WAJIB SHA256 hex 64 karakter.
 * @returns {{ ok: boolean, reason?: string, isNew?: boolean }}
 */
function validateDevice(apiKey, fingerprint) {
  if (revokedKeys.has(apiKey)) {
    return { ok: false, reason: "API key telah direvoke" };
  }

  if (!fingerprint || fingerprint.length < 16) {
    return { ok: false, reason: "Fingerprint tidak valid" };
  }

  // Hanya terima SHA256 hex (64 char lowercase hex)
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
    return { ok: false, reason: "Format fingerprint tidak valid (harus SHA256 hex)" };
  }

  const existing = deviceRegistry.get(apiKey);

  if (!existing) {
    deviceRegistry.set(apiKey, {
      fingerprint,
      registeredAt: new Date().toISOString(),
    });
    return { ok: true, isNew: true };
  }

  if (existing.fingerprint === fingerprint) {
    return { ok: true, isNew: false };
  }

  return {
    ok: false,
    reason: "Fingerprint tidak cocok. Hubungi admin untuk reset perangkat.",
  };
}

/**
 * Reset binding device — izinkan perangkat baru mendaftar ulang.
 * @returns {boolean}
 */
function resetDevice(apiKey) {
  if (!deviceRegistry.has(apiKey)) return false;
  deviceRegistry.delete(apiKey);
  return true;
}

/**
 * Revoke API key secara permanen (session ini).
 * Untuk permanent: tambah ke env REVOKED_KEYS.
 */
function revokeKey(apiKey) {
  revokedKeys.add(apiKey);
  deviceRegistry.delete(apiKey);
}

/** Cek apakah API key sudah direvoke */
function isRevoked(apiKey) {
  return revokedKeys.has(apiKey);
}

/** Info device terdaftar (untuk admin endpoint) */
function getDeviceInfo(apiKey) {
  return deviceRegistry.get(apiKey) || null;
}

module.exports = { validateDevice, resetDevice, revokeKey, isRevoked, getDeviceInfo };
