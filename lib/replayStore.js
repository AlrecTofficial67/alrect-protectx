/**
 * lib/replayStore.js
 * Alrect Protect v2 — Anti-Replay Nonce Store
 *
 * Menyimpan nonce yang sudah digunakan untuk mencegah replay attack.
 * Nonce di-expire setelah NONCE_TTL_MS.
 * Map size di-cap untuk mencegah memory exhaustion (DoS via nonce flood).
 *
 * CATATAN PRODUKSI:
 * Di Vercel, setiap cold start menghasilkan instance baru → store kosong.
 * Attacker yang tahu ini bisa mencoba replay tepat saat cold start.
 * Mitigasi: window timestamp yang ketat (30 detik) membatasi window exploit.
 * Solusi enterprise: Upstash Redis dengan SETNX + TTL.
 */

const NONCE_TTL_MS  = 90 * 1000; // Simpan 90 detik (3x window timestamp)
const MAX_STORE_SIZE = 10_000;   // Maksimum 10k nonce (proteksi OOM)

// Map: nonce (string) → timestamp kapan pertama kali terlihat
const nonceMap = new Map();

/**
 * Cek apakah nonce sudah pernah dipakai. Jika belum, daftarkan.
 * @param {string} nonce
 * @returns {boolean} true = sudah pernah dipakai (REPLAY)
 */
function isReplay(nonce) {
  cleanup();

  if (nonceMap.has(nonce)) return true;

  // Tolak jika store sudah penuh (DoS protection)
  if (nonceMap.size >= MAX_STORE_SIZE) {
    // Hapus entri terlama secara paksa
    const oldest = nonceMap.keys().next().value;
    nonceMap.delete(oldest);
  }

  nonceMap.set(nonce, Date.now());
  return false;
}

/**
 * Hapus nonce yang sudah expired.
 * Dipanggil setiap kali isReplay() dipanggil.
 */
function cleanup() {
  const now = Date.now();
  // Map.entries() mengembalikan insertion order — hapus dari depan (terlama)
  for (const [nonce, ts] of nonceMap.entries()) {
    if (now - ts > NONCE_TTL_MS) {
      nonceMap.delete(nonce);
    } else {
      break; // Map sorted by insertion time, sisanya masih valid
    }
  }
}

/** Jumlah nonce aktif (untuk monitoring) */
function storeSize() {
  return nonceMap.size;
}

module.exports = { isReplay, storeSize };
