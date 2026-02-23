/**
 * lib/auditLogger.js
 * Alrect Protect v2 — Audit Logger
 *
 * Semua event dicatat dengan struktur konsisten:
 * - Log NORMAL: akses berhasil
 * - Log ATTACK: semua kegagalan auth, dengan reason detail
 *
 * Di Vercel: log ke stdout (Vercel Functions Logs dashboard)
 * Di local: log ke console + file di logs/
 *
 * Format: JSON per baris (JSON Lines / NDJSON)
 * Mudah di-parse oleh log aggregator (Datadog, Papertrail, dll)
 */

const fs   = require("fs");
const path = require("path");

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const LOG_DIR       = path.join(__dirname, "../logs");

// Pastikan folder logs ada (hanya di local)
if (!IS_PRODUCTION) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  } catch {
    // Folder mungkin sudah ada
  }
}

/**
 * Tulis log entry ke stdout dan (local only) ke file.
 * @param {"NORMAL"|"ATTACK"|"WARN"} type
 * @param {object} data
 */
function writeLog(type, data) {
  const entry = {
    ts:   new Date().toISOString(),
    type,
    ...data,
  };

  const line = JSON.stringify(entry);

  // Selalu ke stdout (Vercel akan tangkap ini)
  if (type === "ATTACK") {
    console.warn(line);
  } else {
    console.log(line);
  }

  // Local: juga tulis ke file terpisah
  if (!IS_PRODUCTION) {
    const filename = type === "ATTACK" ? "attack.log" : "access.log";
    try {
      fs.appendFileSync(path.join(LOG_DIR, filename), line + "\n", "utf-8");
    } catch {
      // Abaikan error tulis file di production
    }
  }
}

/**
 * Log akses berhasil.
 */
function logAccess({ ip, apiKey, script, deviceFp, sessionUsed }) {
  writeLog("NORMAL", {
    event:     "SCRIPT_SERVED",
    ip,
    apiKey:    maskKey(apiKey),
    script,
    deviceFp:  maskFp(deviceFp),
    sessionUsed: !!sessionUsed,
  });
}

/**
 * Log percobaan akses gagal (attack attempt).
 */
function logAttack({ ip, apiKey, path: reqPath, reason, code, ua }) {
  writeLog("ATTACK", {
    event:   "AUTH_FAILED",
    ip,
    apiKey:  apiKey ? maskKey(apiKey) : null,
    path:    reqPath,
    code,
    reason,
    ua:      ua ? ua.substring(0, 120) : null,
  });
}

/**
 * Log peringatan sistem (bukan auth failure, tapi anomali).
 */
function logWarn({ ip, message, detail }) {
  writeLog("WARN", { event: "SYSTEM_WARN", ip, message, detail });
}

/**
 * Log event penting sistem (startup, config change, dll).
 */
function logSystem(message, data = {}) {
  writeLog("NORMAL", { event: "SYSTEM", message, ...data });
}

// ============================================================
// Helper: Mask sensitive values untuk log
// ============================================================

/** Tampilkan 4 char pertama dan 4 terakhir dari API key */
function maskKey(key) {
  if (!key || key.length < 8) return "****";
  return key.substring(0, 4) + "****" + key.substring(key.length - 4);
}

/** Tampilkan 8 char pertama dari fingerprint */
function maskFp(fp) {
  if (!fp) return null;
  return fp.substring(0, 8) + "...";
}

module.exports = { logAccess, logAttack, logWarn, logSystem };
