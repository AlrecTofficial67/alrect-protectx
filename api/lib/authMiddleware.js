/**
 * lib/authMiddleware.js
 * Alrect Protect v2 — Middleware Autentikasi (Rebuilt)
 *
 * Urutan validasi (semua harus LULUS):
 * 0. Cek blacklist (IP & Key)
 * 1. Request inspection (UA, header pattern, anti-curl advanced)
 * 2. API Key valid & tidak direvoke
 * 3. Timestamp dalam toleransi
 * 4. Nonce belum pernah dipakai (anti-replay)
 * 5. HMAC SHA256 signature valid
 * 6. Device fingerprint terdaftar & cocok
 *
 * Setiap kegagalan: catat ke audit log + tambah abuse counter
 */

const { verifySignature }  = require("./crypto");
const { isReplay }         = require("./replayStore");
const { validateDevice }   = require("./deviceRegistry");
const { inspectRequest }   = require("./requestInspector");
const { isBlacklisted, recordFailure, recordSuccess } = require("./abuseProtector");
const { logAttack, logAccess } = require("./auditLogger");
const path = require("path");

/**
 * Middleware autentikasi utama.
 */
function authMiddleware(req, res, next) {
  const HMAC_SECRET         = process.env.HMAC_SECRET;
  const VALID_API_KEY       = process.env.API_KEY;
  const TIMESTAMP_TOLERANCE = parseInt(process.env.TIMESTAMP_TOLERANCE || "30", 10);

  const ip     = getClientIp(req);
  const apiKey = req.headers["x-alrect-key"] || null;

  // ─── LAYER 0: Blacklist check ────────────────────────────
  const blResult = isBlacklisted(ip, apiKey);
  if (blResult.blocked) {
    const retryAfter = Math.ceil((blResult.retryAfterMs || 60000) / 1000);
    res.setHeader("Retry-After", String(retryAfter));
    return deny(req, res, ip, apiKey, "BLACKLISTED", blResult.reason, 429);
  }

  // ─── LAYER 1: Request inspection (anti-curl advanced) ────
  const inspection = inspectRequest(req);
  if (!inspection.ok) {
    recordFailure(ip, null); // Jangan expose bahwa key valid/invalid saat UA salah
    return deny(req, res, ip, null, inspection.code, inspection.reason);
  }

  // ─── LAYER 2: API Key ────────────────────────────────────
  if (!apiKey || apiKey !== VALID_API_KEY) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "KEY_INVALID", "API Key tidak valid");
  }

  // ─── LAYER 3: Timestamp ──────────────────────────────────
  const tsHeader = req.headers["x-alrect-timestamp"];
  if (!tsHeader) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "TIMESTAMP_MISSING", "Timestamp tidak ada");
  }

  const requestTime = parseInt(tsHeader, 10);
  if (isNaN(requestTime)) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "TIMESTAMP_INVALID", "Format timestamp tidak valid");
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const diff   = Math.abs(nowSec - requestTime);
  if (diff > TIMESTAMP_TOLERANCE) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "TIMESTAMP_EXPIRED", `Timestamp kedaluwarsa (${diff}s)`);
  }

  // ─── LAYER 4: Nonce (Anti-Replay) ────────────────────────
  const nonce = req.headers["x-alrect-nonce"];
  if (!nonce || nonce.length < 16) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "NONCE_INVALID", "Nonce tidak ada atau terlalu pendek");
  }

  if (isReplay(nonce)) {
    // Double penalty untuk replay attack
    recordFailure(ip, apiKey);
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "REPLAY_DETECTED", "Request duplikat terdeteksi");
  }

  // ─── LAYER 5: HMAC Signature ─────────────────────────────
  const signature = req.headers["x-alrect-signature"];
  if (!signature) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "SIG_MISSING", "Signature tidak ada");
  }

  // Format signed data: "apiKey:timestamp:nonce:path"
  const signedData = `${apiKey}:${tsHeader}:${nonce}:${req.path}`;
  if (!verifySignature(signedData, HMAC_SECRET, signature)) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "SIG_INVALID", "Signature tidak valid");
  }

  // ─── LAYER 6: Device Fingerprint ─────────────────────────
  const deviceFp = req.headers["x-alrect-device"];
  if (!deviceFp) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "DEVICE_MISSING", "Device fingerprint tidak ada");
  }

  const deviceCheck = validateDevice(apiKey, deviceFp);
  if (!deviceCheck.ok) {
    recordFailure(ip, apiKey);
    return deny(req, res, ip, apiKey, "DEVICE_MISMATCH", deviceCheck.reason);
  }

  // ─── SEMUA LULUS ─────────────────────────────────────────
  recordSuccess(ip, apiKey);

  // Attach context untuk handler
  req.alrect = {
    ip,
    apiKey,
    deviceFp,
    nonce,
    timestamp: tsHeader,
    isNewDevice: deviceCheck.isNew,
  };

  next();
}

/**
 * Kirim respons penolakan.
 */
function deny(req, res, ip, apiKey, code, reason, status = 403) {
  logAttack({
    ip,
    apiKey,
    path: req.path,
    code,
    reason,
    ua: req.headers["user-agent"],
  });

  // Endpoint API selalu JSON
  if (req.path.startsWith("/script") || req.path.startsWith("/session") || req.path.startsWith("/admin")) {
    return res.status(status).json({
      success: false,
      error: code,
      message: "Akses ditolak",
    });
  }

  return res.status(status).sendFile("access-denied.html", {
    root: path.join(__dirname, "../public"),
  });
}

/**
 * Ambil IP client yang sebenarnya (Vercel proxy-aware).
 */
function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.socket?.remoteAddress || req.ip || "0.0.0.0";
}

module.exports = { authMiddleware, getClientIp, deny };
