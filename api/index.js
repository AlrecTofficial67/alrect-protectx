/**
 * api/index.js
 * Alrect Protect v2 — Main Server (Production Hardened)
 *
 * Route overview:
 *   GET  /               → Access Denied HTML (public)
 *   GET  /health         → Health check (public, no sensitive info)
 *   POST /session        → Minta session token (requires full auth)
 *   GET  /script/:name   → Ambil script terenkripsi (requires full auth)
 *   GET  /lua/:token     → Loadstring endpoint khusus Roblox executor
 *   POST /admin/reset    → Reset device binding (requires admin key)
 *   POST /admin/revoke   → Revoke API key permanen (requires admin key)
 */

require("dotenv").config();

const { validateEnv } = require("../lib/envValidator");
validateEnv();

const express    = require("express");
const path       = require("path");
const fs         = require("fs");
const rateLimit  = require("express-rate-limit");
const { authMiddleware, getClientIp, deny } = require("../lib/authMiddleware");
const { encryptScript }  = require("../lib/scriptEncryptor");
const { createSession }  = require("../lib/sessionManager");
const { resetDevice, revokeKey, getDeviceInfo } = require("../lib/deviceRegistry");
const { logAccess, logSystem, logAttack } = require("../lib/auditLogger");

const app  = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(express.json({ limit: "4kb" }));

// ============================================================
// SECURITY HEADERS
// ============================================================
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options",   "nosniff");
  res.setHeader("X-Frame-Options",          "DENY");
  res.setHeader("X-XSS-Protection",         "0");
  res.setHeader("Referrer-Policy",          "no-referrer");
  res.setHeader("Cache-Control",            "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma",                   "no-cache");
  res.setHeader("Strict-Transport-Security","max-age=63072000; includeSubDomains; preload");
  res.setHeader("X-Protected-By",           "Alrect-Protect/2.0");
  res.removeHeader("X-Powered-By");
  next();
});

// ============================================================
// RATE LIMITERS
// ============================================================

const globalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    logAttack({ ip: getClientIp(req), apiKey: req.headers["x-alrect-key"], path: req.path, code: "GLOBAL_RATE_LIMIT", reason: "Global rate limit exceeded", ua: req.headers["user-agent"] });
    res.status(429).json({ success: false, error: "RATE_LIMITED", message: "Terlalu banyak request" });
  },
});

const scriptLimiter = rateLimit({
  windowMs: 60 * 1000, max: 15,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    res.status(429).json({ success: false, error: "SCRIPT_RATE_LIMITED", message: "Terlalu banyak request script." });
  },
});

const sessionLimiter = rateLimit({
  windowMs: 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    res.status(429).json({ success: false, error: "SESSION_RATE_LIMITED" });
  },
});

const adminLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    res.status(429).json({ success: false, error: "ADMIN_RATE_LIMITED" });
  },
});

const luaLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  handler: (req, res) => {
    const ua = req.headers["user-agent"] || "";
    const isBrowser = /mozilla|chrome|safari|firefox|edge|opera/i.test(ua);
    if (isBrowser) {
      return res.status(429).sendFile("access-denied.html", { root: path.join(__dirname, "../public") });
    }
    res.status(429).type("text/plain").send('error("Rate limited")');
  },
});

app.use(globalLimiter);

// ============================================================
// PUBLIC ROUTES
// ============================================================

app.get("/", (req, res) => {
  res.status(403).sendFile("access-denied.html", {
    root: path.join(__dirname, "../public"),
  });
});

app.get("/health", (req, res) => {
  const isProd = process.env.NODE_ENV === "production";
  res.json({
    status: "ok",
    service: "Alrect Protect",
    ...(isProd ? {} : { version: "2.0.0", uptime: process.uptime() }),
  });
});

// ============================================================
// SESSION ENDPOINT
// ============================================================

app.post("/session", sessionLimiter, authMiddleware, (req, res) => {
  const { apiKey, deviceFp } = req.alrect;
  const token = createSession(apiKey, deviceFp);
  logAccess({ ip: req.alrect.ip, apiKey, script: "[session-create]", deviceFp, sessionUsed: false });
  res.json({ success: true, token, ttl: parseInt(process.env.SESSION_TTL || "300", 10) });
});

// ============================================================
// SCRIPT ENDPOINT — Protected
// ============================================================

app.get("/script/:name", scriptLimiter, authMiddleware, (req, res) => {
  const { apiKey, deviceFp, nonce, ip } = req.alrect;
  const scriptName = req.params.name;

  if (!/^[a-zA-Z0-9_\-\.]{1,64}$/.test(scriptName)) {
    return res.status(400).json({ success: false, error: "INVALID_NAME" });
  }

  const vaultDir   = path.resolve(__dirname, "../scripts-vault");
  const safeName   = path.basename(scriptName);
  const scriptPath = path.resolve(vaultDir, safeName);

  if (!scriptPath.startsWith(vaultDir + path.sep) && scriptPath !== vaultDir) {
    logAttack({ ip, apiKey, path: req.path, code: "PATH_TRAVERSAL", reason: "Path traversal attempt", ua: req.headers["user-agent"] });
    return res.status(403).json({ success: false, error: "PATH_VIOLATION" });
  }

  if (!fs.existsSync(scriptPath)) {
    return res.status(404).json({ success: false, error: "NOT_FOUND" });
  }

  let content;
  try {
    content = fs.readFileSync(scriptPath, "utf-8");
  } catch (err) {
    logAttack({ ip, apiKey, path: req.path, code: "READ_ERROR", reason: err.message, ua: req.headers["user-agent"] });
    return res.status(500).json({ success: false, error: "READ_ERROR" });
  }

  let encrypted;
  try {
    encrypted = encryptScript(content, apiKey, nonce);
  } catch (err) {
    return res.status(500).json({ success: false, error: "ENCRYPT_ERROR" });
  }

  logAccess({ ip, apiKey, script: safeName, deviceFp, sessionUsed: false });

  res.json({
    success:    true,
    script:     safeName,
    ciphertext: encrypted.ciphertext,
    keyHint:    encrypted.keyHint,
    nonce,
    encoding:   "base64-xor",
    xorSeed:    parseInt(process.env.SCRIPT_XOR_SEED || "42", 10),
  });
});

// ============================================================
// LUA LOADSTRING ENDPOINT — Khusus Roblox Executor
// Browser  → Access Denied HTML
// Executor → Plain text Lua script
// Penggunaan: loadstring(game:HttpGet("URL/lua/TOKEN"))()
// ============================================================

const LUA_TOKENS = {
  "50b51f3ed6666b9ee70ab2c6": "example.lua",
  // Tambah token lain di sini:
  // "token_baru": "script_lain.lua",
};

app.get("/lua/:token", luaLimiter, (req, res) => {
  const token = req.params.token;
  const ip    = getClientIp(req);
  const ua    = req.headers["user-agent"] || "";

  // Deteksi browser → tampil halaman Access Denied
  const isBrowser = /mozilla|chrome|safari|firefox|edge|opera|webkit/i.test(ua);
  if (isBrowser) {
    return res.status(403).sendFile("access-denied.html", {
      root: path.join(__dirname, "../public"),
    });
  }

  // Cek token valid
  const scriptName = LUA_TOKENS[token];
  if (!scriptName) {
    logAttack({
      ip,
      apiKey: null,
      path:   req.path,
      code:   "LUA_TOKEN_INVALID",
      reason: "Token tidak valid",
      ua,
    });
    return res.status(200).type("text/plain").send('error("Unauthorized")');
  }

  // Baca script dari vault
  const vaultDir   = path.resolve(__dirname, "../scripts-vault");
  const scriptPath = path.resolve(vaultDir, scriptName);

  if (!scriptPath.startsWith(vaultDir) || !fs.existsSync(scriptPath)) {
    return res.status(200).type("text/plain").send('error("Not found")');
  }

  try {
    const content = fs.readFileSync(scriptPath, "utf-8");
    logAccess({ ip, apiKey: token.substring(0, 8) + "...", script: scriptName, deviceFp: "roblox-executor" });
    res.type("text/plain").send(content);
  } catch (err) {
    res.status(200).type("text/plain").send('error("Internal error")');
  }
});

// ============================================================
// ADMIN ENDPOINTS
// ============================================================

function adminAuth(req, res, next) {
  const ADMIN_KEY = process.env.ADMIN_KEY;
  if (!ADMIN_KEY) {
    return res.status(503).json({ success: false, error: "ADMIN_DISABLED" });
  }
  const providedKey = req.headers["x-alrect-admin-key"];
  if (!providedKey || providedKey !== ADMIN_KEY) {
    logAttack({ ip: getClientIp(req), apiKey: null, path: req.path, code: "ADMIN_AUTH_FAILED", reason: "Invalid admin key", ua: req.headers["user-agent"] });
    return res.status(403).json({ success: false, error: "UNAUTHORIZED" });
  }
  next();
}

app.post("/admin/reset", adminLimiter, adminAuth, (req, res) => {
  const { apiKey } = req.body || {};
  if (!apiKey || typeof apiKey !== "string") {
    return res.status(400).json({ success: false, error: "API key diperlukan" });
  }
  const ok = resetDevice(apiKey);
  logSystem("Device reset", { targetKey: apiKey.substring(0, 8) + "..." });
  res.json({ success: true, message: ok ? "Device binding berhasil direset" : "API key tidak ditemukan" });
});

app.post("/admin/revoke", adminLimiter, adminAuth, (req, res) => {
  const { apiKey } = req.body || {};
  if (!apiKey || typeof apiKey !== "string") {
    return res.status(400).json({ success: false, error: "API key diperlukan" });
  }
  revokeKey(apiKey);
  logSystem("API key revoked", { targetKey: apiKey.substring(0, 8) + "..." });
  res.json({ success: true, message: "API key berhasil direvoke." });
});

app.post("/admin/device-info", adminLimiter, adminAuth, (req, res) => {
  const { apiKey } = req.body || {};
  if (!apiKey) {
    return res.status(400).json({ success: false, error: "API key diperlukan" });
  }
  const info = getDeviceInfo(apiKey);
  res.json({
    success: true,
    data: info ? { fingerprint: info.fingerprint.substring(0, 16) + "...", registeredAt: info.registeredAt } : null,
    message: info ? "Device ditemukan" : "Tidak ada device terdaftar",
  });
});

// ============================================================
// CATCH ALL — 404
// ============================================================
app.use((req, res) => {
  res.status(404).sendFile("access-denied.html", {
    root: path.join(__dirname, "../public"),
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
});

// ============================================================
// START
// ============================================================
if (require.main === module) {
  app.listen(PORT, () => {
    logSystem("Server started", { port: PORT, env: process.env.NODE_ENV || "development" });
    console.log(`\n✅ Alrect Protect v2 berjalan di http://localhost:${PORT}\n`);
  });
}

module.exports = app;
