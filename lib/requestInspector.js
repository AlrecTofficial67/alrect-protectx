/**
 * lib/requestInspector.js
 * Alrect Protect v2 — Advanced Request Inspector
 *
 * Analisis mendalam pola request untuk mendeteksi:
 * - curl / wget / httpie bahkan setelah UA di-spoof
 * - Postman / Insomnia / API tools
 * - Script bot yang tidak memiliki pola header browser nyata
 *
 * PRINSIP: Client resmi kita (AlrectClient) memiliki "fingerprint header"
 * yang konsisten dan diverifikasi server. Tool lain tidak akan tahu
 * kombinasi header mana yang wajib ada.
 *
 * Ini BUKAN pengganti HMAC. Ini lapisan tambahan sebelum HMAC dicek,
 * untuk menyaring traffic noise lebih awal.
 */

// ============================================================
// Header yang WAJIB ada di request client resmi kita
// Client yang tidak tahu daftar ini tidak bisa lolos
// ============================================================
const REQUIRED_CUSTOM_HEADERS = [
  "x-alrect-key",
  "x-alrect-timestamp",
  "x-alrect-nonce",
  "x-alrect-signature",
  "x-alrect-device",
];

// ============================================================
// Header yang menandakan tool HTTP umum
// curl by default TIDAK mengirim Accept-Language dan Accept-Encoding dengan gzip,br
// wget tidak mengirim Accept header yang benar
// ============================================================

// UA yang diblokir (pattern)
const BLOCKED_UA_PATTERNS = [
  /^curl\//i,
  /^wget\//i,
  /^python-requests\//i,
  /^python\//i,
  /^go-http-client\//i,
  /^java\//i,
  /^okhttp\//i,
  /^apache-httpclient/i,
  /^axios\//i,
  /^node-fetch\//i,
  /^got\//i,
  /^ky\//i,
  /^undici\//i,
  /postmanruntime/i,
  /insomnia\//i,
  /httpie\//i,
  /paw\//i,
  /restsharp/i,
  /libwww-perl/i,
  /lwp-useragent/i,
  /scrapy/i,
  /mechanize/i,
  /ruby/i,
  /php/i,
  /dart:/i,
  /mozilla/i,    // Blokir browser
  /chrome/i,
  /safari/i,
  /firefox/i,
  /msie/i,
  /trident/i,
  /edg\//i,
  /opr\//i,
];

// UA yang WAJIB ada (string exact substring)
const REQUIRED_UA_SUBSTRING = "AlrectClient/1.0";

// ============================================================
// Accept header yang mencurigakan
// curl default: */*
// wget: */*
// Browser: text/html,application/xhtml+xml,...
// Client resmi kita: application/json
// ============================================================
const SUSPICIOUS_ACCEPT = [
  "*/*",           // curl/wget default
  "text/html",     // browser (sudah diblokir UA, tapi defence in depth)
];

// Accept-Encoding yang mencurigakan
// curl: --compressed baru mengirim gzip
// Client resmi kita WAJIB tidak mengirim Accept-Encoding
// (karena kita mau raw text, bukan compressed response)
const FORBIDDEN_ACCEPT_ENCODING_VALUES = ["br", "deflate", "zstd"];

// Header yang TIDAK BOLEH ada (dikirim browser/tool tapi bukan client kita)
const FORBIDDEN_HEADERS = [
  "sec-fetch-site",      // Chrome/Firefox only
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "upgrade-insecure-requests",
  "cache-control",       // Browser cache control
  "pragma",
  "origin",              // CORS preflight (browser)
  "referer",             // Kebocoran dari browser
];

/**
 * Inspeksi request secara mendalam.
 * @param {import('express').Request} req
 * @returns {{ ok: boolean, reason: string, code: string }}
 */
function inspectRequest(req) {
  const ua = req.headers["user-agent"] || "";
  const headers = req.headers;

  // --- 1. Cek UA terhadap daftar blokir ---
  for (const pattern of BLOCKED_UA_PATTERNS) {
    if (pattern.test(ua)) {
      return { ok: false, code: "UA_BLOCKED", reason: `User-Agent diblokir` };
    }
  }

  // --- 2. UA wajib mengandung identifier client resmi ---
  if (!ua.includes(REQUIRED_UA_SUBSTRING)) {
    return { ok: false, code: "UA_INVALID", reason: "User-Agent tidak dikenal" };
  }

  // --- 3. Cek header terlarang (menandai browser/bot) ---
  for (const h of FORBIDDEN_HEADERS) {
    if (headers[h] !== undefined) {
      return {
        ok: false,
        code: "HEADER_FORBIDDEN",
        reason: `Header terlarang terdeteksi: ${h}`,
      };
    }
  }

  // --- 4. Cek Accept header ---
  const accept = (headers["accept"] || "").toLowerCase();
  // Accept harus application/json, bukan wildcard atau HTML
  if (accept && accept !== "application/json") {
    for (const sus of SUSPICIOUS_ACCEPT) {
      if (accept.includes(sus)) {
        return {
          ok: false,
          code: "ACCEPT_SUSPICIOUS",
          reason: "Accept header mencurigakan",
        };
      }
    }
  }

  // --- 5. Cek Accept-Encoding ---
  const encoding = (headers["accept-encoding"] || "").toLowerCase();
  if (encoding) {
    for (const forbidden of FORBIDDEN_ACCEPT_ENCODING_VALUES) {
      if (encoding.includes(forbidden)) {
        return {
          ok: false,
          code: "ENCODING_SUSPICIOUS",
          reason: "Accept-Encoding mencurigakan (pola browser/tool)",
        };
      }
    }
  }

  // --- 6. Semua custom header wajib ada ---
  for (const h of REQUIRED_CUSTOM_HEADERS) {
    if (!headers[h]) {
      return {
        ok: false,
        code: "HEADER_MISSING",
        reason: `Header wajib tidak ada: ${h}`,
      };
    }
  }

  // --- 7. Cek Connection header ---
  // curl sering mengirim: Connection: keep-alive (tapi juga bisa spoofed)
  // Kita tidak blokir keep-alive karena valid, tapi blokir "upgrade"
  const conn = (headers["connection"] || "").toLowerCase();
  if (conn.includes("upgrade")) {
    return {
      ok: false,
      code: "CONNECTION_SUSPICIOUS",
      reason: "Connection header mencurigakan",
    };
  }

  return { ok: true, code: "OK", reason: "" };
}

module.exports = { inspectRequest };
