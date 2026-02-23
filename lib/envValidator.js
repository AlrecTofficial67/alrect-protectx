/**
 * lib/envValidator.js
 * Alrect Protect v2 — Environment Variable Validator
 *
 * Dijalankan saat startup. Jika ada env var wajib yang kosong
 * atau lemah, server MENOLAK untuk start. Ini mencegah deploy
 * dengan konfigurasi insecure secara tidak sengaja.
 */

const REQUIRED = [
  {
    key: "HMAC_SECRET",
    minLen: 32,
    desc: "HMAC signing secret (min 32 karakter)",
  },
  {
    key: "API_KEY",
    minLen: 16,
    desc: "Master API key (min 16 karakter)",
  },
  {
    key: "SCRIPT_ENC_KEY",
    minLen: 16,
    desc: "Script encryption key (min 16 karakter)",
  },
];

/**
 * Validasi semua env var yang diperlukan.
 * @throws {Error} jika ada yang tidak valid
 */
function validateEnv() {
  const errors = [];

  for (const req of REQUIRED) {
    const val = process.env[req.key];
    if (!val || val.trim() === "") {
      errors.push(`  ✗ ${req.key} tidak ada — ${req.desc}`);
      continue;
    }
    if (val.length < req.minLen) {
      errors.push(
        `  ✗ ${req.key} terlalu pendek (${val.length} < ${req.minLen}) — ${req.desc}`
      );
    }
  }

  // Deteksi penggunaan nilai default/placeholder yang tidak aman
  const dangerous = [
    "ganti_",
    "your_",
    "change_me",
    "secret",
    "password",
    "123456",
    "example",
  ];
  for (const req of REQUIRED) {
    const val = (process.env[req.key] || "").toLowerCase();
    for (const d of dangerous) {
      if (val.includes(d)) {
        errors.push(
          `  ✗ ${req.key} menggunakan nilai placeholder yang tidak aman`
        );
        break;
      }
    }
  }

  if (errors.length > 0) {
    console.error("\n🚨 ALRECT PROTECT: Konfigurasi tidak valid!\n");
    console.error(errors.join("\n"));
    console.error("\nSalin .env.example → .env dan isi semua nilai dengan benar.\n");
    process.exit(1);
  }

  console.log("✅ Env validation OK");
}

module.exports = { validateEnv };
