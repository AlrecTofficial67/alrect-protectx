#!/usr/bin/env python3
"""
client/alrect-client.py
Alrect Protect v2 — Official Python Client

Fitur:
- HMAC SHA256 signing
- Anti-replay nonce (UUID)
- Device fingerprint (SHA256 dari info sistem)
- Dekripsi response (Base64 + XOR)
- Session token support

Cara pakai:
  # Via environment variable (direkomendasikan)
  export ALRECT_API_KEY="api-key-anda"
  export ALRECT_SECRET="hmac-secret-anda"
  export ALRECT_ENC_KEY="script-enc-key-anda"
  export ALRECT_XOR_SEED="42"

  python alrect-client.py --url https://app.vercel.app --script example.lua

Dependensi: hanya stdlib Python (tidak butuh pip install apapun)
"""

import hmac
import hashlib
import time
import os
import sys
import uuid
import argparse
import platform
import json
import base64
import urllib.request
import urllib.error


# ============================================================
# KONFIGURASI — Isi via environment variable, jangan hardcode
# ============================================================
def get_config():
    cfg = {
        "api_key":    os.environ.get("ALRECT_API_KEY", ""),
        "hmac_secret": os.environ.get("ALRECT_SECRET", ""),
        "enc_key":    os.environ.get("ALRECT_ENC_KEY", ""),
        "xor_seed":   int(os.environ.get("ALRECT_XOR_SEED", "42")),
    }
    missing = [k for k, v in cfg.items() if not str(v)]
    if missing:
        print(f"[ERROR] Environment variable tidak ada: {', '.join(f'ALRECT_{k.upper()}' for k in missing)}")
        print("        Lihat TUTORIAL.md untuk cara konfigurasi.")
        sys.exit(1)
    return cfg


# ============================================================
# DEVICE FINGERPRINT
# ============================================================
def get_device_fingerprint() -> str:
    """
    SHA256 dari informasi perangkat yang konsisten.
    Harus menghasilkan nilai yang sama setiap kali di perangkat yang sama.
    """
    components = [
        platform.node(),           # Hostname
        platform.system(),         # OS name
        platform.machine(),        # Machine type (x86_64, ARM, dll)
        platform.processor(),      # Processor info
        str(os.getpid() // 1000),  # Rough process group (bukan exact PID)
    ]
    raw = "|".join(c for c in components if c)
    return hashlib.sha256(raw.encode()).hexdigest()


# ============================================================
# HMAC SIGNING
# ============================================================
def build_signature(api_key: str, timestamp: int, nonce: str, path: str, secret: str) -> str:
    """
    HMAC SHA256 dari "apiKey:timestamp:nonce:path".
    Format ini harus IDENTIK dengan verifikasi di server (lib/crypto.js).
    """
    data = f"{api_key}:{timestamp}:{nonce}:{path}"
    return hmac.new(
        secret.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


# ============================================================
# DECRYPTION (mirror dari server lib/scriptEncryptor.js)
# ============================================================
def derive_key_bytes(enc_key: str, api_key: str, nonce: str, key_len: int = 256) -> bytes:
    """
    Derive encryption key dari SCRIPT_ENC_KEY + apiKey + nonce.
    Harus sama persis dengan server-side deriveKey().
    """
    context = f"{api_key}:{nonce}"
    derived = hmac.new(
        enc_key.encode("utf-8"),
        context.encode("utf-8"),
        hashlib.sha256
    ).digest()  # 32 bytes

    # Expand ke key_len bytes menggunakan counter mode
    key = bytearray()
    counter = 0
    while len(key) < key_len:
        h = hmac.new(derived, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        key.extend(h)
        counter += 1
    return bytes(key[:key_len])


def xor_decrypt(ciphertext_b64: str, enc_key: str, api_key: str, nonce: str, xor_seed: int) -> str:
    """
    Base64 decode + XOR decrypt.
    Mirror dari server: xorBuffer() di lib/scriptEncryptor.js
    """
    encrypted = base64.b64decode(ciphertext_b64)
    key_bytes  = derive_key_bytes(enc_key, api_key, nonce)

    result = bytearray()
    for i, byte in enumerate(encrypted):
        k = key_bytes[i % len(key_bytes)]
        s = (xor_seed + i) & 0xFF
        result.append(byte ^ k ^ s)

    return result.decode("utf-8")


# ============================================================
# HTTP REQUEST (tanpa requests library)
# ============================================================
def do_request(url: str, headers: dict, timeout: int = 10) -> tuple[int, dict | str]:
    """
    Kirim GET request menggunakan urllib (built-in, tidak perlu pip install).
    Returns: (status_code, body)
    """
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except urllib.error.URLError as e:
        raise ConnectionError(f"Tidak bisa terhubung: {e.reason}") from e


# ============================================================
# MAIN FETCH FUNCTION
# ============================================================
def fetch_script(base_url: str, script_name: str, cfg: dict, verbose: bool = False) -> str | None:
    """
    Ambil dan dekripsi script dari Alrect Protect server.
    """
    script_path = f"/script/{script_name}"
    url = base_url.rstrip("/") + script_path

    timestamp  = int(time.time())
    nonce      = uuid.uuid4().hex  # 32 char hex, unik per request
    device_fp  = get_device_fingerprint()
    signature  = build_signature(cfg["api_key"], timestamp, nonce, script_path, cfg["hmac_secret"])

    headers = {
        "User-Agent":          "AlrectClient/1.0",
        "X-Alrect-Key":        cfg["api_key"],
        "X-Alrect-Timestamp":  str(timestamp),
        "X-Alrect-Nonce":      nonce,
        "X-Alrect-Signature":  signature,
        "X-Alrect-Device":     device_fp,
        "Accept":              "application/json",
    }

    if verbose:
        print(f"[*] URL:       {url}")
        print(f"[*] Timestamp: {timestamp}")
        print(f"[*] Nonce:     {nonce}")
        print(f"[*] Device:    {device_fp[:16]}...")

    try:
        status, body = do_request(url, headers)
    except ConnectionError as e:
        print(f"[✗] {e}")
        return None

    if status == 200 and isinstance(body, dict) and body.get("success"):
        ciphertext = body["ciphertext"]
        resp_nonce = body["nonce"]   # Server echo nonce untuk derive key
        xor_seed   = body.get("xorSeed", 42)

        try:
            plaintext = xor_decrypt(
                ciphertext,
                cfg["enc_key"],
                cfg["api_key"],
                resp_nonce,
                xor_seed,
            )
            print(f"[✓] Script diterima dan didekripsi ({len(plaintext)} bytes)")
            return plaintext
        except Exception as e:
            print(f"[✗] Gagal dekripsi: {e}")
            if verbose:
                print(f"    Ciphertext prefix: {ciphertext[:40]}...")
            return None

    else:
        if isinstance(body, dict):
            print(f"[✗] Error {status}: {body.get('error')} — {body.get('message')}")
        else:
            print(f"[✗] Error {status}: {str(body)[:200]}")
        return None


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Alrect Protect v2 — Official Python Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python alrect-client.py --url https://app.vercel.app --script example.lua
  python alrect-client.py --url https://app.vercel.app --script loader.lua --save output.lua
        """
    )
    parser.add_argument("--url",     required=True,  help="Base URL server")
    parser.add_argument("--script",  required=True,  help="Nama file script")
    parser.add_argument("--save",    metavar="FILE",  help="Simpan ke file lokal")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan detail request")
    args = parser.parse_args()

    cfg = get_config()
    content = fetch_script(args.url, args.script, cfg, verbose=args.verbose)

    if content:
        print("\n" + "=" * 60)
        print(content)
        print("=" * 60)

        if args.save:
            try:
                os.makedirs(os.path.dirname(args.save) or ".", exist_ok=True)
                with open(args.save, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"\n[✓] Disimpan ke: {args.save}")
            except OSError as e:
                print(f"[✗] Gagal simpan: {e}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
