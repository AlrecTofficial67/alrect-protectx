#!/usr/bin/env python3
"""
client/test-suite.py
Alrect Protect v2 — Comprehensive Security Test Suite

Menguji semua lapisan keamanan. Semua test (kecuali "valid") harus DITOLAK.

Cara pakai:
  export ALRECT_API_KEY="..."
  export ALRECT_SECRET="..."
  export ALRECT_ENC_KEY="..."
  python test-suite.py --url https://app.vercel.app [--verbose]
"""

import hmac
import hashlib
import time
import uuid
import os
import sys
import platform
import json
import urllib.request
import urllib.error
import argparse


# ============================================================
# CONFIG dari env
# ============================================================
API_KEY     = os.environ.get("ALRECT_API_KEY", "")
HMAC_SECRET = os.environ.get("ALRECT_SECRET", "")
SCRIPT_NAME = "example.lua"


def get_fp():
    raw = f"{platform.node()}|{platform.system()}|{platform.machine()}|{platform.processor()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def make_sig(api_key, ts, nonce, path, secret):
    data = f"{api_key}:{ts}:{nonce}:{path}"
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()


def do_get(url, headers, timeout=8):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return None, str(e)


# ============================================================
# TEST RUNNER
# ============================================================

PASS = 0
FAIL = 0
TOTAL = 0


def run_test(label, url, headers, expect_status, verbose=False):
    global PASS, FAIL, TOTAL
    TOTAL += 1

    status, body = do_get(url, headers)

    ok = (status == expect_status)
    icon = "✓" if ok else "✗"
    color_ok   = "\033[32m"  # green
    color_fail = "\033[31m"  # red
    color_reset = "\033[0m"
    color = color_ok if ok else color_fail

    error_code = ""
    if isinstance(body, dict):
        error_code = body.get("error", "")

    print(f"  {color}{icon}{color_reset} [{status}] {label:<55} {error_code}")

    if verbose and not ok:
        print(f"       Expected: {expect_status}, Got: {status}")
        print(f"       Body: {str(body)[:120]}")

    if ok:
        PASS += 1
    else:
        FAIL += 1


def build_valid_headers(api_key, secret, path, fp):
    ts    = str(int(time.time()))
    nonce = uuid.uuid4().hex
    sig   = make_sig(api_key, int(ts), nonce, path, secret)
    return {
        "User-Agent":          "AlrectClient/1.0",
        "X-Alrect-Key":        api_key,
        "X-Alrect-Timestamp":  ts,
        "X-Alrect-Nonce":      nonce,
        "X-Alrect-Signature":  sig,
        "X-Alrect-Device":     fp,
        "Accept":              "application/json",
    }


def run_all_tests(base_url, verbose=False):
    path = f"/script/{SCRIPT_NAME}"
    url  = base_url.rstrip("/") + path
    fp   = get_fp()

    print(f"\n{'='*70}")
    print(f"  Alrect Protect v2 — Security Test Suite")
    print(f"  Target: {base_url}")
    print(f"{'='*70}")

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 1 — User-Agent / Request Pattern Checks\n")

    # 1a. Browser UA
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Accept": "application/json"}
    run_test("Browser User-Agent (Mozilla/Chrome)", url, h, 403, verbose)

    # 1b. curl UA
    h = {"User-Agent": "curl/8.5.0", "Accept": "application/json"}
    run_test("curl User-Agent", url, h, 403, verbose)

    # 1c. wget
    h = {"User-Agent": "Wget/1.21.4", "Accept": "application/json"}
    run_test("wget User-Agent", url, h, 403, verbose)

    # 1d. Python requests
    h = {"User-Agent": "python-requests/2.31.0", "Accept": "application/json"}
    run_test("python-requests User-Agent", url, h, 403, verbose)

    # 1e. Postman
    h = {"User-Agent": "PostmanRuntime/7.36.1", "Accept": "application/json"}
    run_test("Postman User-Agent", url, h, 403, verbose)

    # 1f. Valid UA tapi ada Sec-Fetch-Site (browser header)
    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["Sec-Fetch-Site"] = "none"
    h["X-Alrect-Nonce"] = uuid.uuid4().hex  # refresh nonce
    ts = str(int(time.time()))
    h["X-Alrect-Timestamp"] = ts
    h["X-Alrect-Signature"] = make_sig(API_KEY, int(ts), h["X-Alrect-Nonce"], path, HMAC_SECRET)
    run_test("Valid UA + Sec-Fetch-Site header (browser pattern)", url, h, 403, verbose)

    # 1g. Valid UA tapi Accept wildcard (curl pattern)
    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["Accept"] = "*/*"
    run_test("Valid UA + Accept: */* (curl default)", url, h, 403, verbose)

    # 1h. Valid UA tapi Accept-Encoding: br (browser pattern)
    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["Accept-Encoding"] = "gzip, deflate, br"
    run_test("Valid UA + Accept-Encoding: br (browser pattern)", url, h, 403, verbose)

    # 1i. No User-Agent sama sekali
    h = {"Accept": "application/json"}
    run_test("Tidak ada User-Agent header", url, h, 403, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 2 — API Key Validation\n")

    h = build_valid_headers("key-palsu-12345678", HMAC_SECRET, path, fp)
    run_test("API Key salah", url, h, 403, verbose)

    h = build_valid_headers("", HMAC_SECRET, path, fp)
    run_test("API Key kosong", url, h, 403, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 3 — Timestamp Validation\n")

    # Timestamp 60 detik lalu
    old_ts = str(int(time.time()) - 60)
    old_nonce = uuid.uuid4().hex
    old_sig = make_sig(API_KEY, int(old_ts), old_nonce, path, HMAC_SECRET)
    h = {
        "User-Agent":          "AlrectClient/1.0",
        "X-Alrect-Key":        API_KEY,
        "X-Alrect-Timestamp":  old_ts,
        "X-Alrect-Nonce":      old_nonce,
        "X-Alrect-Signature":  old_sig,
        "X-Alrect-Device":     fp,
        "Accept":              "application/json",
    }
    run_test("Timestamp kedaluwarsa (60 detik lalu)", url, h, 403, verbose)

    # Timestamp dari masa depan
    future_ts = str(int(time.time()) + 120)
    future_nonce = uuid.uuid4().hex
    future_sig = make_sig(API_KEY, int(future_ts), future_nonce, path, HMAC_SECRET)
    h = {
        "User-Agent":          "AlrectClient/1.0",
        "X-Alrect-Key":        API_KEY,
        "X-Alrect-Timestamp":  future_ts,
        "X-Alrect-Nonce":      future_nonce,
        "X-Alrect-Signature":  future_sig,
        "X-Alrect-Device":     fp,
        "Accept":              "application/json",
    }
    run_test("Timestamp dari masa depan (+120 detik)", url, h, 403, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 4 — Anti-Replay Nonce\n")

    print("  [Replay test: kirim request identik 2x dengan nonce sama]")
    r_nonce = uuid.uuid4().hex
    r_ts    = str(int(time.time()))
    r_sig   = make_sig(API_KEY, int(r_ts), r_nonce, path, HMAC_SECRET)
    r_h = {
        "User-Agent":          "AlrectClient/1.0",
        "X-Alrect-Key":        API_KEY,
        "X-Alrect-Timestamp":  r_ts,
        "X-Alrect-Nonce":      r_nonce,
        "X-Alrect-Signature":  r_sig,
        "X-Alrect-Device":     fp,
        "Accept":              "application/json",
    }
    status1, _ = do_get(url, r_h)
    status2, body2 = do_get(url, r_h)

    global PASS, FAIL, TOTAL
    TOTAL += 1
    replay_blocked = status2 in (403, 429)
    icon = "✓" if replay_blocked else "✗"
    err = body2.get("error", "") if isinstance(body2, dict) else ""
    print(f"  {'✓' if status1 in (200, 403) else '?'} Request ke-1: {status1}")
    if replay_blocked:
        PASS += 1
        print(f"  \033[32m{icon}\033[0m Request ke-2 (replay): {status2} {err}  ← REPLAY DITOLAK ✓")
    else:
        FAIL += 1
        print(f"  \033[31m{icon}\033[0m Request ke-2 (replay): {status2}  ← SEHARUSNYA DITOLAK!")

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 5 — HMAC Signature\n")

    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["X-Alrect-Signature"] = "a" * 64
    run_test("Signature palsu (64 'a')", url, h, 403, verbose)

    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["X-Alrect-Signature"] = make_sig(API_KEY, int(time.time()), h["X-Alrect-Nonce"], "/script/other.lua", HMAC_SECRET)
    run_test("Signature untuk path yang berbeda", url, h, 403, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🔴 LAYER 6 — Device Fingerprint\n")

    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["X-Alrect-Device"] = "a" * 64  # Format salah (bukan SHA256 hex)
    run_test("Fingerprint format salah (bukan SHA256 hex lowercase)", url, h, 403, verbose)

    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    h["X-Alrect-Device"] = hashlib.sha256(b"perangkat-lain-berbeda").hexdigest()
    run_test("Fingerprint perangkat berbeda (setelah binding)", url, h, 403, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🔴 Path Traversal Attack\n")

    for traversal in ["../lib/crypto.js", "../../etc/passwd", "%2e%2e/package.json"]:
        t_url = base_url.rstrip("/") + f"/script/{traversal}"
        h = build_valid_headers(API_KEY, HMAC_SECRET, f"/script/{traversal}", fp)
        run_test(f"Path traversal: {traversal[:40]}", t_url, h, 400, verbose)

    # ──────────────────────────────────────────────────────────
    print("\n🟢 VALID REQUEST (harus 200)\n")

    h = build_valid_headers(API_KEY, HMAC_SECRET, path, fp)
    run_test("Request valid lengkap", url, h, 200, verbose)

    # ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    total_color = "\033[32m" if FAIL == 0 else "\033[33m"
    print(f"  Hasil: {total_color}{PASS}/{TOTAL} PASS, {FAIL} FAIL\033[0m")
    if FAIL > 0:
        print(f"  ⚠️  Ada {FAIL} test yang tidak sesuai ekspektasi!")
    else:
        print(f"  🎉 Semua test lulus!")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description="Alrect Protect v2 — Test Suite")
    parser.add_argument("--url",     required=True, help="Base URL server")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan detail kegagalan")
    args = parser.parse_args()

    if not API_KEY or not HMAC_SECRET:
        print("[ERROR] Set environment variables:")
        print("  export ALRECT_API_KEY='...'")
        print("  export ALRECT_SECRET='...'")
        sys.exit(1)

    run_all_tests(args.url, verbose=args.verbose)


if __name__ == "__main__":
    main()
