
--[[
╔══════════════════════════════════════════════════════════════╗
║          ALRECT PROTECT — PROTECTED LUA LOADER v2           ║
║          Didistribusikan terenkripsi. Jangan share.          ║
╚══════════════════════════════════════════════════════════════╝

File ini adalah LOADER dengan anti-debug, anti-hook, dan
anti-getgc checks. Script asli ter-embed sebagai data terenkripsi.
]]

-- Preserve critical functions sebelum environment bisa di-hook
local _type    = type
local _error   = error
local _pcall   = pcall
local _pairs   = pairs
local _ipairs  = ipairs
local _load    = load
local _tostr   = tostring
local _os      = os
local _math    = math
local _string  = string
local _table   = table
local _io      = io
local _debug   = debug
local _rawget  = rawget
local _rawset  = rawset
local _cg      = collectgarbage
local _char    = string.char
local _byte    = string.byte
local _sub     = string.sub
local _find    = string.find
local _format  = string.format
local _floor   = math.floor
local _time    = os.time
local _exit    = os.exit
local _date    = os.date
local _concat  = table.concat
local _insert  = table.insert

-- ============================================================
-- BAGIAN 1: ANTI-ENVIRONMENT CHECKS
-- ============================================================

local function hardCrash(reason)
  _io.stderr:write("[ALRECT] Security check failed: " .. _tostr(reason) .. "\n")
  -- Corrupt execution state
  local sink = {}
  for i = 1, 500 do _insert(sink, function() return hardCrash end) end
  _exit(1)
end

local function checkDebugHooks()
  if _debug then
    local hook = _debug.gethook()
    if hook ~= nil then
      hardCrash("debug hook active")
    end
    -- Cek debug.traceback tidak ter-hook
    if _type(_debug.traceback) ~= "function" then
      hardCrash("debug.traceback hooked")
    end
  end
end

local function checkGC()
  local pre = _cg("count")
  _cg("collect")
  local post = _cg("count")
  -- Memory HARUS berkurang atau setidaknya tidak tumbuh drastis setelah collect
  if post > pre * 3 + 100 then
    hardCrash("GC anomaly detected")
  end
end

local function checkFunctionIntegrity()
  -- Verifikasi type() tidak di-override (heuristik)
  if _type(_type) ~= "function" then hardCrash("type() hooked") end
  if _type(_pcall) ~= "function" then hardCrash("pcall() hooked") end
  if _type(_error) ~= "function" then hardCrash("error() hooked") end
  if _type(_load)  ~= "function" then hardCrash("load() hooked") end

  -- Verifikasi behaviour dasar pcall
  local ok = _pcall(function() end)
  if ok ~= true then hardCrash("pcall behaviour anomaly") end
end

local function checkExploitGlobals()
  -- Daftar fungsi exploit umum (Roblox executor, script engines, dll)
  local exploitFns = {
    "hookfunction", "hookmetamethod", "getrawmetatable",
    "checkcaller",  "islclosure",      "getupvalue",
    "setupvalue",   "getconstants",    "setconstant",
    "readfile",     "writefile",       "getgc",
    "fireclickdetector", "decompile",  "getscripts",
  }
  for _, name in _ipairs(exploitFns) do
    if _rawget(_G, name) ~= nil then
      hardCrash("exploit API detected: " .. name)
    end
  end
end

-- Jalankan semua pre-flight checks
checkDebugHooks()
checkGC()
checkFunctionIntegrity()
checkExploitGlobals()

-- ============================================================
-- BAGIAN 2: KEY DERIVATION (FNV-1a + LCG)
-- ============================================================

local function fnv1a32(str)
  local h = 2166136261
  for i = 1, #str do
    -- XOR lalu multiply (FNV-1a)
    h = (h ~ _byte(str, i)) * 16777619
    h = h & 0xFFFFFFFF  -- Clamp ke 32-bit
  end
  return h
end

-- Key derivation: seed dari embed_secret + jam saat ini
-- Mengganti key setiap jam membatasi window jika ciphertext bocor
local function deriveKeyBytes(secret, keyLen)
  keyLen = keyLen or 256
  local hourSlot = _floor(_time() / 3600)
  local seed = fnv1a32(secret .. ":" .. _tostr(hourSlot))

  local bytes = {}
  local state = seed
  for i = 1, keyLen do
    -- LCG (Linear Congruential Generator) untuk expand seed ke stream
    state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
    _insert(bytes, state & 0xFF)
  end
  return bytes
end

-- ============================================================
-- BAGIAN 3: BASE64 DECODE + XOR DECRYPT
-- ============================================================

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_LUT = {}
for i = 1, #B64 do B64_LUT[_sub(B64, i, i)] = i - 1 end

local function base64Decode(s)
  -- Strip whitespace dan padding
  s = s:gsub("[^A-Za-z0-9+/=]", "")
  local pad = (s:sub(-2) == "==" and 2) or (s:sub(-1) == "=" and 1) or 0
  local len = #s - pad
  local out = {}

  for i = 1, len, 4 do
    local a = B64_LUT[s:sub(i,   i  )] or 0
    local b = B64_LUT[s:sub(i+1, i+1)] or 0
    local c = B64_LUT[s:sub(i+2, i+2)] or 0
    local d = B64_LUT[s:sub(i+3, i+3)] or 0
    local n = (a << 18) | (b << 12) | (c << 6) | d
    _insert(out, _char((n >> 16) & 0xFF))
    if i + 1 < len then _insert(out, _char((n >> 8) & 0xFF)) end
    if i + 2 < len then _insert(out, _char(n & 0xFF)) end
  end

  return _concat(out)
end

local function xorDecrypt(data, keyBytes, xorSeed)
  xorSeed = xorSeed or 42
  local keyLen = #keyBytes
  local out = {}
  for i = 1, #data do
    local b = _byte(data, i)
    local k = keyBytes[((i - 1) % keyLen) + 1]
    local s = (xorSeed + (i - 1)) & 0xFF
    _insert(out, _char(b ~ k ~ s))
  end
  return _concat(out)
end

-- ============================================================
-- BAGIAN 4: EXECUTE PAYLOAD
-- Secret dan payload diisi oleh server saat mengirim file ini.
-- EMBED_SECRET = string yang di-derive dari SCRIPT_ENC_KEY server.
-- ENCRYPTED_PAYLOAD = Base64(XOR(script_asli))
-- ============================================================

local EMBED_SECRET       = "{{EMBED_SECRET}}"
local ENCRYPTED_PAYLOAD  = "{{ENCRYPTED_PAYLOAD}}"
local XOR_SEED           = 42  -- Sama dengan SCRIPT_XOR_SEED di .env server

local function executePayload()
  -- Mode demo jika placeholder belum diganti server
  if _find(ENCRYPTED_PAYLOAD, "{{", 1, true) then
    print("=== Alrect Protect v2 — Demo Mode ===")
    print("Anti-debug checks: PASSED")
    print("Anti-hook checks:  PASSED")
    print("Anti-GC checks:    PASSED")
    print("Environment:       CLEAN")
    print("")
    print("Waktu load: " .. _date("%Y-%m-%d %H:%M:%S"))
    print("")
    print("[INFO] Ini mode demo. Untuk produksi, server akan")
    print("[INFO] mengisi ENCRYPTED_PAYLOAD dengan script asli Anda.")
    return
  end

  -- Derive key dari embed secret
  local keyBytes = deriveKeyBytes(EMBED_SECRET, 256)

  -- Decode dan decrypt payload
  local ok1, decoded = _pcall(base64Decode, ENCRYPTED_PAYLOAD)
  if not ok1 then hardCrash("base64 decode failed") end

  local ok2, plaintext = _pcall(xorDecrypt, decoded, keyBytes, XOR_SEED)
  if not ok2 then hardCrash("xor decrypt failed") end

  -- Verifikasi minimal plaintext adalah Lua code yang valid
  if #plaintext < 1 then hardCrash("payload empty") end

  -- Check ulang sebelum load (anti-hook yang dipasang setelah init)
  checkDebugHooks()
  checkExploitGlobals()

  -- Load dan jalankan
  local fn, loadErr = _load(plaintext, "=alrect", "t")
  if not fn then
    hardCrash("payload load error: " .. _tostr(loadErr))
  end

  local ok3, runErr = _pcall(fn)
  if not ok3 then
    _error(runErr, 2)
  end
end

executePayload()
