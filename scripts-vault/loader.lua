--[[
    ALRECT DERONIC PROTECT — PUBLIC LOADER
    
    File ini AMAN untuk publik.
    Tidak ada secret, tidak ada script asli.
    Tugas: download dan jalankan script asli secara aman.
]]

-- Anti re-run
if getgenv().AlrectLoaded then
    return
end
getgenv().AlrectLoaded = true

-- Preserve functions
local _pcall  = pcall
local _error  = error
local _load   = load
local _print  = print
local _tostr  = tostring
local HttpSvc = game:GetService("HttpService")

-- ============================================================
-- CONFIG — Ini PRIVATE, di-obfuscate saat generate
-- Secret di-embed di loader, bukan di URL publik
-- ============================================================
local _c = {
    _u = "https://alrect-protectxx.vercel.app/lua/PRIVATE_TOKEN",
    _s = "a7f3k9x2m5q8w1e4r6t0y3b8",
}

-- ============================================================
-- BASE64 DECODE
-- ============================================================
local function b64decode(encoded)
    local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local b64map = {}
    for i = 1, #b64chars do
        b64map[b64chars:sub(i,i)] = i - 1
    end

    local bytes = {}
    local pad = 0
    if encoded:sub(-2) == "==" then pad = 2
    elseif encoded:sub(-1) == "=" then pad = 1 end
    encoded = encoded:gsub("[^%w%+%/]", "")

    for i = 1, #encoded, 4 do
        local a = b64map[encoded:sub(i,i)]     or 0
        local b = b64map[encoded:sub(i+1,i+1)] or 0
        local c = b64map[encoded:sub(i+2,i+2)] or 0
        local d = b64map[encoded:sub(i+3,i+3)] or 0
        local n = (a * 262144) + (b * 4096) + (c * 64) + d
        table.insert(bytes, math.floor(n / 65536) % 256)
        table.insert(bytes, math.floor(n / 256)   % 256)
        table.insert(bytes, n % 256)
    end
    for i = 1, pad do bytes[#bytes] = nil end
    return bytes
end

-- ============================================================
-- XOR DECRYPT
-- ============================================================
local function xorDecrypt(encoded, key)
    local bytes   = b64decode(encoded)
    local keyLen  = #key
    local result  = {}
    for i = 1, #bytes do
        result[i] = string.char(
            bit32.bxor(bytes[i], key:byte(((i-1) % keyLen) + 1))
        )
    end
    return table.concat(result)
end

-- ============================================================
-- DERIVE KEY — harus sama persis dengan server
-- ============================================================
local function simpleHash(str)
    local hash = 5381
    for i = 1, #str do
        hash = (hash * 33 + str:byte(i)) % (2^32)
    end
    return string.format("%08x", hash)
end

local function deriveKey(secret, token)
    local base   = secret .. token
    local result = ""
    for i = 1, 8 do
        result = result .. simpleHash(base .. tostring(i))
    end
    return result
end

-- ============================================================
-- MAIN
-- ============================================================
local function run()
    -- Ambil token dari URL private
    local token = _c._u:match("/lua/(.+)$")
    if not token then _error("[Alrect] Config error") return end

    -- Request ke server dengan secret header
    local ok, res = _pcall(function()
        return HttpSvc:RequestAsync({
            Url     = _c._u,
            Method  = "GET",
            Headers = {
                ["X-Alrect-Secret"] = _c._s,
            }
        })
    end)

    if not ok or not res then
        _error("[Alrect] Gagal connect: " .. _tostr(res))
        return
    end

    if res.StatusCode ~= 200 then
        _error("[Alrect] Server error: " .. _tostr(res.StatusCode))
        return
    end

    -- Parse JSON response
    local ok2, data = _pcall(HttpSvc.JSONDecode, HttpSvc, res.Body)
    if not ok2 or not data or not data.d then
        _error("[Alrect] Response error")
        return
    end

    -- Decrypt
    local encKey = deriveKey(_c._s, token)
    local ok3, code = _pcall(xorDecrypt, data.d, encKey)
    if not ok3 or not code or #code == 0 then
        _error("[Alrect] Decrypt error")
        return
    end

    -- Load dan jalankan
    local fn, err = _load(code)
    if not fn then
        _error("[Alrect] Load error: " .. _tostr(err))
        return
    end

    local ok4, err2 = _pcall(fn)
    if not ok4 then
        _error("[Alrect] Runtime error: " .. _tostr(err2))
    end
end

run()
