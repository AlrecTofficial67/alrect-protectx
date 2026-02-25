--[[
    ALRECT DERONIC PROTECT — PUBLIC LOADER (FIXED)
    loadstring(game:HttpGet("URL/lua/PUBLIC_TOKEN"))()
]]

if getgenv().AlrectLoaded then return end
getgenv().AlrectLoaded = true

local _pcall  = pcall
local _error  = error
local _load   = load
local _print  = print
local _tostr  = tostring
local Http    = game:GetService("HttpService")

-- CONFIG — ganti _u dan _s
local _c = {
    _u = "https://deronikcx-protectxx.vercel.app/lua/a1b2c3d4e5f6a7b8c9d0e1f2",
    _s = "a1b2c3d4e5f6a7b8c9d0e1f2",
}

-- ============================================================
-- BASE64 DECODE → returns string
-- ============================================================
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64map = {}
for i = 1, #b64chars do
    b64map[b64chars:sub(i,i)] = i - 1
end

local function b64decode(s)
    s = s:gsub("[^A-Za-z0-9%+%/]", "")
    local result = {}
    for i = 1, #s, 4 do
        local a = b64map[s:sub(i,i)]   or 0
        local b = b64map[s:sub(i+1,i+1)] or 0
        local c = b64map[s:sub(i+2,i+2)] or 0
        local d = b64map[s:sub(i+3,i+3)] or 0
        local n = a*16777216 + b*262144 + c*4096 + d*64
        -- ambil 3 byte
        table.insert(result, math.floor(n/16777216) % 256)
        table.insert(result, math.floor(n/65536)    % 256)
        table.insert(result, math.floor(n/256)      % 256)
    end
    -- hapus padding
    local pad = s:sub(-1) == "=" and (s:sub(-2,-2) == "=" and 2 or 1) or 0
    -- Recalc properly
    result = {}
    for i = 1, #s, 4 do
        local a = b64map[s:sub(i,i)]     or 0
        local b2= b64map[s:sub(i+1,i+1)] or 0
        local c = b64map[s:sub(i+2,i+2)] or 0
        local d = b64map[s:sub(i+3,i+3)] or 0
        local v = a*262144 + b2*4096 + c*64 + d
        table.insert(result, math.floor(v/65536))
        if s:sub(i+2,i+2) ~= "=" then
            table.insert(result, math.floor(v/256) % 256)
        end
        if s:sub(i+3,i+3) ~= "=" then
            table.insert(result, v % 256)
        end
    end
    return result
end

-- ============================================================
-- XOR DECRYPT
-- ============================================================
local function xorDecrypt(encoded, key)
    local bytes  = b64decode(encoded)
    local result = {}
    for i = 1, #bytes do
        local kb = key:byte(((i-1) % #key) + 1)
        result[i] = string.char(bit32.bxor(bytes[i], kb))
    end
    return table.concat(result)
end

-- ============================================================
-- DERIVE KEY — harus identik dengan server
-- server: crypto.createHmac("sha256", secret).update(token).digest("hex")
-- Roblox tidak punya HMAC, jadi kita pakai simple hash yg sama
-- ============================================================
local function simpleHash(str)
    local h = 5381
    for i = 1, #str do
        h = (h * 33 + str:byte(i)) % 4294967296
    end
    return string.format("%08x", h)
end

local function deriveKey(secret, token)
    local base = secret .. token
    local out  = ""
    for i = 1, 8 do
        out = out .. simpleHash(base .. tostring(i))
    end
    return out -- 64 char hex
end

-- ============================================================
-- MAIN
-- ============================================================
local function run()
    local token = _c._u:match("/lua/([^%?]+)$")
    if not token then
        warn("[Alrect] URL config error")
        return
    end

    -- Request dengan secret header
    local ok, res = _pcall(function()
        return Http:RequestAsync({
            Url    = _c._u,
            Method = "GET",
            Headers = {
                ["X-Alrect-Secret"] = _c._s,
            }
        })
    end)

    if not ok then
        warn("[Alrect] Connect error: " .. _tostr(res))
        return
    end

    if not res or res.StatusCode ~= 200 then
        warn("[Alrect] Server error: " .. _tostr(res and res.StatusCode or "nil"))
        warn("[Alrect] Body: " .. _tostr(res and res.Body or ""))
        return
    end

    -- Parse JSON {d: "base64encrypted"}
    local ok2, data = _pcall(Http.JSONDecode, Http, res.Body)
    if not ok2 or type(data) ~= "table" or not data.d then
        warn("[Alrect] Response parse error. Body: " .. _tostr(res.Body):sub(1,100))
        return
    end

    -- Derive key dan decrypt
    local encKey = deriveKey(_c._s, token)
    local ok3, code = _pcall(xorDecrypt, data.d, encKey)
    if not ok3 or not code or #code == 0 then
        warn("[Alrect] Decrypt error: " .. _tostr(code))
        return
    end

    -- Load dan jalankan
    local fn, loadErr = _load(code)
    if not fn then
        warn("[Alrect] Load error: " .. _tostr(loadErr))
        return
    end

    local ok4, runErr = _pcall(fn)
    if not ok4 then
        warn("[Alrect] Runtime error: " .. _tostr(runErr))
    end
end

run()
