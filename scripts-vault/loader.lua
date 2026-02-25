--[[
    ALRECT DERONIC PROTECT — PUBLIC LOADER
    loadstring(game:HttpGet("https://alrect-protectxx.vercel.app/lua/50b51f3ed6666b9ee70ab2c6"))()
]]

if getgenv().AlrectLoaded then return end
getgenv().AlrectLoaded = true

local _pcall = pcall
local _load  = load
local Http   = game:GetService("HttpService")

local _c = {
    _u = "https://unver-protect.vercel.app/lua/8f52fbb9e0902a389560f691",
    _s = "8f52fbb9e0902a389560f691",
}

-- BASE64 DECODE
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64map = {}
for i = 1, #b64chars do b64map[b64chars:sub(i,i)] = i - 1 end

local function b64decode(s)
    s = s:gsub("[^A-Za-z0-9%+%/]", "")
    local result = {}
    for i = 1, #s, 4 do
        local a = b64map[s:sub(i,i)]     or 0
        local b = b64map[s:sub(i+1,i+1)] or 0
        local c = b64map[s:sub(i+2,i+2)] or 0
        local d = b64map[s:sub(i+3,i+3)] or 0
        local v = a*262144 + b*4096 + c*64 + d
        table.insert(result, math.floor(v/65536))
        if s:sub(i+2,i+2) ~= "=" then table.insert(result, math.floor(v/256) % 256) end
        if s:sub(i+3,i+3) ~= "=" then table.insert(result, v % 256) end
    end
    return result
end

-- XOR DECRYPT
local function xorDecrypt(encoded, key)
    local bytes = b64decode(encoded)
    local result = {}
    for i = 1, #bytes do
        result[i] = string.char(bit32.bxor(bytes[i], key:byte(((i-1) % #key) + 1)))
    end
    return table.concat(result)
end

-- DERIVE KEY (harus sama dengan server)
local function simpleHash(str)
    local h = 5381
    for i = 1, #str do h = (h * 33 + str:byte(i)) % 4294967296 end
    return string.format("%08x", h)
end

local function deriveKey(secret, token)
    local base = secret .. token
    local out = ""
    for i = 1, 8 do out = out .. simpleHash(base .. tostring(i)) end
    return out
end

-- MAIN
local function run()
    local token = _c._u:match("/lua/([^%?]+)$")
    if not token then warn("[Alrect] URL error") return end

    local ok, res = _pcall(function()
        return Http:RequestAsync({
            Url    = _c._u,
            Method = "GET",
            Headers = { ["X-Alrect-Secret"] = _c._s }
        })
    end)

    if not ok or not res then
        warn("[Alrect] Connect error: " .. tostring(res))
        return
    end

    if res.StatusCode ~= 200 then
        warn("[Alrect] HTTP " .. tostring(res.StatusCode) .. " | " .. tostring(res.Body):sub(1,80))
        return
    end

    local ok2, data = _pcall(Http.JSONDecode, Http, res.Body)
    if not ok2 or type(data) ~= "table" or not data.d then
        warn("[Alrect] Parse error. Body: " .. tostring(res.Body):sub(1,100))
        return
    end

    local encKey = deriveKey(_c._s, token)
    local ok3, code = _pcall(xorDecrypt, data.d, encKey)
    if not ok3 or not code or #code == 0 then
        warn("[Alrect] Decrypt error: " .. tostring(code))
        return
    end

    local fn, loadErr = _load(code)
    if not fn then
        warn("[Alrect] Load error: " .. tostring(loadErr))
        return
    end

    local ok4, runErr = _pcall(fn)
    if not ok4 then warn("[Alrect] Runtime: " .. tostring(runErr)) end
end

run()
