--[[
    ALRECT DERONIC PROTECT — LOADER (Delta Compatible)
    loadstring(game:HttpGet("https://prri-scriptv14.vercel.app/lua/50b51f3ed6666b9ee70ab2c6"))()
]]

if getgenv().AlrectLoaded then return end
getgenv().AlrectLoaded = true

local URL = "https://prri-scriptv14.vercel.app/lua/8f52fbb9e0902a389560f691"

local ok, code = pcall(game.HttpGet, game, URL)

if not ok or not code or #code == 0 then
    warn("[Alrect] Gagal download script: " .. tostring(code))
    return
end

local fn, err = load(code)
if not fn then
    warn("[Alrect] Load error: " .. tostring(err))
    return
end

local ok2, err2 = pcall(fn)
if not ok2 then
    warn("[Alrect] Runtime error: " .. tostring(err2))
end
