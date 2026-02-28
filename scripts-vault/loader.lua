--[[
    ALRECT DERONIC PROTECT — LOADER
    loadstring(game:HttpGet("https://prri-v14.vercel.app/lua/50b51f3ed6666b9ee70ab2c6"))()
]]

if getgenv().AlrectLoaded then return end
getgenv().AlrectLoaded = true

local URL = "https://prri-v14.vercel.app/lua/8f52fbb9e0902a389560f691"

local code = game:HttpGet(URL)

if not code or code == "" then
    warn("[Alrect] Gagal download script")
    return
end

local fn, err = load(code)
if not fn then
    warn("[Alrect] Load error: " .. tostring(err))
    return
end

local ok, runErr = pcall(fn)
if not ok then
    warn("[Alrect] Runtime error: " .. tostring(runErr))
end
