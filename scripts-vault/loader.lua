--[[
    ALRECT DERONIC PROTECT — PUBLIC LOADER
    loadstring(game:HttpGet("https://unver-protectx.vercel.app/lua/50b51f3ed6666b9ee70ab2c6"))()
]]

if getgenv().AlrectLoaded then return end
getgenv().AlrectLoaded = true

local Http = game:GetService("HttpService")

local _c = {
    _u = "https://unver-protectx.vercel.app/lua/8f52fbb9e0902a389560f691",
    _s = "82a7191e04396f88b6f9bc39",
}

local function run()
    local ok, res = pcall(function()
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
        warn("[Alrect] HTTP " .. tostring(res.StatusCode) .. " | " .. tostring(res.Body):sub(1, 100))
        return
    end

    local code = res.Body
    if not code or #code == 0 then
        warn("[Alrect] Response kosong")
        return
    end

    local fn, loadErr = load(code)
    if not fn then
        warn("[Alrect] Load error: " .. tostring(loadErr))
        return
    end

    local ok2, runErr = pcall(fn)
    if not ok2 then
        warn("[Alrect] Runtime: " .. tostring(runErr))
    end
end

run()
