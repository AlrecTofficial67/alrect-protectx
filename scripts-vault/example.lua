-- Script kamu di sini
print("Alrect script loaded!")

-- Contoh simple UI
local ScreenGui = Instance.new("ScreenGui")
local Frame = Instance.new("Frame")
local Label = Instance.new("TextLabel")

ScreenGui.Parent = game.Players.LocalPlayer.PlayerGui
ScreenGui.ResetOnSpawn = false

Frame.Parent = ScreenGui
Frame.Size = UDim2.new(0, 300, 0, 150)
Frame.Position = UDim2.new(0.5, -150, 0.5, -75)
Frame.BackgroundColor3 = Color3.fromRGB(15, 15, 15)

Label.Parent = Frame
Label.Size = UDim2.new(1, 0, 1, 0)
Label.Text = "Alrect Deronic Protect Guard"
Label.TextColor3 = Color3.fromRGB(0, 255, 65)
Label.Font = Enum.Font.Code
Label.TextScaled = true
