local Whitelist = "" -- // change this to ur webserver's url

local Player = game:GetService("Players").LocalPlayer

local RegistryBackup = {}

for Index, Value in pairs(getreg()) do
    RegistryBackup[Index] = Value
end

local LFunctionList = {
    [0] = syn.request
}

local CFunctionList = {
    [0] = {
        f = pcall,
        r = "missing argument #1",
        c = true,
        s = false
    },
    [1] = {
        f = xpcall,
        r = "missing argument #2 to 'xpcall' (function expected)",
        c = true,
        s = false
    },
    [2] = {
        f = pcall,
        r = "attempt to call a boolean value",
        c = true,
        s = false,
        a = {function() end}
    },
    [3] = {
        f = xpcall,
        r = "attempt to call a boolean value",
        c = true,
        s = false,
        a = {function() end, function() end}
    },
	[4] = {
		f = syn.request,
		r = "invalid argument #1 to '?' (table expected, got no value)",
		c = true,
		s = false
    },
    [5] = {
        f = getconstants,
        r = "invalid argument #1 to '?' (function or number expected)",
        c = true,
        s = false
    },
    [6] = {
        f = getconstants,
        r = "attempt to call a table value",
        c = true,
        s = false,
        a = {function() end}
    },
    [7] = {
        f = getconstants,
        r = "attempt to call a table value",
        c = true,
        s = false,
        a = {1}
    },
    [8] = {
        f = string.byte,
        r = "missing argument #1 to 'byte' (string expected)",
        c = true,
        s = false
    },
    [9] = {
        f = function() end,
        r = nil,
        c = false,
        s = true
    },
    [10] = {
        f = function() return RS end,
        r = RS,
        c = false,
        s = true
    },
    [11] = {
        f = function() return false end,
        r = false,
        c = false,
        s = true
    },
    [12] = {
        f = function() return true end,
        r = true,
        c = false,
        s = true
    }
}

local Increment = 0
local Env = getfenv()
local CPassed = false
local LPassed = false

local GCI = 0;
local SF = 0;
local PCC = 0;
local ALH = 0;

while true do
    if not CFunctionList[Increment] and (Increment == #CFunctionList + 1) then 
        CPassed = true
        break
    end
    
    local Function = CFunctionList[Increment]["f"]
    local Return = CFunctionList[Increment]["r"]
    local ToBeCalled = CFunctionList[Increment]["c"]
    local WillBeSuccessful = CFunctionList[Increment]["s"]
    local Arguments = CFunctionList[Increment]["a"]
	    
    if Arguments then
	    local Called =false
	        
	    setfenv(0, {tostring = function() while true do end end})
	        
	    xpcall(Function(unpack(Arguments)), function(Magnet)
	        Called = true
	            
	        if Magnet and Magnet ~= Return then
	            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x01 - " .. tostring(Increment))
	        end
	    end)
            
        setfenv(0, Env)
            
        if Called == false and ToBeCalled == true then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x02 - " .. tostring(Increment))
        end
            
        Called = false
            
        setfenv(0, {tostring = function() while true do end end})
            
        local Success, Error = pcall(Function(unpack(Arguments)))
            
        if (not WillBeSuccessful == Success) or WillBeSuccessful ~= Success then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x03 - " .. tostring(Increment))
        end
            
        setfenv(0, Env)
            
        if Error ~= Return then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x04 - " .. tostring(Increment))
        end
    else
        Called = false
	        
        setfenv(0, {tostring = function() while true do end end})
	        
        xpcall(Function, function(Magnet2)
	       Called = true
	            
	       if Magnet2 and Magnet2 ~= Return then
	           return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x01 - " .. tostring(Increment))
	       end
        end)
        
        setfenv(0, Env)
            
        if Called == false and ToBeCalled == true then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x02 - " .. tostring(Increment))
        end
            
        Called = false
            
        setfenv(0, {tostring = function() while true do end end})
            
        local Success, Error = pcall(Function)
            
        if (not WillBeSuccessful == Success) or WillBeSuccessful ~= Success then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x03 - " .. tostring(Increment))
        end
            
        setfenv(0, Env)
            
        if Error ~= Return then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x04 - " .. tostring(Increment))
        end
    end
        
    Increment = Increment + 1
end

if CPassed == false then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - C_0x05")
end

Increment = 0

while true do
    if not LFunctionList[Increment] and (Increment == #LFunctionList + 1) then
        LPassed = true
        break;
    end
    
    local Function = LFunctionList[Increment]
 
    local GCS1, GCS2 = debug.getconstants, getconstants
    local GC1, GC2 = debug.getconstant, getconstant
    local GI1, GI2 =  debug.getinfo, getinfo
    local ICL1, ICL2 = islclosure, syn_islclosure
    local GUVS1, GUVS2 = debug.getupvalues, getupvalues
    local GUV1, GUV2 = debug.getupvalue, getupvalue
    
    local ConstantsCheck1, ConstantsCheck2 = pcall(function()
        GCS1(Function)
    end), pcall(function()
        GCS2(Function)
    end)
    
    if ConstantsCheck1 or ConstantsCheck2 then
        return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x01")
    end
    
    local ConstantCheck1, ConstantCheck2 = pcall(function()
        GC1(Function, 1)
    end), pcall(function()
        GC2(Function, 1)
    end)
    
    if ConstantCheck1 or ConstantCheck2 then
        return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x01")
    end
    
    local FSRC1, FSRC2 = GI1(function() end).source, GI2(function() end).source
    local NCFSRC1, NCFSRC2 = GI1(newcclosure(function() end)).source, GI2(newcclosure(function() end)).source
    local FS1, FS2 = GI1(Function).source, GI2(Function).source
    
    if (FS1 == FSRC1 or not (FS1 ~= FSRC1) or FS2 == FSRC1 or not (FS2 ~= FSRC1)) then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x02")
    end
    if (FS1 == FSRC2 or not (FS1 ~= FSRC2) or FS2 == FSRC2 or not (FS2 ~= FSRC2)) then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x03")
    end
    if (FS1 ~= NCFSRC2 or not (FS1 == NCFSRC2) or FS2 ~= NCFSRC2 or not (FS2 == NCFSRC2)) then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x04")
    end
    if (FS1 ~= NCFSRC1 or not (FS1 == NCFSRC1) or FS2 ~= NCFSRC1 or not (FS2 == NCFSRC1)) then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x05")
    end
    
    local ILC1,ICL2 = ICL1(Function), ICL2(Function)
    
    if ILC1 or ILC2 then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x06")
    end
 
    local ValuesCheck1, ValuesCheck2 = GUVS1(Function), GUVS2(Function)
    
    if #ValuesCheck1 >= 2 or #ValuesCheck2 >= 2 then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x07")
    else
        for i,v in pairs(ValuesCheck1) do
            if type(v) ~= "userdata" then
                pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x08")
            end
        end
        for i,v in pairs(ValuesCheck2) do
            if type(v) ~= "userdata" then
                pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x09")
            end
        end
    end
 
    local ValueCheck1, ValueCheck2 = GUV1(Function, 1),GUV2(Function, 1)
    
    if type(ValueCheck1) ~= "userdata" or type(ValueCheck2) ~= "userdata" then
        pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x10")
    end

    Increment = Increment + 1
end

if LPassed == false then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x11")
end

local GCRegister = function(C)
    if tostring(C) == 'hookfunction' then
        ALH = ALH + 1
        
        if ALH >= 3 then
            return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x12")
        end
    end
end

while true do
    GCI = GCI + 1
    
    if getgc()[GCI] == nil then break; end
    
    local GCF = getgc()[GCI]
    local FC = false
    
    if GCF and is_synapse_function(GCF) and (getgenv().RegistryHook ~= GCF) then
        SF = SF + 1
        
        local CPC = pcall(function() getconstants(GCF) end)
        local CPCD = pcall(function() debug.getconstants(GCF) end)
        
        if CPC or CPCD then
            PCC = PCC + 1
            
            local GCC = 0
            
            while true do
                if #getconstants(GCF) == GCC or #getconstants(GCF) == GCC then break; end
                
                GCC = GCC + 1
                
                local C = CPC and getconstants(GCF)[GCC] or debug.getconstants(GCF)[GCC]
            end
        end
    end
end

if SF < 300 then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x13")
end

if GCI < 2000 then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x14")
end

if PCC < 100 then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x15")
end

if ALH >= 3 then
    return pcall(Player["Kick\0\0\0\0"], Player, "Magnet Tamper Protection - L_0x15")
end

getgenv().RegistryHook = "Ok" do
    RegistryHook = hookfunction(getreg, newcclosure(function()
        return RegistryBackup
    end))
end

local Request do
    if syn and syn.request then
        Request = syn.request
    elseif http and http.request then
        Request = request
    elseif request then
        Request = request
    end
end

local Headers = Request({Url = Whitelist, Method = "GET"})["Headers"]
local IsWhitelisted, WhitelistMethod = Headers["Is-Whitelisted"], Headers["Whitelist-Method"]
local WhitelistExists = Request({Url = Whitelist, Method = "POST", Headers = {whitelist = IsWhitelisted}})["Body"]

local Notification = loadstring(game:HttpGet("https://raw.githubusercontent.com/Jxereas/UI-Libraries/main/notification_gui_library.lua"))()

if WhitelistExists == "true" then
    Notification.new("info", "Magnet's Whitelist", "Whitelisted!")
else
    Notification.new("info", "Magnet's Whitelist", "Not Whitelisted!")
end
