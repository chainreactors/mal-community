function run_gogo(cmd, args)
    local session = active()
    local arch = session.Os.Arch
    local gogo_path = "chainreactors/gogo.exe"
    return execute_exe(session, script_resource(gogo_path), args, true, 600, arch, "", new_sac())
end

command("gogo", run_gogo, "gogo", "T1046")

function run_port_scan(cmdline, flag_ip, flag_port)
    local session = active()
    session = with_context(session, "gogo")
    local arch = session.Os.Arch
    local gogo_path = "chainreactors/gogo.exe"
    args = shellsplit(cmdline .. " -p " .. flag_port .. " -i " .. flag_ip .. " -o" .. " jl" .. " -q")
    return execute_exe(session, script_resource(gogo_path), args, true, 600, arch, "", new_sac(),
        callback_context(session))
end

command("portscan", run_port_scan, "port scan with gogo", "T1046")

function run_zombie(cmd, args)
    local session = active()
    local arch = session.Os.Arch
    local zombie_path = "chainreactors/zombie.exe"
    return execute_exe(session, script_resource(zombie_path), args, true, 600, arch, "", new_sac())
end

command("zombie", run_zombie, "zombie", "T1078")


function run_brute(cmd, cmdline, flag_input, flag_user, flag_pass)
    local session = active()
    session = with_context(session, "zombie")
    local arch = session.Os.Arch
    local zombie_path = "chainreactors/zombie.exe"
    args = shellsplit(cmdline ..
        " -i " .. flag_input .. " -u " .. flag_user .. " -p " .. flag_pass .. " -o " .. " jl" .. " -q")
    return execute_exe(session, script_resource(zombie_path), args, true, 600, arch, "", new_sac(),
        callback_context(session))
end

command("brute", run_brute, "brute with zombie", "T1078")
