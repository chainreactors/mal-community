local root_command= "proxy"
local function new_sac()
    local sac = new_sacrifice(0,false,false,false,"")
    return sac
end

-- gost
local function run_gost(args)
    local session = active()
    local pe_path = script_resource("proxy/gost_2.12.0_windows_amd64.exe")
    local arch = session.Os.Arch
    local sac = new_sac()
    return execute_exe(session, pe_path, args, true, 60, arch, "", sac)
end
command( root_command.. ":gost", run_gost, "Usage: proxy gost -- <gost args>", "")
