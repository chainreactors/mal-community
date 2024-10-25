local regexp = require("regexp")
local time = require("time")

local function noconsolation(args)
    local PE, path, path_set, name_set, pebytes, x, matchfound, pe_id, local_load
    local cmdline, headers, method, use_unicode, timeout, timeout_set, nooutput, alloc_console, close_handles
    local free_libs, dont_save, list_pes, unload_pe, link_to_peb, dont_unload, load_all_deps, load_all_deps_but, load_deps
    local search_paths, pepath, pename, inthread = args[1], "", "", "", 0, 0, "", 0, false, 0, 0, "", 0, 0, 0, 0, 0, "", "", "", "", 0
    print(args)
    --local is64 = binfo(bid, "is64") -- todo
    local session = active()
    local barch = session.Os.Arch
    -- todo
    if barch == "x86" and is64 == 1 then
        error(bid, "WoW64 is not supported")
        return
    end

    if #args < 2 then
        error("Invalid number of arguments")
        return
    end

    local i = 1
    while i <= #args do
        local arg = args[i]
        if arg == "--local" or arg == "-l" then
            local_load = 1
        elseif arg == "--timeout" or arg == "-t" then
            i = i + 1
            timeout = args[i]
            if not timeout then
                error( "missing --timeout value")
            elseif not tonumber(timeout) then
                error( "Invalid timeout: " .. args[i])
            end
            timeout_set = 1
        elseif arg == "-k" then
            headers = 1
        elseif arg == "--method" or arg == "-m" then
            i = i + 1
            method = args[i]
            if method == nil then
                error( "missing --method value" )
            end
        elseif arg == "-w" then
            use_unicode = 1
        elseif arg == "--no-output" or arg == "-no" then
            nooutput = 1
        elseif arg == "--alloc-console" or arg == "-ac" then
            alloc_console = 1
        elseif arg == "--close-handles" or arg == "-ch" then
            close_handles = 1
        elseif arg == "--free-libraries" or arg == "-fl" then
            i = i + 1
            free_libs = args[i]
            if free_libs == nil then
                error( "missing --free-libraries value")
            end
        elseif arg == "--dont-save" or arg == "-ds" then
            dont_save = 1
        elseif arg == "--list-pes" or arg == "-lpe" then
            list_pes = 1
        elseif arg == "--unload-pe" or arg == "-upe" then
            i = i + 1
            unload_pe = args[i]
            if unload_pe == nil then
                error("missing --unload-pe value")
            end
        elseif arg == "--link-to-peb" or arg == "-ltp" then
            link_to_peb = 1
        elseif arg == "--dont-unload" or arg == "-du" then
            dont_unload = 1
        elseif arg == "--load-all-dependencies" or arg == "-lad" then
            load_all_deps = 1
        elseif arg == "--load-all-dependencies-but" or arg == "-ladb" then
            i = i + 1
            load_all_deps_but = args[i]
            if load_all_deps_but == nil then
                error("missing --load-all-dependencies-but value")
            end
        elseif arg == "--load-dependencies" or arg == "-ld" then
            i = i + 1
            load_deps = args[i]
            if load_deps == nil then
                error("missing --load-dependencies value")
            end
        elseif arg == "--search-paths" or arg == "-sp" then
            i = i + 1
            search_paths = args[i]
            if search_paths == nil then
                error("missing --search-paths value")
            end
        elseif arg == "--inthread" or arg == "-it" then
            inthread = 1
        elseif file_exists(arg) or ismatch("^\p{Alpha}:\\\\.*", arg) then
            path = args[i]
            path_set = 1
            break
        elseif local_load == 0 and file_exists(arg) and ismatch("^/\p{Alpha}.*",arg) then
            error("Specified executable ".. args .. " does not exist")
        elseif arg == "--help" or arg == "-h" then
            error("Usage: noconsolation")
        else
            error("invalid argument: " .. arg)
        end
        i = i + 1
    end

    if (free_libs == "" and unload_pe == "" and list_pes == 0 and name_set == 0 and path_set == 0 and close_handles == 0) then
        error( "PE path not provided")
    end

    if path_set ~= nil and file_exists(path) and local_load ==1 then
        PE = path
    end

    if path_set ~= nil and list_pes then
        error("The option --list-pes must be ran alone")
    end

    if unload_pe ~= "" and list_pes then
        error("The option --list-pes must be ran alone")
    end

    if free_libs ~= "" and free_libs ~= "" then
        error("The option --list-pes must be ran alone")
    end

    if free_libs ~= "" and unload_pe ~= "" then
        error("The option --unload-pe must be ran alone")
    end

    if path_set ==1 and free_libs ~= "" then
        error("The option --free-libraries must be ran alone")
    end

    if timeout_set == 1 and inthread == 1 then
        error( "The options --inthread and --timeout are not compatible")
    end
    if path_set == 1 then
        if local_load ~=1 then
            pename = strings.split(arg, "/")
            pename = "C:\\Windows\\System32\\" .. pename
            local data = read(path)
            if data == nil then
                error("Could not read PE file")
            end
            path = ''
        else
            pename = strings.split(path, "\\\\")
            pepath = path
        end
    end
    if path_set == 1 or name_set then
        cmdline = pename
        for y = i + 1, #args do
            local y_arg = string.gsub(args[y], '\\"', '"')
            cmdline = cmdline .. " " .. arg
        end
    end
    local nick = "nick"
     runpe(pename, pepath, pebytes, path, local_load, timeout, headers, cmdline, method, use_unicode, nooutput, alloc_console, close_handles, free_libs, dont_save, list_pes, unload_pe, nick, tstamp(), link_to_peb, dont_unload, load_all_deps, load_all_deps_but, load_deps, search_paths, inthread)
end

local function runpe(pename, pepath, pebytes, path, local_load, timeout, headers, cmdline, method, use_unicode, nooutput, alloc_console, close_handles, free_libs, dont_save, list_pes, unload_pe, nick, timestamp, link_to_peb, dont_unload, load_all_deps, load_all_deps_but, load_deps, search_paths, inthread)
    local session = active()
    local barch = session.Os.Arch
    local bof_path = "No-Consolation/dist/NoConsolation" .. barch .. ".o"
    local packed_args = bof_pack(
            "ZzZbziiiZzziiiziiizzziiizzzi",
            pename, pename,
            pepath, pebytes, path,
            local_load, timeout, headers,
            cmdline, cmdline,
            method, use_unicode,
            nooutput, alloc_console,
            close_handles, free_libs, dont_save,
            list_pes, unload_pe,
            nick, timestamp,
            link_to_peb, dont_unload,
            load_all_deps, load_all_deps_but,
            load_deps, search_paths, inthread
    )
    print("nick")
    return bof(session, script_resource(bof_path), packed_args, true)
end

command("nc:noconsolation", noconsolation, "Run an unmanaged EXE/DLL inside Beacon's memory","T")
