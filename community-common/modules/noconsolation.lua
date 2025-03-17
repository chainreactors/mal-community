local strings = require("strings")
local filepath = require("filepath")
local noconsolation_dir = "No-Consolation/dist/"

local function run_noconsolation(args)
    local session = active()
    local bid = session.id
    local arch = session.Os.Arch
    local pe_id = 0
    local local_flag = 0
    local i = 1
    local path = ''
    local pename = ''
    local pepath = ''
    local path_set = 0
    local name_set = 0
    local pebytes = ''
    local headers = 0
    local method = ''
    local use_unicode = 0
    local timeout = 60
    local timeout_set = 0
    local nooutput = 0
    local alloc_console = 0
    local close_handles = 0
    local free_libs = ""
    local dont_save = 0
    local list_pes = 0
    local unload_pe = ""
    local link_to_peb = 0
    local dont_unload = 0
    local load_all_deps = 0
    local load_all_deps_but = ""
    local load_deps = ""
    local search_paths = ""
    local inthread = 0
    local cmdline = ""
    
    -- if session.Os.Arch == "x32" and session.is64 == 1 then
    --     error("WoW64 is not supported")
    -- end

    if #args < 2 then
        error("Invalid number of arguments")
    end
    print(args)
    -- 解析参数
    i = 1
    while i <= #args do
        if args[i] == "--local" or args[i] == "-l" then
            local_flag = 1
        elseif args[i] == "--timeout" or args[i] == "-t" then
            i = i + 1
            if i > #args then
                error("Missing --timeout value")
            end
            timeout = tonumber(args[i])
            if not timeout then
                error("Invalid timeout value: " .. args[i+1])
            end
            timeout_set = 1
        elseif args[i] == "-k" then
            headers = 1
        elseif args[i] == "--method" or args[i] == "-m" then
            i = i + 1
            if i > #args then
                error("Missing --method value")
            end
            method = args[i]
        elseif arg == "-w" then
            use_unicode = 1
        elseif args[i] == "--no-output" or args[i] == "-no" then
            nooutput = 1
        elseif args[i] == "--alloc-console" or args[i] == "-ac" then
            alloc_console = 1
        elseif args[i] == "--close-handles" or args[i] == "-ch" then
            close_handles = 1
        elseif args[i] == "--free-libraries" or args[i]  == "-fl" then
            i = i + 1
            if i > #args then
                error("Missing --free-libraries value")
            end
            free_libs = args[i]
        elseif args[i] == "--dont-save" or args[i] == "-ds" then
            dont_save = 1
        elseif args[i] == "--list-pes" or args[i] == "-lpe" then
            list_pes = 1
        elseif args[i] == "--unload-pe" or args[i] == "-upe" then
            i = i + 1
            if i > #args then
                error("Missing --unload-pe value")
            end
            unload_pe = args[i+1]
        elseif arg == "--link-to-peb" or arg == "-ltp" then
            link_to_peb = 1
        elseif args[i] == "--dont-unload" or args[i] == "-du" then
            dont_unload = 1
        elseif args[i] == "--load-all-dependencies" or args[i] == "-lad" then
            load_all_deps = 1
        elseif args[i] == "--load-all-dependencies-but" or args[i] == "-ladb" then
            i = i + 1
            if i > #args then
                error("Missing --load-all-dependencies-but value")
            end
            load_all_deps_but = args[i]
        elseif args[i] == "--load-dependencies" or args[i] == "-ld" then
            i = i + 1
            if i > #args then
                error("Missing --load-dependencies value")
            end
            load_deps = args[i+1]
        elseif args[i] == "--search-paths" or args[i]    == "-sp" then
            i = i + 1
            if i > #args then
                error("Missing --search-paths value")
            end
            search_paths = args[i]
        elseif arg == "--inthread" or arg == "-it" then
            inthread = 1
        elseif file_exists(args[i]) or args[i]:match('^\p{Alpha}:\\\\.*') then
            path_set = 1
            path = args[i]
            break
        elseif local_flag == 0 and not file_exists(args[i]) and args[i]:match('^\\p{Alpha}.*\.exe') then
            error("Specified executable " .. args[i] .." does not exist")
        elseif local_flag == 0 and not file_exists(args[i]) and args[i]:match('^\p{Alpha}.*\.exe') then
            name_set = 1
            pename = args[i]
        elseif args[i] == "--help" or args[i] == "-h" then
            print("Help information...")
            return
        else
            error("invalid argument: " .. args[i])
        end
        i = i + 1
    end
    -- allow users to perform some tasks without having to run a PE
    if #free_libs == 0 and #unload_pe == 0 and list_pes == 0 and name_set == 0 and path_set == 0 and close_handles == 0 then
        error("PE path not provided")
    end

    if path_set == 1 and not file_exists(path) and local_flag == 0 then
        error("Specified executable ".. path .." does not exist")
    end
    if path_set == 1 and list_pes == 1 then
        error("The option --list-pes must be ran alone")
    end

    if #unload_pe ~= 0 and list_pes == 1 then
        error("The option --list-pes must be ran alone")
    end
    
    if #free_libs ~= 0 and list_pes == 1 then
        error("The option --list-pes must be ran alone")
    end
    if #free_libs ~= 0 and unload_pe ~= 0 then
        error("The option --unload-pe must be ran alone")
    end

    if path_set == 1 and #unload_pe ~= 0 then
        error("The option --unload-pe must be ran alone")
    end
    if path_set == 1 and #free_libs ~= 0 then
        error("The option --free-libraries must be ran alone")
    end

    if timeout_set == 1 and inthread == 1 then
        error("The option --inthread and --timeout are not compatible")
    end

    if path_set == 1 then
        if local_flag == 0 then
            split_str = strings.split("/", path)
            pename = split_str[#split_str]
            print("pename: " .. pename)
            pepath = "C:\\Windows\\System32\\" .. pename
            pebytes = read(path)
            if pebytes == nil then
                error("could not read PE")
            end
            path = ''
        else
            split_str = strings.split('\\\\', path)
            -- print("path: " .. path)
            -- pename = split_str[#split_str]
            print("pename2: " .. pename)
            pename = filepath.basename(path)
            pepath = path
        end
    end
    local cmdline = pename 
    if path_set == 1 or name_set == 1 then
        for y = i + 1, #args do
            arg = string.gsub(args[y], '\\"', '"')
            cmdline = cmdline .. " " .. arg
        end
    end

    local mynick = "user1" 
    local time_stamp = timestamp()
    local pack_args = bof_pack("ZzZbziiiZzziiizziizzziiizzzi", pename, pename, pepath, pebytes, path, local_flag, timeout, headers, cmdline, cmdline ,method,use_unicode,nooutput,alloc_console,close_handles,free_libs,dont_save,list_pes,unload_pe,mynick,time_stamp,link_to_peb,dont_unload,load_all_deps,load_all_deps_but,load_deps,search_paths,inthread)

    local bof_file = noconsolation_dir .. "NoConsolation." .. arch .. ".o"

    return bof(session, script_resource(bof_file), pack_args, true)
end

-- 注册命令
command("noconsolation", run_noconsolation, "noconsolation", "")