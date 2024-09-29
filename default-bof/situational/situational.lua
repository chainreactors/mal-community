local situational = {}
bof_dir = "situational/"

-- dir 
function situational.help_dir() return "bof dir" end

function situational.parse_dir(args)
    size = #args
    if size > 2 or size <= 0 then error("<=2 arguments are allowed") end
    targetdir = '.\\'
    subdirs = "0"
    if size > 0 then targetdir = args[1] end
    if size == 2 and args[2] ~= '/s' then
        error("Invalid parameter: " .. args[2])
        return nil
    end
    if size == 2 and args[2] == '/s' then subdirs = "1" end
    return bof_pack("Zs", targetdir, subdirs)
end

function situational.run_dir(args)
    args = situational.parse_dir(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "dir", "o"), args,
               true, callback_log(session, true))
end

-- env 
function situational.help_env() return "bof env" end

function situational.parse_env(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_env(args)
    args = situational.parse_env(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "env", "o"), args,
               true)
end

-- adcs_enum 
function situational.help_adcs_enum() return "bof adcs_enum" end

function situational.parse_adcs_enum(args)
    size = #args
    domain = ''
    if size == 1 then domain = args[1] end
    return bof_pack("Z", domain)
end

function situational.run_adcs_enum(args)
    args = situational.parse_adcs_enum(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "adcs_enum", "o"),
               args, true)
end

-- arp 
function situational.help_arp() return "bof arp" end

function situational.parse_arp(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_arp(args)
    args = situational.parse_arp(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "arp", "o"), args,
               true)
end

-- cacls 
function situational.help_cacls() return "bof cacls" end

function situational.parse_cacls(args)
    size = #args
    if size ~= 1 then error("1 arguments are allowed") end
    file_path = args[1]
    return args
end

function situational.run_cacls(args)
    args = situational.parse_cacls(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "cacls", "o"),
               pack_bof_args("Z", args), true)
end

-- driversigs 
function situational.help_driversigs() return "bof driversigs" end

function situational.parse_driversigs(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_driversigs(args)
    args = situational.parse_driversigs(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "driversigs", "o"),
               args, true)
end

-- enum_filter_driver 
function situational.help_enum_filter_driver() return "bof enum_filter_driver" end

function situational.parse_enum_filter_driver(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    system = ''
    if size == 1 then system = args[1] end
    return bof_pack("z", system)
end

function situational.run_enum_filter_driver(args)
    args = situational.parse_enum_filter_driver(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "enum_filter_driver", "o"),
               args, true)
end

-- enumlocalsessions 
function situational.help_enumlocalsessions() return "bof enumlocalsessions" end

function situational.parse_enumlocalsessions(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_enumlocalsessions(args)
    args = situational.parse_enumlocalsessions(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "enumlocalsessions", "o"),
               args, true)
end

-- get_password_policy 
function situational.help_get_password_policy() return "bof get_password_policy" end

function situational.parse_get_password_policy(args)
    size = #args
    if size > 1 then error("0 arguments are allowed") end
    hostname = '.'
    if size == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_get_password_policy(args)
    args = situational.parse_get_password_policy(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "get_password_policy", "o"),
               args, true)
end

-- netsession 
function situational.help_netsession() return "bof netsession" end

function situational.parse_netsession(args)
    size = #args
    if size > 1 then error("0 arguments are allowed") end
    computer = ''
    if size == 1 then computer = args[1] end
    return bof_pack("Z", computer)
end

function situational.run_netsession(args)
    args = situational.parse_netsession(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "get_netsession", "o"), args,
               true)
end

-- ipconfig 
function situational.help_ipconfig() return "bof ipconfig" end

function situational.parse_ipconfig(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_ipconfig(args)
    args = situational.parse_ipconfig(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "ipconfig", "o"),
               args, true)
end

-- ldapsearch 
function situational.help_ldapsearch() return "bof ldapsearch" end

function situational.parse_ldapsearch(args)
    size = #args
    if size < 1 or size > 5 then error(" 1<=x<=5 arguments are allowed") end
    query = args[1]
    attributes = ''
    result_limit = 0
    hostname = ''
    domain = ''
    if size >= 2 then attributes = args[2] end
    if size >= 3 then result_limit = args[3] end
    if size >= 4 then hostname = args[4] end
    if size == 5 then domain = args[5] end
    return bof_pack("zzszz", query, attributes, result_limit, hostname, domain)
end

function situational.run_ldapsearch(args)
    args = situational.parse_ldapsearch(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "ldapsearch", "o"),
               args, true)
end

-- list_firewall_rules 
function situational.help_list_firewall_rules() return "bof list_firewall_rules" end

function situational.parse_list_firewall_rules(args)
    size = #args
    if size ~= 0 then error("<=0 arguments are allowed") end
    return args
end

function situational.run_list_firewall_rules(args)
    args = situational.parse_list_firewall_rules(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "list_firewall_rules", "o"),
               args, true)
end

-- listdns 
function situational.help_listdns() return "bof listdns" end

function situational.parse_listdns(args)
    size = #args
    if size ~= 0 then error("<=0 arguments are allowed") end
    return args
end

function situational.run_listdns(args)
    args = situational.parse_listdns(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "listdns", "o"), args,
               true)
end

-- locale 
function situational.help_locale() return "bof locale" end

function situational.parse_locale(args)
    size = #args
    if size ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_locale(args)
    args = situational.parse_locale(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "locale", "o"), args,
               true)
end

-- netgroup 
function situational.help_netgroup() return "bof netgroup" end

function situational.parse_netgroup(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    domain = ''
    group = ''
    if size == 1 then domain = args[1] end
    return bof_pack("sZZ", "0", domain, group)
end

function situational.run_netgroup(args)
    args = situational.parse_netgroup(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netgroup", "o"),
               args, true)
end

-- netgroup_list_members 
function situational.help_netgroup_list_members()
    return "bof netgroup_list_members"
end

function situational.parse_netgroup_list_members(args)
    size = #args
    if size < 1 or size > 2 then error("1<=x<=2 arguments are allowed") end
    domain = ''
    group = ''
    if size == 1 then
        group = args[1]
    elseif size == 2 then
        domain = args[1]
        group = args[2]
    end
    return bof_pack("sZZ", "1", domain, group)
end

function situational.run_netgroup_list_members(args)
    args = situational.parse_netgroup_list_members(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netgroup", "o"),
               args, true)
end

-- netlocalgroup 
function situational.help_netlocalgroup() return "bof netlocalgroup" end

function situational.parse_netlocalgroup(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    server = ''
    group = ''
    if size == 1 then server = args[1] end
    return bof_pack("sZZ", "0", server, group)
end

function situational.run_netlocalgroup(args)
    args = situational.parse_netlocalgroup(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netlocalgroup", "o"),
               args, true)
end

-- netshares 
function situational.help_netshares() return "bof netshares" end

function situational.parse_netshares(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    computer = ''
    if size == 1 then computer = args[1] end
    return bof_pack("Zi", computer)
end

function situational.run_netshares(args)
    args = situational.parse_netshares(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netshares", "o"),
               args, true)
end

-- netstat 
function situational.help_netstat() return "bof netstat" end

function situational.run_netstat(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netstat", "o"), args,
               true)
end

-- netuptime 
function situational.help_netuptime() return "bof netuptime" end

function situational.parse_netuptime(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    hostname = ''
    if size == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_netuptime(args)
    args = situational.parse_netuptime(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netuptime", "o"),
               args, true)
end

-- netuser 
function situational.help_netuser() return "bof netuser" end

function situational.parse_netuser(args)
    size = #args
    if size < 1 or size > 2 then error("1<=x<=2 arguments are allowed") end
    username = args[1]
    domain = ''
    if size == 2 then domain = args[2] end
    return bof_pack("ZZ", username, domain)
end

function situational.run_netuser(args)
    args = situational.parse_netuser(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netuser", "o"), args,
               true)
end

-- netuserenum 
function situational.help_netuserenum() return "bof netuserenum" end

function situational.parse_netuserenum(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end

    enumtype = {all = 1, locked = 2, disabled = 3, active = 4}
    _type = enumtype["all"]
    if size == 1 then
        arg = args[1]:lower()
        if enumtype[arg] == nil then
            error("Parameter not in: [all, locked, disabled, active]")
        end
        _type = enumtype[arg]
    end
    return bof_pack("ii", "0", _type)
end

function situational.run_netuserenum(args)
    args = situational.parse_netuserenum(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netuserenum", "o"),
               args, true)
end

-- netview 
function situational.help_netview() return "bof netview" end

function situational.parse_netview(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    computer = ''
    if size == 1 then computer = args[1] end
    return bof_pack("Z", computer)
end

function situational.run_netview(args)
    args = situational.parse_netview(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "netview", "o"), args,
               true)
end

-- nslookup 
function situational.help_nslookup() return "bof nslookup" end

function situational.parse_nslookup(args)
    size = #args
    if size < 1 then
        error("Missing parameters: at least 1 argument is required")
    elseif size > 3 then
        error("Too many parameters: 1 to 3 arguments are allowed")
    end

    recordmapping = {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        WKS = 0xb,
        PTR = 0xc,
        HINFO = 0xd,
        MINFO = 0xe,
        MX = 0xf,
        TEXT = 0x10,
        RP = 0x11,
        AFSDB = 0x12,
        X25 = 0x13,
        ISDN = 0x14,
        RT = 0x15,
        AAAA = 0x1c,
        SRV = 0x21,
        WINSR = 0xff02,
        KEY = 0x19,
        ANY = 0xff
    }
    lookup = args[1]
    server = ''
    if size >= 2 then
        server = args[2]
        if server == "127.0.0.1" then
            error("Localhost DNS queries have a potential to crash, refusing")
        end
    end
    record_type = recordmapping["A"]
    if size == 3 then
        requested_type = args[3]:upper()
        if recordmapping[requested_type] then
            record_type = recordmapping[requested_type]
        else
            error("Invalid record type: " .. requested_type)
        end
    end
    return bof_pack("zzs", lookup, server, record_type)
end

function situational.run_nslookup(args)
    args = situational.parse_nslookup(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "nslookup", "o"),
               args, true)
end

-- quser 
function situational.help_quser() return "bof quser" end

function situational.parse_quser(args)
    size = #args
    if size > 1 then error("<=1 arguments are allowed") end
    hostname = '127.0.0.1'
    if size == 1 then hostname = args[1] end
    return bof_pack("z", hostname)
end

function situational.run_quser(args)
    args = situational.parse_quser(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "quser", "o"), args,
               true)
end

-- reg_query 
function situational.help_reg_query() return "bof reg_query" end

function situational.parse_reg_query(args)
    size = #args
    params_parsed = 1
    reghives = {HKCR = 0, HKCU = 1, HKLM = 2, HKU = 3}
    if size < 2 then
        error("Missing parameters: at least 2 arguments are required")
    elseif size > 4 then
        error("Too many parameters: no more than 4 arguments are allowed")
    end

    hostname = nil
    if reghives[args[params_parsed]:upper()] == nil then
        hostname = args[params_parsed]
        params_parsed = params_parsed + 1
    end

    if reghives[args[params_parsed]:upper()] == nil then
        error("Provided registry hive value is invalid")
    end
    hive = reghives[args[params_parsed]:upper()]
    params_parsed = params_parsed + 1

    if size < params_parsed then
        error("Missing parameters: registry path is required")
    end

    path = args[params_parsed]
    params_parsed = params_parsed + 1

    key = nil
    if size >= params_parsed then key = args[params_parsed] end
    return bof_pack("ziss", hostname, hive, path, key or "", false)
end

function situational.run_reg_query(args)
    args = situational.parse_reg_query(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "reg_query", "o"),
               args, true)
end

-- resources 
function situational.help_resources() return "bof resources" end

function situational.run_resources(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "resources", "o"),
               args, true)
end

-- routeprint 
function situational.help_routeprint() return "bof routeprint" end

function situational.run_routeprint(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    session = active()
    return bof(session, find_resource(session, bof_dir .. "routeprint", "o"),
               args, true)
end

-- sc_enum 
function situational.help_sc_enum() return "bof sc_enum" end

function situational.parse_sc_enum(args)
    size = #args
    server = ""
    if size == 1 then
        server = args[1]
    elseif size > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    return bof_pack("z", server)
end

function situational.run_sc_enum(args)
    args = situational.parse_sc_enum(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "sc_enum", "o"), args,
               true)
end

-- sc_qc 
function situational.help_sc_qc() return "bof sc_qc" end

function situational.parse_sc_qc(args)
    size = #args
    service = ""
    server = ""
    if size == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif size == 1 then
        service = args[1]
    elseif size == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qc(args)
    args = situational.parse_sc_qc(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "sc_qc", "o"), args,
               true)
end

-- sc_qdescription 
function situational.help_sc_qdescription() return "bof sc_qdescription" end

function situational.parse_sc_qdescription(args)
    size = #args
    service = ""
    server = ""
    if size == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif size == 1 then
        service = args[1]
    elseif size == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qdescription(args)
    args = situational.parse_sc_qdescription(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "sc_qdescription", "o"), args,
               true)
end

-- sc_qfailure 
function situational.help_sc_qfailure() return "bof sc_qfailure" end

function situational.parse_sc_qfailure(args)
    size = #args
    service = ""
    server = ""
    if size == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif size == 1 then
        service = args[1]
    elseif size == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qfailure(args)
    args = situational.parse_sc_qfailure(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "sc_qfailure", "o"),
               args, true)
end

-- sc_qtriggerinfo 
function situational.help_sc_qtriggerinfo() return "bof sc_qtriggerinfo" end

function situational.parse_sc_qtriggerinfo(args)
    size = #args
    service = ""
    server = ""
    if size == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif size == 1 then
        service = args[1]
    elseif size == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qtriggerinfo(args)
    args = situational.parse_sc_qtriggerinfo(args)
    session = active()
    return bof(session,
               find_resource(session, bof_dir .. "sc_qtriggerinfo", "o"), args,
               true)
end

-- sc_query 
function situational.help_sc_query() return "bof sc_query" end

function situational.parse_sc_query(args)
    size = #args
    service = ""
    server = ""
    if size == 1 then
        service = args[1]
    elseif size == 2 then
        service = args[1]
        server = args[2]
    elseif size > 2 then
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_query(args)
    args = situational.parse_sc_query(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "sc_query", "o"),
               args, true)
end

-- schtasksenum 
function situational.help_schtasksenum() return "bof schtasksenum" end

function situational.parse_schtasksenum(args)
    size = #args
    server = ""
    if size == 1 then
        server = args[1]
    elseif size > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    return bof_pack("Z", server)
end

function situational.run_schtasksenum(args)
    args = situational.parse_schtasksenum(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "schtasksenum", "o"),
               args, true)
end

-- schtasksquery 
function situational.help_schtasksquery() return "bof schtasksquery" end

function situational.parse_schtasksquery(args)
    size = #args
    service = ""
    server = ""
    if size == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif size == 1 then
        service = args[1]
    elseif size == 2 then
        server = args[1]
        service = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("ZZ", server, service)
end

function situational.run_schtasksquery(args)
    args = situational.parse_schtasksquery(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "schtasksquery", "o"),
               args, true)
end

-- tasklist 
function situational.help_tasklist() return "bof tasklist" end

function situational.parse_tasklist(args)
    size = #args
    hostname = ""
    if size > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    if size == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_tasklist(args)
    args = situational.parse_tasklist(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "tasklist", "o"),
               args, true)
end

-- uptime 
function situational.help_uptime() return "bof uptime" end

function situational.run_uptime(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    session = active()
    return bof(session, find_resource(session, bof_dir .. "uptime", "o"), args,
               true)
end

-- whoami 
function situational.help_whoami() return "bof whoami" end

function situational.run_whoami(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    session = active()
    return bof(session, find_resource(session, bof_dir .. "whoami", "o"), args,
               true)
end

-- windowlist 
function situational.help_windowlist() return "bof windowlist" end

function situational.run_windowlist(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    session = active()
    return bof(session, find_resource(session, bof_dir .. "windowlist", "o"),
               args, true)
end

-- wmi_query 
function situational.help_wmi_query() return "bof wmi_query" end

function situational.parse_wmi_query(args)
    query = ""
    server = "."
    namespace = "root\\cimv2"
    size = #args

    if size < 1 then
        error("Missing parameters: at least 1 parameter is required")
    elseif size > 3 then
        error("Too many parameters: no more than 3 parameters are allowed")
    end
    query = args[1]
    if size > 1 then server = args[2] end
    if size > 2 then namespace = args[3] end
    resource = string.format("\\\\%s\\%s", server, namespace)
    return bof_pack("ZZZZ", server, namespace, query, resource)
end

function situational.run_wmi_query(args)
    args = situational.parse_wmi_query(args)
    session = active()
    return bof(session, find_resource(session, bof_dir .. "wmi_query", "o"),
               args, true)
end

-- screenshot 
function situational.help_screenshot() return "bof screenshot" end

function situational.parse_screenshot(args)
    size = #args
    if size ~= 1 then error("1 arguments are allowed") end
    filename = args[1]
    save = "1"
    return bof_pack("z", filename)
end

function situational.run_screenshot(args)
    screenshot_path = temp_dir .. "/" .. args[1]
    print(screenshot_path)
    args = situational.parse_screenshot(args)
    session = active()
    result = bof(session, find_resource(session, bof_dir .. "screenshot", "o"),
                 args, true, callback_file(screenshot_path))
    if result then
        print("Screenshot saved to: " .. screenshot_path)
    end
    return true
end

return situational
