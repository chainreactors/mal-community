-- CS-Situational-Awareness-BOF Module
local situational = {}
situational.bof_dir = "SituationalAwareness/"

-- dir
function situational.parse_dir(args)
    if #args > 2 or #args <= 0 then error("<=2 arguments are allowed") end
    local targetdir = '.\\'
    local subdirs = "0"
    if #args > 0 then targetdir = args[1] end
    if #args == 2 and args[2] ~= '/s' then
        error("Invalid parameter: " .. args[2])
    end
    if #args == 2 and args[2] == '/s' then subdirs = "1" end
    return bof_pack("Zs", targetdir, subdirs)
end

function situational.run_dir(args)
    local session = active()
    args = situational.parse_dir(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "dir" .. "." .. arch .. ".o"), args,
               true, callback_log(session, true))
end
command("situational:dir", situational.run_dir,
        "Command: situational dir [targetdir] [/s]", "T1083")

-- env
function situational.parse_env(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_env(args)
    local session = active()
    args = situational.parse_env(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "env" .. "." .. arch .. ".o"), args,
               true)
end
command("situational:env", situational.run_env, "Command: situational env",
        "T1082")

-- adcs_enum
function situational.parse_adcs_enum(args)
    local domain = ''
    if #args == 1 then domain = args[1] end
    return bof_pack("Z", domain)
end

function situational.run_adcs_enum(args)
    local session = active()
    args = situational.parse_adcs_enum(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "adcs_enum" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:adcs_enum", situational.run_adcs_enum,
        "Command: situational adcs_enum [domain]", "T1557.002")

-- arp
function situational.parse_arp(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_arp(args)
    local session = active()
    args = situational.parse_arp(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "arp" .. "." .. arch .. ".o"), args,
               true)
end
command("situational:arp", situational.run_arp, "Command: situational arp",
        "T1016")

-- cacls
function situational.parse_cacls(args)
    if #args ~= 1 then error("1 argument is allowed") end
    local file_path = args[1]
    return bof_pack("Z", file_path)
end

function situational.run_cacls(args)
    local session = active()
    args = situational.parse_cacls(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "cacls" .. "." .. arch .. ".o"), args,
               true)
end
command("situational:cacls", situational.run_cacls,
        "Command: situational cacls <file_path>", "T1222.001")

-- driversigs
function situational.parse_driversigs(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_driversigs(args)
    local session = active()
    args = situational.parse_driversigs(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "driversigs" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:driversigs", situational.run_driversigs,
        "Command: situational driversigs", "T1012")

-- Enum Local Sessions
function situational.parse_enumlocalsessions(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_enumlocalsessions(args)
    local session = active()
    args = situational.parse_enumlocalsessions(args)
    local arch = session.Os.Arch
    return bof(session,
               script_resource(
                   situational.bof_dir .. "enumlocalsessions" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:enumlocalsessions", situational.run_enumlocalsessions,
        "Command: situational enumlocalsessions", "T1078")

-- get_password_policy
function situational.parse_get_password_policy(args)
    local hostname = '.'
    if #args == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_get_password_policy(args)
    local session = active()
    args = situational.parse_get_password_policy(args)
    local arch = session.Os.Arch
    return bof(session,
               script_resource(
                   situational.bof_dir .. "get_password_policy" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:get_password_policy", situational.run_get_password_policy,
        "Command: situational get_password_policy [hostname]", "T1201")

-- netsession
function situational.parse_netsession(args)
    local computer = ''
    if #args == 1 then computer = args[1] end
    return bof_pack("Z", computer)
end

function situational.run_netsession(args)
    local session = active()
    args = situational.parse_netsession(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "get_netsession" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:netsession", situational.run_netsession,
        "Command: situational netsession [computer]", "T1076")

-- ipconfig
function situational.parse_ipconfig(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_ipconfig(args)
    local session = active()
    args = situational.parse_ipconfig(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "ipconfig" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:ipconfig", situational.run_ipconfig,
        "Command: situational ipconfig", "T1016")

-- ldapsearch
function situational.parse_ldapsearch(args)
    if #args < 1 or #args > 5 then error("1<=x<=5 arguments are allowed") end
    local query = args[1]
    local attributes = ''
    local result_limit = 0
    local hostname = ''
    local domain = ''
    if #args >= 2 then attributes = args[2] end
    if #args >= 3 then result_limit = args[3] end
    if #args >= 4 then hostname = args[4] end
    if #args == 5 then domain = args[5] end
    return bof_pack("zzszz", query, attributes, result_limit, hostname, domain)
end

function situational.run_ldapsearch(args)
    local session = active()
    args = situational.parse_ldapsearch(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "ldapsearch" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:ldapsearch", situational.run_ldapsearch,
        "Command: situational ldapsearch <query> [attributes] [result_limit] [hostname] [domain]",
        "T1018")

-- list_firewall_rules
function situational.parse_list_firewall_rules(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_list_firewall_rules(args)
    local session = active()
    args = situational.parse_list_firewall_rules(args)
    local arch = session.Os.Arch
    return bof(session,
               script_resource(
                   situational.bof_dir .. "list_firewall_rules" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:list_firewall_rules", situational.run_list_firewall_rules,
        "Command: situational list_firewall_rules", "T1562.004")

-- listdns
function situational.parse_listdns(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_listdns(args)
    local session = active()
    args = situational.parse_listdns(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "listdns" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:listdns", situational.run_listdns,
        "Command: situational listdns", "T1016")

-- locale
function situational.parse_locale(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_locale(args)
    local session = active()
    args = situational.parse_locale(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "locale" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:locale", situational.run_locale,
        "Command: situational locale", "T1614")

-- netgroup
function situational.parse_netgroup(args)
    local domain = ''
    local group = ''
    if #args == 1 then domain = args[1] end
    return bof_pack("sZZ", "0", domain, group)
end

function situational.run_netgroup(args)
    local session = active()
    args = situational.parse_netgroup(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netgroup" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netgroup", situational.run_netgroup,
        "Command: situational netgroup [domain]", "T1069")

-- netgroup_list_members
function situational.parse_netgroup_list_members(args)
    local domain = ''
    local group = ''
    if #args == 1 then
        group = args[1]
    elseif #args == 2 then
        domain = args[1]
        group = args[2]
    end
    return bof_pack("sZZ", "1", domain, group)
end

function situational.run_netgroup_list_members(args)
    local session = active()
    args = situational.parse_netgroup_list_members(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netgroup" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netgroup_list_members",
        situational.run_netgroup_list_members,
        "Command: situational netgroup_list_members <group> [domain]", "T1069")

-- netlocalgroup
function situational.parse_netlocalgroup(args)
    local server = ''
    local group = ''
    if #args == 1 then server = args[1] end
    return bof_pack("sZZ", "0", server, group)
end

function situational.run_netlocalgroup(args)
    local session = active()
    args = situational.parse_netlocalgroup(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netlocalgroup" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netlocalgroup", situational.run_netlocalgroup,
        "Command: situational netlocalgroup [server]", "T1069")

-- netshares
function situational.parse_netshares(args)
    local computer = ''
    if #args == 1 then computer = args[1] end
    return bof_pack("Zi", computer)
end

function situational.run_netshares(args)
    local session = active()
    args = situational.parse_netshares(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netshares" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netshares", situational.run_netshares,
        "Command: situational netshares [computer]", "T1135")

-- netstat
function situational.parse_netstat(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    return args
end

function situational.run_netstat(args)
    local session = active()
    args = situational.parse_netstat(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netstat" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netstat", situational.run_netstat,
        "Command: situational netstat", "T1049")

-- netuptime
function situational.parse_netuptime(args)
    local hostname = ''
    if #args == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_netuptime(args)
    local session = active()
    args = situational.parse_netuptime(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netuptime" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netuptime", situational.run_netuptime,
        "Command: situational netuptime [hostname]", "T1124")

-- netuser
function situational.parse_netuser(args)
    if #args < 1 or #args > 2 then error("1<=x<=2 arguments are allowed") end
    local username = args[1]
    local domain = ''
    if #args == 2 then domain = args[2] end
    return bof_pack("ZZ", username, domain)
end

function situational.run_netuser(args)
    local session = active()
    args = situational.parse_netuser(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netuser" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netuser", situational.run_netuser,
        "Command: situational netuser <username> [domain]", "T1087.002")

-- netuserenum
function situational.parse_netuserenum(args)
    if #args > 1 then error("<=1 arguments are allowed") end
    local enumtype = {all = 1, locked = 2, disabled = 3, active = 4}
    local _type = enumtype["all"]
    if #args == 1 then
        local arg = args[1]:lower()
        if enumtype[arg] == nil then
            error("Parameter not in: [all, locked, disabled, active]")
        end
        _type = enumtype[arg]
    end
    return bof_pack("ii", "0", _type)
end

function situational.run_netuserenum(args)
    local session = active()
    args = situational.parse_netuserenum(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netuserenum" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netuserenum", situational.run_netuserenum,
        "Command: situational netuserenum [all|locked|disabled|active]",
        "T1087.002")

-- netview
function situational.parse_netview(args)
    local computer = ''
    if #args == 1 then computer = args[1] end
    return bof_pack("Z", computer)
end

function situational.run_netview(args)
    local session = active()
    args = situational.parse_netview(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "netview" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:netview", situational.run_netview,
        "Command: situational netview [computer]", "T1018")

-- nslookup
function situational.parse_nslookup(args)
    if #args < 1 then
        error("Missing parameters: at least 1 argument is required")
    elseif #args > 3 then
        error("Too many parameters: 1 to 3 arguments are allowed")
    end

    local recordmapping = {
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

    local lookup = args[1]
    local server = ''
    if #args >= 2 then
        server = args[2]
        if server == "127.0.0.1" then
            error("Localhost DNS queries have a potential to crash, refusing")
        end
    end

    local record_type = recordmapping["A"]
    if #args == 3 then
        local requested_type = args[3]:upper()
        if recordmapping[requested_type] then
            record_type = recordmapping[requested_type]
        else
            error("Invalid record type: " .. requested_type)
        end
    end

    return bof_pack("zzs", lookup, server, record_type)
end

function situational.run_nslookup(args)
    local session = active()
    args = situational.parse_nslookup(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "nslookup" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:nslookup", situational.run_nslookup,
        "Command: situational nslookup <lookup> [server] [record type]", "T1016")

-- quser
function situational.parse_quser(args)
    local hostname = '127.0.0.1'
    if #args == 1 then hostname = args[1] end
    return bof_pack("z", hostname)
end

function situational.run_quser(args)
    local session = active()
    args = situational.parse_quser(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "quser" .. "." .. arch .. ".o"), args,
               true)
end
command("situational:quser", situational.run_quser,
        "Command: situational quser [hostname]", "T1078.001")

-- reg_query
function situational.parse_reg_query(args)
    local reghives = {HKCR = 0, HKCU = 1, HKLM = 2, HKU = 3}
    if #args < 2 then
        error("Missing parameters: at least 2 arguments are required")
    elseif #args > 4 then
        error("Too many parameters: no more than 4 arguments are allowed")
    end

    local params_parsed = 1
    local hostname = nil
    if reghives[args[params_parsed]:upper()] == nil then
        hostname = args[params_parsed]
        params_parsed = params_parsed + 1
    end

    if reghives[args[params_parsed]:upper()] == nil then
        error("Provided registry hive value is invalid")
    end
    local hive = reghives[args[params_parsed]:upper()]
    params_parsed = params_parsed + 1

    if #args < params_parsed then
        error("Missing parameters: registry path is required")
    end

    local path = args[params_parsed]
    params_parsed = params_parsed + 1

    local key = nil
    if #args >= params_parsed then key = args[params_parsed] end

    return bof_pack("ziss", hostname, hive, path, key or "", false)
end

function situational.run_reg_query(args)
    local session = active()
    args = situational.parse_reg_query(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "reg_query" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:reg_query", situational.run_reg_query,
        "Command: situational reg_query <hive> <path> [key]", "T1012")

-- resources
function situational.run_resources(args)
    local session = active()
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "resources" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:resources", situational.run_resources,
        "Command: situational resources", "T1082")

-- routeprint
function situational.run_routeprint(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    local session = active()
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "routeprint" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:routeprint", situational.run_routeprint,
        "Command: situational routeprint", "T1016")

-- sc_enum
function situational.parse_sc_enum(args)
    local server = ""
    if #args == 1 then
        server = args[1]
    elseif #args > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    return bof_pack("z", server)
end

function situational.run_sc_enum(args)
    local session = active()
    args = situational.parse_sc_enum(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_enum" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:sc_enum", situational.run_sc_enum,
        "Command: situational sc_enum [server]", "T1057")

-- sc_qc
function situational.parse_sc_qc(args)
    local service = ""
    local server = ""
    if #args == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif #args == 1 then
        service = args[1]
    elseif #args == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qc(args)
    local session = active()
    args = situational.parse_sc_qc(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_qc" .. "." .. arch .. ".o"), args,
               true)
end
command("situational:sc_qc", situational.run_sc_qc,
        "Command: situational sc_qc <service> [server]", "T1057")

-- sc_qdescription
function situational.parse_sc_qdescription(args)
    local service = ""
    local server = ""
    if #args == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif #args == 1 then
        service = args[1]
    elseif #args == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qdescription(args)
    local session = active()
    args = situational.parse_sc_qdescription(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_qdescription" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:sc_qdescription", situational.run_sc_qdescription,
        "Command: situational sc_qdescription <service> [server]", "T1057")

-- sc_qfailure
function situational.parse_sc_qfailure(args)
    local service = ""
    local server = ""
    if #args == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif #args == 1 then
        service = args[1]
    elseif #args == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qfailure(args)
    local session = active()
    args = situational.parse_sc_qfailure(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_qfailure" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:sc_qfailure", situational.run_sc_qfailure,
        "Command: situational sc_qfailure <service> [server]", "T1057")

-- sc_qtriggerinfo
function situational.parse_sc_qtriggerinfo(args)
    local service = ""
    local server = ""
    if #args == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif #args == 1 then
        service = args[1]
    elseif #args == 2 then
        service = args[1]
        server = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_qtriggerinfo(args)
    local session = active()
    args = situational.parse_sc_qtriggerinfo(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_qtriggerinfo" .. "." .. arch ..
                       ".o"), args, true)
end
command("situational:sc_qtriggerinfo", situational.run_sc_qtriggerinfo,
        "Command: situational sc_qtriggerinfo <service> [server]", "T1057")

-- sc_query
function situational.parse_sc_query(args)
    local service = ""
    local server = ""
    if #args == 1 then
        service = args[1]
    elseif #args == 2 then
        service = args[1]
        server = args[2]
    elseif #args > 2 then
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("zz", server, service)
end

function situational.run_sc_query(args)
    local session = active()
    args = situational.parse_sc_query(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "sc_query" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:sc_query", situational.run_sc_query,
        "Command: situational sc_query <service> [server]", "T1057")

-- schtasksenum
function situational.parse_schtasksenum(args)
    local server = ""
    if #args == 1 then
        server = args[1]
    elseif #args > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    return bof_pack("Z", server)
end

function situational.run_schtasksenum(args)
    local session = active()
    args = situational.parse_schtasksenum(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "schtasksenum" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:schtasksenum", situational.run_schtasksenum,
        "Command: situational schtasksenum [server]", "T1053.005")

-- schtasksquery
function situational.parse_schtasksquery(args)
    local service = ""
    local server = ""
    if #args == 0 then
        error("Not enough parameters: at least 1 parameter is required")
    elseif #args == 1 then
        service = args[1]
    elseif #args == 2 then
        server = args[1]
        service = args[2]
    else
        error("Too many parameters: no more than 2 parameters are allowed")
    end
    return bof_pack("ZZ", server, service)
end

function situational.run_schtasksquery(args)
    local session = active()
    args = situational.parse_schtasksquery(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "schtasksquery" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:schtasksquery", situational.run_schtasksquery,
        "Command: situational schtasksquery <service> [server]", "T1053.005")

-- tasklist
function situational.parse_tasklist(args)
    local hostname = ""
    if #args > 1 then
        error("Too many parameters: only 0 or 1 parameter is allowed")
    end
    if #args == 1 then hostname = args[1] end
    return bof_pack("Z", hostname)
end

function situational.run_tasklist(args)
    local session = active()
    args = situational.parse_tasklist(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "tasklist" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:tasklist", situational.run_tasklist,
        "Command: situational tasklist [hostname]", "T1057")

-- uptime
function situational.run_uptime(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    local session = active()
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "uptime" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:uptime", situational.run_uptime,
        "Command: situational uptime", "T1124")

-- whoami
function situational.run_whoami(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    local session = active()
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "whoami" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:whoami", situational.run_whoami,
        "Command: situational whoami", "T1033")

-- windowlist
function situational.run_windowlist(args)
    if #args ~= 0 then error("0 arguments are allowed") end
    local session = active()
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "windowlist" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:windowlist", situational.run_windowlist,
        "Command: situational windowlist", "T1057")

-- wmi_query
function situational.parse_wmi_query(args)
    local query = ""
    local server = "."
    local namespace = "root\\cimv2"
    if #args < 1 then
        error("Missing parameters: at least 1 parameter is required")
    elseif #args > 3 then
        error("Too many parameters: no more than 3 parameters are allowed")
    end
    query = args[1]
    if #args > 1 then server = args[2] end
    if #args > 2 then namespace = args[3] end
    local resource = string.format("\\\\%s\\%s", server, namespace)
    return bof_pack("ZZZZ", server, namespace, query, resource)
end

function situational.run_wmi_query(args)
    local session = active()
    args = situational.parse_wmi_query(args)
    local arch = session.Os.Arch
    return bof(session, script_resource(
                   situational.bof_dir .. "wmi_query" .. "." .. arch .. ".o"),
               args, true)
end
command("situational:wmi_query", situational.run_wmi_query,
        "Command: situational wmi_query <query> [server] [namespace]", "T1047")

-- screenshot

function situational.run_screenshot(args)
    local filename
    if #args == 1 then
        filename = args[1]
    else
        filename = "screenshot.jpg"
    end
    local packed_args = bof_pack("z", filename)
    local session = active()
    local arch = session.Os.Arch
    local result = bof(session, script_resource(
                           situational.bof_dir .. "screenshot" .. "." .. arch ..
                               ".o"), packed_args, true,
                       callback_bof(session, filename))
    if result == false then return "Screenshot failed" end
    return "Screenshot OK"
end
command("situational:screenshot", situational.run_screenshot,
        "Command: situational screenshot <filename>", "T1113")
