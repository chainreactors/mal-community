--- common sharp
local function run_SharpWebServer(args)
    local session = active()
    local arch = session.Os.Arch
    local csharp_file = "common/SharpWebServer_net4.5.exe"
    return execute_assembly(session, script_resource(csharp_file), args, true,
                            new_sac())
end
command("common:sharpweb", run_SharpWebServer, "common sharpweb", "")

