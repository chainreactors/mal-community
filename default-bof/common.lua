function bof_pack(format, ...)
    local args = {...}
    return pack_bof_args(format, args)
end

function auto_register_commands(parent_name, module)
    for name, func in pairs(module) do
        if type(func) == "function" and name:match("^run_") then
            local command_name = name:sub(5)
            local help_func = module["help_" .. command_name]
            local register_name = parent_name .. "_" .. command_name
            if help_func then
                command(register_name, func, "Command: " .. command_name)
                help(register_name, help_func())
            else
                print("No help function for " .. command_name)
            end
        end
    end
end
