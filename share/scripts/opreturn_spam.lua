-- Chained OP_RETURN Spam Detector for Bitcoin Knots
-- Detects data embedding via chained OP_RETURN outputs with 0x01bc magic prefix
-- Compatible with Bitcoin Knots PR #119 modular filter system

-- Knotwork/444 magic prefix
local KNOTWORK_MAGIC = {0x01, 0xbc}

local function extract_opreturn_data(script_pubkey)
    if #script_pubkey < 2 then
        return nil
    end
    
    -- Check for OP_RETURN (0x6a)
    local first_byte = string.byte(script_pubkey, 1)
    if first_byte ~= 0x6a then
        return nil
    end
    
    -- Skip OP_RETURN and PUSH opcodes to get to actual data
    local i = 2
    local opcode = string.byte(script_pubkey, i)
    
    -- Handle PUSHDATA opcodes (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4)
    if opcode == 0x4c then
        -- OP_PUSHDATA1: next byte is length
        i = i + 2
    elseif opcode == 0x4d then
        -- OP_PUSHDATA2: next 2 bytes are length
        i = i + 3
    elseif opcode == 0x4e then
        -- OP_PUSHDATA4: next 4 bytes are length
        i = i + 5
    elseif opcode > 0 and opcode <= 0x4b then
        -- Direct push opcode (1-75 bytes)
        i = i + 1
    else
        return nil
    end
    
    if i > #script_pubkey then
        return nil
    end
    
    -- Extract the data portion
    return string.sub(script_pubkey, i)
end

local function has_magic_prefix(data)
    if not data or #data < 2 then
        return false
    end
    
    local byte1 = string.byte(data, 1)
    local byte2 = string.byte(data, 2)
    
    return byte1 == KNOTWORK_MAGIC[1] and byte2 == KNOTWORK_MAGIC[2]
end

local function get_chunk_info(data)
    if not data or #data < 4 then
        return nil
    end
    
    return {
        chunk_index = string.byte(data, 3),
        total_chunks = string.byte(data, 4)
    }
end

-- Main filter function called by Bitcoin Knots
function validate(tx, ctx)
    local outputs = tx:get_outputs()
    local opreturn_outputs = {}
    local has_magic = false
    local has_chain_pattern = false
    local largest_opreturn = 0
    local details = {}
    
    -- Find all OP_RETURN outputs
    for i, output in ipairs(outputs) do
        if output:is_op_return() then
            table.insert(opreturn_outputs, {
                index = i - 1,
                output = output,
                script = output:get_script_pubkey()
            })
        end
    end
    
    -- No OP_RETURN outputs
    if #opreturn_outputs == 0 then
        return {
            accept = true,
            score = 0,
            reason = "No OP_RETURN outputs"
        }
    end
    
    -- Analyze each OP_RETURN output
    for _, op_out in ipairs(opreturn_outputs) do
        local data = extract_opreturn_data(op_out.script)
        
        if data then
            local data_size = #data
            if data_size > largest_opreturn then
                largest_opreturn = data_size
            end
            
            -- Check for knotwork magic prefix (444 protocol)
            if has_magic_prefix(data) then
                has_magic = true
                details.magic_prefix = true
                
                local chunk_info = get_chunk_info(data)
                if chunk_info then
                    details.chunk_index = chunk_info.chunk_index
                    details.total_chunks = chunk_info.total_chunks
                    
                    if ctx and ctx.log_warn then
                        ctx:log_warn(string.format(
                            "Knotwork magic (444) detected: chunk %d/%d",
                            chunk_info.chunk_index,
                            chunk_info.total_chunks
                        ))
                    end
                end
            end
        end
    end
    
    -- Check for continuation output pattern (small value output for chaining)
    local has_continuation = false
    for _, output in ipairs(outputs) do
        local value = output:get_value()
        if value > 0 and value < 15000 then
            has_continuation = true
            break
        end
    end
    
    if has_continuation and #opreturn_outputs > 0 then
        has_chain_pattern = true
        details.has_continuation = true
    end
    
    -- Detect knotwork magic prefix (high confidence)
    if has_magic then
        return {
            accept = false,
            score = 95,
            reason = "Knotwork magic prefix (444) detected in OP_RETURN data"
        }
    end
    
    -- Detect chained OP_RETURN pattern (medium confidence)
    if has_chain_pattern then
        return {
            accept = false,
            score = 60,
            reason = "Chained OP_RETURN pattern with continuation output"
        }
    end
    
    -- Detect oversized OP_RETURN (lower confidence)
    if largest_opreturn > 80 then
        return {
            accept = false,
            score = 40,
            reason = string.format("OP_RETURN exceeds standard size (%d bytes)", largest_opreturn)
        }
    end
    
    -- No suspicious patterns
    return {
        accept = true,
        score = 0,
        reason = "No suspicious OP_RETURN patterns"
    }
end

-- Optional: Lifecycle hooks
local function on_load()
    return true
end

local function on_unload()
    return true
end

-- Export module functions
return {
    validate = validate,
    on_load = on_load,
    on_unload = on_unload
}
