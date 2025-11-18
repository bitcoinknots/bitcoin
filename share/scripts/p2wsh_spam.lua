-- P2WSH Fake Multisig Spam Detector for Bitcoin Knots
-- Uses ordiknots decode validation logic for zero false positives
-- Compatible with Bitcoin Knots PR #119 modular filter system

local ORDIKNOT_PREFIX = "444"

-- extract fake pubkeys from CHECKMULTISIG script
-- Returns: array of 33-byte pubkeys, or nil on parse error
local function extract_pubkeys_from_script(script)
    if not script or #script == 0 then
        return nil
    end

    local pubkeys = {}
    local i = 1

    -- parse script bytecode until we hit CHECKMULTISIG or OP_N
    while i <= #script do
        local opcode = string.byte(script, i)

        -- OP_CHECKMULTISIG - stop parsing
        if opcode == 0xae then
            break
        end

        -- OP_1 through OP_16 (0x51-0x60) - skip
        if opcode >= 0x51 and opcode <= 0x60 then
            i = i + 1
        -- direct push opcodes (1-75 bytes)
        elseif opcode >= 0x01 and opcode <= 0x4b then
            local push_len = opcode

            -- validate push doesn't extend beyond script
            if i + push_len > #script then
                return nil
            end

            -- only treat 33-byte pushes as pubkeys
            if push_len == 33 then
                local pubkey = string.sub(script, i + 1, i + 33)
                table.insert(pubkeys, pubkey)
            end

            i = i + 1 + push_len
        -- OP_PUSHDATA1 (0x4c)
        elseif opcode == 0x4c then
            if i + 1 > #script then
                return nil
            end
            local push_len = string.byte(script, i + 1)
            if i + 1 + push_len > #script then
                return nil
            end
            i = i + 2 + push_len
        -- OP_PUSHDATA2 (0x4d)
        elseif opcode == 0x4d then
            if i + 2 > #script then
                return nil
            end
            local push_len = string.byte(script, i + 1) + string.byte(script, i + 2) * 256
            if i + 2 + push_len > #script then
                return nil
            end
            i = i + 3 + push_len
        -- OP_PUSHDATA4 (0x4e)
        elseif opcode == 0x4e then
            if i + 4 > #script then
                return nil
            end
            i = i + 5  -- skip for now, not common
        else
            -- other opcodes - skip
            i = i + 1
        end
    end

    return pubkeys
end

-- decode fake pubkeys to extract embedded data
-- Returns: concatenated data bytes, or nil if validation fails
local function decode_fake_pubkeys(pubkeys)
    if not pubkeys or #pubkeys == 0 then
        return nil
    end

    -- skip first pubkey (real signing key)
    if #pubkeys < 2 then
        return nil
    end

    local data = {}

    -- extract 32 data bytes from each fake pubkey
    for i = 2, #pubkeys do
        local pubkey = pubkeys[i]

        -- validate pubkey length
        if #pubkey ~= 33 then
            return nil
        end

        -- validate prefix (must be 0x02 or 0x03 for compressed pubkey)
        local prefix = string.byte(pubkey, 1)
        if prefix ~= 0x02 and prefix ~= 0x03 then
            return nil
        end

        -- extract 32 data bytes (skip first prefix byte)
        local payload = string.sub(pubkey, 2, 33)
        table.insert(data, payload)
    end

    -- concatenate all data
    return table.concat(data)
end

-- strip trailing null padding from data
local function strip_trailing_nulls(data)
    if not data or #data == 0 then
        return data
    end

    local last_non_null = #data
    while last_non_null > 0 and string.byte(data, last_non_null) == 0 do
        last_non_null = last_non_null - 1
    end

    return string.sub(data, 1, last_non_null)
end

-- validate that witnessScript is ordiknots spam using full decode logic
-- Returns: true if definitely spam, false otherwise
local function validate_ordiknots_spam(witness_script)
    if not witness_script or #witness_script == 0 then
        return false
    end

    -- fast path: check for "444" anywhere in the script
    if not string.find(witness_script, ORDIKNOT_PREFIX, 1, true) then
        return false
    end

    -- check for CHECKMULTISIG opcode at the end
    local last_byte = string.byte(witness_script, #witness_script)
    if last_byte ~= 0xae then
        return false
    end

    -- extract pubkeys from script
    local pubkeys = extract_pubkeys_from_script(witness_script)
    if not pubkeys or #pubkeys < 2 then
        return false
    end

    -- decode fake pubkeys to get embedded data
    local data = decode_fake_pubkeys(pubkeys)
    if not data then
        return false
    end

    -- strip trailing null padding
    data = strip_trailing_nulls(data)

    -- validate "444" prefix at the start of decoded data
    if #data < 3 then
        return false
    end

    if string.sub(data, 1, 3) == ORDIKNOT_PREFIX then
        return true
    end

    return false
end

-- main filter function called by Bitcoin Knots
function validate(tx, ctx)
    -- get all transaction inputs
    local inputs = tx:get_inputs()

    if not inputs or #inputs == 0 then
        return {
            accept = true,
            score = 0,
            reason = "No inputs"
        }
    end

    -- only check first input (matching ordiknots detect.rs logic)
    local first_input = inputs[1]
    local witness = first_input:get_witness()

    -- witness must have at least 3 elements for P2WSH
    if not witness or #witness < 3 then
        return {
            accept = true,
            score = 0,
            reason = "No P2WSH witness data"
        }
    end

    -- extract witnessScript (last element in witness stack)
    local witness_script = witness[#witness]

    if not witness_script or #witness_script == 0 then
        return {
            accept = true,
            score = 0,
            reason = "Empty witness script"
        }
    end

    -- validate using full ordiknots decode logic
    if validate_ordiknots_spam(witness_script) then
        if ctx and ctx.log_warn then
            ctx:log_warn(string.format(
                "Ordiknots P2WSH spam detected: witnessScript decodes with '444' prefix"
            ))
        end

        return {
            accept = false,
            score = 100,
            reason = "Ordiknots P2WSH spam: witnessScript decodes with '444' prefix"
        }
    end

    -- not spam
    return {
        accept = true,
        score = 0,
        reason = "No ordiknots spam patterns detected"
    }
end

-- optional: lifecycle hooks
local function on_load()
    return true
end

local function on_unload()
    return true
end

-- export module functions
return {
    validate = validate,
    on_load = on_load,
    on_unload = on_unload
}
