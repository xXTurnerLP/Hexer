-- Handy commands --------------------------------------------------------------------------------------
--
-- Commands appear in the command palette (Ctrl+Shift+P) and the Scripts menu. `run(doc)` gets the
-- active document (or nil). Everything a command edits is ONE undo step (Ctrl+Z reverts it all).
-- hx.prompt(title, default, { hint = ... }) asks the user for a line of text (nil = cancelled).

-- Last XOR key entered (the prompt's default next time; survives until the scripts are reloaded).
hx_xor_key = hx_xor_key or "FF"

-- Byte-by-byte work in Lua runs at a few MB/s and commands run on the UI thread (10 s limit), so
-- these commands cap how much they touch (XOR works on 8-byte words, so it can do more).
local MAX_XOR = 256 * 1024 * 1024
local MAX_XOR_KEY = 4096
local MAX_SUM = 16 * 1024 * 1024
local CHUNK = 64 * 1024

-- Returns start, len of the selection, or nil after telling the user why.
local function selection(doc, max)
    if not doc then
        hx.warn("no document")
        return nil
    end
    local start, len = doc:selection()
    if len == 0 then
        hx.warn("select some bytes first")
        return nil
    end
    if max and len > max then
        hx.warn(string.format("selection is %d bytes; this command handles at most %d", len, max))
        return nil
    end
    return start, len
end

-- "FF", "DE AD BE EF", "0x12,0x34" (anything paste accepts) or a quoted text key: "secret".
-- Returns the key bytes, or nil and why not.
local function parse_key(text)
    text = text:match("^%s*(.-)%s*$")
    local key = text:match('^"(.*)"$') or text:match("^'(.*)'$")
    if not key then
        local ok, bytes = pcall(hx.unhex, text)
        if not ok then return nil, "not hex bytes or a quoted text: " .. text end
        key = bytes
    end
    if #key == 0 then return nil, "the key is empty" end
    if #key > MAX_XOR_KEY then return nil, string.format("the key is longer than %d bytes", MAX_XOR_KEY) end
    return key
end

-- XORs [start, start+len) with `key` repeated from the first byte, 8 bytes per Lua operation.
local function xor_range(doc, start, len, key)
    local k = #key
    local a, b = k, 8
    while b ~= 0 do a, b = b, a % b end
    local period = k * 8 // a                         -- the key stream repeats every lcm(k, 8) bytes
    local stream = key:rep(period // k)
    local nw = period // 8
    local words = { string.unpack("<" .. string.rep("i8", nw), stream) }
    local chunk = period * math.max(1, CHUNK // period)   -- whole periods: each chunk starts at key[1]
    for off = 0, len - 1, chunk do
        local data = doc:read(start + off, math.min(chunk, len - off))
        local n = #data // 8
        local fmt = "<" .. string.rep("i8", n)
        local v = { string.unpack(fmt, data) }
        for i = 1, n do v[i] = v[i] ~ words[(i - 1) % nw + 1] end
        local tail = {}
        for i = n * 8 + 1, #data do
            tail[#tail + 1] = string.char(data:byte(i) ~ stream:byte((i - 1) % period + 1))
        end
        doc:write(start + off, string.pack(fmt, table.unpack(v, 1, n)) .. table.concat(tail))
    end
end

hx.command {
    name = "Selection: XOR with key",
    description = "XOR the selected bytes with a key you enter (hex bytes or \"text\", repeated)",
    run = function(doc)
        local start, len = selection(doc, MAX_XOR)
        if not start then return end
        local default = type(hx_xor_key) == "number" and string.format("%02X", hx_xor_key & 0xFF)
                        or tostring(hx_xor_key)
        local text = hx.prompt(string.format("XOR %d selected bytes with key", len), default, {
            hint = 'Hex bytes: FF  or  DE AD BE EF  or  0x12,0x34\nText in quotes: "secret"\n'
                .. "The key repeats over the selection.",
        })
        if not text then return end                  -- cancelled
        local key, why = parse_key(text)
        if not key then return hx.error("XOR: " .. why) end
        hx_xor_key = text
        doc:transaction(function() xor_range(doc, start, len, key) end, "XOR selection")
        print(string.format("XORed %d bytes at 0x%X with %s", len, start,
            #key <= 16 and hx.hex(key) or string.format("a %d-byte key", #key)))
    end,
}

hx.command {
    name = "Selection: print as C array",
    description = "Print the selected bytes (max 64 KiB) as a C array to the console",
    run = function(doc)
        local start, len = selection(doc, 64 * 1024)
        if not start then return end
        local data = doc:read(start, len)
        local lines = { string.format("// %s @ 0x%X, %d bytes", doc:name(), start, len),
                        string.format("const unsigned char data[%d] = {", len) }
        for i = 1, #data, 16 do
            local row = {}
            for j = i, math.min(i + 15, #data) do row[#row + 1] = string.format("0x%02X", data:byte(j)) end
            lines[#lines + 1] = "    " .. table.concat(row, ", ") .. (i + 15 < #data and "," or "")
        end
        lines[#lines + 1] = "};"
        print(table.concat(lines, "\n"))
    end,
}

hx.command {
    name = "Selection: checksum (sum8/xor8/crc32)",
    description = "Print 8-bit sum, 8-bit XOR and CRC-32 of the selection (or of the whole file if small)",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        local start, len = doc:selection()
        if len == 0 then start, len = 0, doc:size() end   -- no selection: whole document
        if len > MAX_SUM then
            return hx.warn(string.format("%d bytes is too much for a Lua checksum; select at most %d", len, MAX_SUM))
        end
        local sum, x, crc = 0, 0, 0
        for off = 0, len - 1, CHUNK do
            local data = doc:read(start + off, math.min(CHUNK, len - off))
            crc = hx.crc32(data, crc)    -- native, continues over chunks
            for i = 1, #data do
                local b = data:byte(i)
                sum = sum + b
                x = x ~ b
            end
        end
        print(string.format("[0x%X +%d]  sum8 = 0x%02X   xor8 = 0x%02X   crc32 = 0x%08X   (sum = %d)",
            start, len, sum & 0xFF, x, crc, sum))
    end,
}

hx.command {
    name = "Selection: disassemble to console",
    description = "Print the selected bytes as x86-64 instructions (addresses from the PE / ELF headers)",
    run = function(doc)
        local start, len = selection(doc, 64 * 1024)
        if not start then return end
        local stop, lines = start + len, 0
        while start < stop and lines < 10000 do
            local list = doc:disasm(start, math.min(1000, stop - start))   -- at most 1 per byte
            if #list == 0 then break end
            for _, i in ipairs(list) do
                if i.offset >= stop then break end
                print(string.format("%010X  %-30s %s", i.address, hx.hex(i.bytes), i.text))
                start, lines = i.offset + i.length, lines + 1
            end
        end
    end,
}

hx.command {
    name = "Highlight: all NUL runs >= 16 bytes in view range",
    description = "Mark runs of 16+ zero bytes in the selection, or else in the 1 MiB starting at the cursor",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        local start, len = doc:selection()
        if len == 0 then start, len = doc:cursor(), 1024 * 1024 end
        len = math.min(len, 64 * 1024 * 1024, doc:size() - start)   -- bounded scan
        local data = doc:read(start, len)
        local pattern = string.rep("\0", 16) .. "\0*"   -- 16 NULs, then any further NULs
        local found, pos = 0, 1
        while found < 5000 do
            local a, b = data:find(pattern, pos)
            if not a then break end
            hx.highlight(doc, start + a - 1, b - a + 1, "blue", string.format("NUL run, %d bytes", b - a + 1))
            found, pos = found + 1, b + 1
        end
        print(string.format("%d NUL run(s) in [0x%X, 0x%X)%s", found, start, start + len,
            found == 5000 and " (stopped at 5000)" or ""))
    end,
}

hx.command {
    name = "Highlight: clear script highlights",
    description = "Remove all ranges marked by scripts (hx.highlight) in this document",
    run = function(doc)
        if doc then hx.clear_highlights(doc) end
    end,
}
