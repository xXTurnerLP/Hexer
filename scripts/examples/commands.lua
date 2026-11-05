-- Handy commands --------------------------------------------------------------------------------------
--
-- Commands appear in the command palette (Ctrl+Shift+P) and the Scripts menu. `run(doc)` gets the
-- active document (or nil). Everything a command edits is ONE undo step (Ctrl+Z reverts it all).
--
-- Commands cannot prompt for input; settings are plain globals you change from the console, e.g.
--   hx_xor_key = 0x5A            -- single-byte key
--   hx_xor_key = "secret"        -- multi-byte key, applied cyclically
-- (Globals survive until the scripts are reloaded; put them in your own user script to keep them.)

hx_xor_key = hx_xor_key or 0xFF

-- Byte-by-byte work in Lua runs at a few MB/s and commands run on the UI thread (10 s limit), so
-- these commands cap how much they touch.
local MAX_XOR = 4 * 1024 * 1024
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

hx.command {
    name = "Selection: XOR with key",
    description = "XOR the selected bytes with hx_xor_key (number 0-255 or a string key)",
    run = function(doc)
        local start, len = selection(doc, MAX_XOR)
        if not start then return end
        local key = hx_xor_key
        if type(key) == "number" then key = string.char(key & 0xFF) end
        if type(key) ~= "string" or #key == 0 then return hx.error("hx_xor_key must be a number or a non-empty string") end

        local klen = #key
        local kbytes = { key:byte(1, -1) }
        for off = 0, len - 1, CHUNK do
            local data = doc:read(start + off, math.min(CHUNK, len - off))
            local out = {}
            for i = 1, #data do
                -- (off + i - 1) is the position inside the selection -> key index
                out[i] = string.char(data:byte(i) ~ kbytes[(off + i - 1) % klen + 1])
            end
            doc:write(start + off, table.concat(out))
        end
        print(string.format("XORed %d bytes at 0x%X with %s", len, start,
            klen == 1 and string.format("0x%02X", kbytes[1]) or hx.inspect(key)))
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
