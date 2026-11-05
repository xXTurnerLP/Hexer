-- HXP: a made-up binary protocol, parsed AND generated ----------------------------------------------
--
-- This is the example to copy when you reverse engineer your own protocol. It shows both
-- directions:
--   * DESERIALIZER: a parser (detect + parse) that turns bytes into a structure tree with enums,
--     labels, notes, colors and a CRC check;
--   * SERIALIZER: commands that build packets with string.pack, open them in a new tab, and patch an
--     existing packet in place (insert a record + fix the length and CRC) as ONE undo step.
--
-- Packet layout (big-endian):
--
--   off  size  field
--   0    2     magic       "HX"
--   2    1     version     1
--   3    1     msg_type    enum MSG_TYPE
--   4    2     length      u16be, number of payload bytes that follow
--   6    ...   payload     TLV records:  tag (u8, enum TAG) | len (ULEB128) | value[len]
--   6+n  2     crc         CRC-16/CCITT-FALSE over bytes [0, 6+n)
--
-- A file may contain several packets back to back (e.g. a capture dump).
--
-- Try it: run the command "HXP: build sample packet" (Ctrl+Shift+P), look at the Structure panel,
-- double-click a value to edit it, then run "HXP: append TLV record at cursor".

local MSG_TYPE = { [1] = "HELLO", [2] = "DATA", [3] = "ACK", [4] = "ERROR", [5] = "BYE" }

local TAG = {
    [0x01] = "DEVICE_ID",    -- u32be
    [0x02] = "TIMESTAMP",    -- u64be, unix seconds
    [0x03] = "TEMPERATURE",  -- i16be, tenths of a degree Celsius
    [0x04] = "NAME",         -- UTF-8 text
    [0x05] = "BLOB",         -- opaque bytes
    [0xFF] = "PADDING",
}
-- Reverse lookup (name -> tag), handy for the serializer.
local TAG_ID = {}
for id, name in pairs(TAG) do TAG_ID[name] = id end

-- Colors per tag make the hex view readable at a glance.
local TAG_COLOR = {
    DEVICE_ID = "cyan", TIMESTAMP = "purple", TEMPERATURE = "orange", NAME = "green",
    BLOB = "gray", PADDING = "gray",
}

-- ---- helpers shared by both directions ---------------------------------------------------------

-- CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). Fine for packets; use hx.crc32 for big data.
local function crc16(s)
    local crc = 0xFFFF
    for i = 1, #s do
        crc = crc ~ (s:byte(i) << 8)
        for _ = 1, 8 do
            if crc & 0x8000 ~= 0 then
                crc = ((crc << 1) ~ 0x1021) & 0xFFFF
            else
                crc = (crc << 1) & 0xFFFF
            end
        end
    end
    return crc
end

-- ULEB128 encoder (the parser side uses p:uleb).
local function uleb(n)
    local out = {}
    repeat
        local b = n & 0x7F
        n = n >> 7
        if n ~= 0 then b = b | 0x80 end
        out[#out + 1] = string.char(b)
    until n == 0
    return table.concat(out)
end

-- Reads an ULEB128 from a document; returns value, byte count (used by the patch command).
local function read_uleb(doc, off)
    local v, shift, n = 0, 0, 0
    repeat
        local b = doc:u8(off + n)
        if not b then return nil end
        v = v | ((b & 0x7F) << shift)
        shift = shift + 7
        n = n + 1
    until b < 0x80 or n == 10
    return v, n
end

-- ---- DESERIALIZER -----------------------------------------------------------------------------------

-- Decodes one record's value according to its tag. `len` is the value length.
local function parse_value(p, tag_name, len)
    local start = p:tell()
    if tag_name == "DEVICE_ID" and len == 4 then
        p:u32("device_id", { fmt = "hex" })
    elseif tag_name == "TIMESTAMP" and len == 8 then
        local t = p:u64("unix_time")
        local ok, text = pcall(os.date, "!%Y-%m-%d %H:%M:%S UTC", t)  -- os.date rejects absurd values
        if ok then p:note(text) end
    elseif tag_name == "TEMPERATURE" and len == 2 then
        local t = p:i16("celsius_x10")
        p:note(string.format("%.1f \u{00B0}C", t / 10))
    elseif tag_name == "NAME" then
        p:str("name", len)
    else
        p:bytes("value", len)
    end
    p:seek(start + len)  -- whatever happened above, continue right after the value
end

local function parse_packet(p)
    p:str("magic", 2, { color = "gray" })
    local version = p:u8("version")
    if version ~= 1 then p:note("unknown version, expected 1") end
    local msg = p:u8("msg_type", { enum = MSG_TYPE, color = "yellow" })
    local length = p:u16("length", { comment = "payload bytes" })
    local payload_start = p:tell()

    if length + 2 > p:remaining() then   -- payload + CRC must fit
        p:bytes("payload (truncated)", p:remaining(), { color = "red" })
        p:note("length says " .. length .. " payload bytes + 2 CRC bytes")
        return
    end

    -- TLV records until the declared payload length is used up.
    local count = 0
    p:struct("payload", function()
        while p:tell() < payload_start + length do
            p:struct(string.format("record[%d]", count), function()
                local tag = p:u8("tag", { enum = TAG })
                local name = TAG[tag] or string.format("0x%02X", tag)
                local len = p:uleb("len")
                if len < 0 or p:tell() + len > payload_start + length then   -- (huge ULEB values wrap negative)
                    p:note("record overruns the payload")
                    len = math.max(0, payload_start + length - p:tell())
                end
                parse_value(p, name, len)
                p:label(name)
            end, { color = TAG_COLOR[TAG[p:peek("B")]] })   -- peek: look at the tag before reading it
            count = count + 1
        end
    end)

    local wanted = p:u16("crc", { fmt = "hex" })
    return msg, length, wanted
end

hx.parser {
    name = "HXP packet",
    extensions = { "hxp" },

    detect = function(doc)
        return doc:read(0, 2) == "HX" and doc:u8(2) == 1
    end,

    parse = function(p, doc)
        p:endian("be")
        local index = 0
        -- Several packets back to back; stop at anything that is not a packet header.
        while p:remaining() >= 8 and p:peek("c2") == "HX" do
            local start = p:tell()
            p:struct(string.format("packet[%d]", index), function()
                local msg, length, wanted = parse_packet(p)
                if wanted then
                    local actual = crc16(doc:read(start, 6 + length))
                    p:note(actual == wanted and "CRC OK" or string.format("CRC MISMATCH: computed 0x%04X", actual))
                end
                p:label(MSG_TYPE[msg] or "?")
            end)
            index = index + 1
        end
        if p:remaining() > 0 then p:bytes("unparsed", p:remaining(), { color = "red" }) end
    end,
}

-- ---- SERIALIZER ---------------------------------------------------------------------------------------

-- One TLV record as bytes.
local function record(tag_name, value)
    return string.pack("B", TAG_ID[tag_name]) .. uleb(#value) .. value
end

-- A full packet: header + payload + CRC. string.pack does the byte layout:
--   ">"  big-endian,  "c2" 2 raw chars,  "B" u8,  "I2" u16
local function build_packet(msg_name, records)
    local payload = table.concat(records)
    assert(#payload <= 0xFFFF, "payload too large for a u16 length")
    local msg_id
    for id, name in pairs(MSG_TYPE) do if name == msg_name then msg_id = id end end
    local body = string.pack(">c2BBI2", "HX", 1, msg_id, #payload) .. payload
    return body .. string.pack(">I2", crc16(body))
end

hx.command {
    name = "HXP: build sample packet",
    description = "Serialize a HELLO and a DATA packet with string.pack and open them in a new tab",
    run = function()
        local hello = build_packet("HELLO", {
            record("DEVICE_ID", string.pack(">I4", 0xC0FFEE42)),
            record("NAME", "sensor-7"),
        })
        local data = build_packet("DATA", {
            record("TIMESTAMP", string.pack(">I8", 1767225600)),   -- 2026-01-01 00:00:00 UTC
            record("TEMPERATURE", string.pack(">i2", 235)),        -- 23.5 degrees
            record("BLOB", "\xDE\xAD\xBE\xEF"),
        })
        local doc = hx.new_doc("sample.hxp", hello .. data)
        print(string.format("Built %d bytes (HELLO %d + DATA %d) in %s", #hello + #data, #hello, #data, doc:name()))
    end,
}

-- Finds the packet containing `off`: returns its start and payload length (or nil).
local function packet_at(doc, off)
    local pos = 0
    while pos + 8 <= doc:size() and doc:read(pos, 2) == "HX" do
        local len = doc:u16be(pos + 4)
        local total = 6 + len + 2
        if off < pos + total then return pos, len end
        pos = pos + total
    end
    return nil
end

-- Text of the record appended by the command below. Change it from the console, e.g.
--   hxp_record_text = "kitchen"
hxp_record_text = hxp_record_text or "added by hexer"

hx.command {
    name = "HXP: append TLV record at cursor",
    description = "Insert a NAME record at the record boundary at/after the cursor, fix length + CRC",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        local pkt, len = packet_at(doc, doc:cursor())
        if not pkt then return hx.warn("cursor is not inside an HXP packet") end

        -- Walk the records to find the boundary at or after the cursor.
        local payload, stop = pkt + 6, pkt + 6 + len
        local at = payload
        while at < stop and at < doc:cursor() do
            local vlen, n = read_uleb(doc, at + 1)
            if not vlen then break end
            at = at + 1 + n + vlen
        end
        at = math.min(at, stop)

        local rec = record("NAME", hxp_record_text)
        if len + #rec > 0xFFFF then return hx.error("packet would exceed 65535 payload bytes") end

        -- All three edits become ONE undo step (Ctrl+Z reverts the whole patch). A command already is
        -- one step ("Script: <name>"); outside commands, doc:transaction(fn, "label") names the step.
        doc:transaction(function()
            doc:insert(at, rec)
            local new_len = len + #rec
            doc:write(pkt + 4, string.pack(">I2", new_len))
            doc:write(pkt + 6 + new_len, string.pack(">I2", crc16(doc:read(pkt, 6 + new_len))))
        end)
        doc:select(at, #rec)
        print(string.format("Inserted %d-byte NAME record at 0x%X; packet at 0x%X now has %d payload bytes",
            #rec, at, pkt, len + #rec))
    end,
}

-- ---- console output -----------------------------------------------------------------------------------

hx.command {
    name = "HXP: print packet summary",
    description = "Print every packet in the document to the console",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        local pos, n = 0, 0
        while pos + 8 <= doc:size() and doc:read(pos, 2) == "HX" do
            local msg, len = doc:u8(pos + 3), doc:u16be(pos + 4)
            local crc_ok = doc:u16be(pos + 6 + len) == crc16(doc:read(pos, 6 + len))
            local tags = {}
            local at = pos + 6
            while at < pos + 6 + len do
                local vlen, k = read_uleb(doc, at + 1)
                if not vlen then break end
                tags[#tags + 1] = TAG[doc:u8(at)] or "?"
                at = at + 1 + k + vlen
            end
            hx.log(string.format("#%d @0x%06X  %-5s  %3d bytes  CRC %s  [%s]", n, pos, MSG_TYPE[msg] or "?",
                len, crc_ok and "ok" or "BAD", table.concat(tags, ", ")))
            pos, n = pos + 8 + len, n + 1
        end
        if n == 0 then hx.warn("no HXP packets at offset 0") else print(n .. " packet(s)") end
    end,
}
