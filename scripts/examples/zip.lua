-- ZIP archive parser ----------------------------------------------------------------------------------
--
-- Walks the archive front to back: local file headers (+ file data), data descriptors, central
-- directory entries and the end-of-central-directory record. All integers are little-endian.
-- Reference: PKWARE APPNOTE.TXT, section 4.3.
--
-- Techniques shown here: dispatch on a peeked signature, bit flags with fmt="bin", decoding packed
-- DOS date/time into a note, doc:find to resynchronise when sizes are unknown, ZIP64 extra
-- fields (64-bit sizes) and end records.

local SIG = {
    LOCAL   = 0x04034b50,  -- "PK\3\4"
    CENTRAL = 0x02014b50,  -- "PK\1\2"
    EOCD    = 0x06054b50,  -- "PK\5\6"
    DESC    = 0x08074b50,  -- "PK\7\8"
    EOCD64  = 0x06064b50,
    LOC64   = 0x07064b50,
}

local METHOD = {
    [0] = "stored", [1] = "shrunk", [6] = "imploded", [8] = "deflate", [9] = "deflate64",
    [12] = "bzip2", [14] = "LZMA", [93] = "zstd", [95] = "xz", [98] = "PPMd", [99] = "AES encrypted",
}

local HOST_OS = { [0] = "MS-DOS/FAT", [3] = "Unix", [7] = "Macintosh", [10] = "NTFS", [19] = "OS X" }

-- DOS time/date (two u16) -> "2024-05-17 13:45:10"
local function dos_datetime(t, d)
    return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2)
end

-- Extra field header ids (APPNOTE 4.5 / 4.6).
local EXTRA_ID = {
    [0x0001] = "ZIP64", [0x000a] = "NTFS times", [0x5455] = "extended timestamp",
    [0x7875] = "Unix UID/GID", [0x9901] = "AES encryption",
}

local U32_MAX = 0xFFFFFFFF   -- a 32-bit size/offset of 0xFFFFFFFF means "the real value is in ZIP64 extra"

-- Fields shared by local and central headers. Returns the values the caller needs.
local function common_header(p)
    local flags = p:u16("flags", { fmt = "bin" })
    local notes = {}
    if flags & 0x0001 ~= 0 then notes[#notes + 1] = "encrypted" end
    if flags & 0x0008 ~= 0 then notes[#notes + 1] = "sizes in data descriptor" end
    if flags & 0x0800 ~= 0 then notes[#notes + 1] = "UTF-8 names" end
    if #notes > 0 then p:note(table.concat(notes, ", ")) end
    p:u16("method", { enum = METHOD })
    local t = p:u16("mod_time", { fmt = "hex" })
    local d = p:u16("mod_date", { fmt = "hex" })
    p:note(dos_datetime(t, d))
    p:u32("crc32", { fmt = "hex" })
    local csize = p:u32("compressed_size")
    local usize = p:u32("uncompressed_size")
    return flags, csize, usize
end

-- Extra field: a list of (id u16, size u16, data) records. `zip64` lists, in order, the 64-bit
-- values a ZIP64 record (id 1) carries for this header. Returns a table of the decoded values.
local function extra_field(p, len, zip64)
    local stop = p:tell() + len
    local values = {}
    p:struct("extra", function()
        local i = 0
        while stop - p:tell() >= 4 do
            p:struct(string.format("record[%d]", i), function()
                local id = p:u16("id", { enum = EXTRA_ID })
                local size = math.min(p:u16("size"), stop - p:tell())
                local body_end = p:tell() + size
                if id == 0x0001 then
                    for _, key in ipairs(zip64) do
                        if p:tell() + 8 > body_end then break end
                        values[key] = p:u64(key)
                    end
                end
                if p:tell() < body_end then p:bytes("data", body_end - p:tell()) end
                p:label(EXTRA_ID[id] or string.format("0x%04X", id))
            end)
            i = i + 1
        end
        if p:tell() < stop then p:bytes("padding", stop - p:tell()) end
    end)
    return values
end

local function local_file(p, doc)
    p:u32("signature", { fmt = "hex", color = "gray" })
    p:u16("version_needed")
    local flags, csize, usize = common_header(p)
    local name_len = p:u16("name_length")
    local extra_len = p:u16("extra_length")
    local name = p:str("name", name_len, { color = "green" })
    p:label(name)
    local zip64 = false
    if extra_len > 0 then
        -- A local header's ZIP64 record holds both sizes when either 32-bit field overflowed.
        local want = (csize == U32_MAX or usize == U32_MAX) and { "uncompressed_size", "compressed_size" } or {}
        local z = extra_field(p, extra_len, want)
        if z.compressed_size then csize, zip64 = z.compressed_size, true end
    end

    if flags & 0x0008 ~= 0 and csize == 0 then
        -- Streamed entry: the size is only known after the data. Find the next header instead.
        local here = p:base() + p:tell()   -- doc:find works on absolute offsets
        local next_hdr = doc:find("PK\7\8", here) or doc:find("PK\3\4", here) or doc:find("PK\1\2", here)
        if not next_hdr then return zip64 end
        csize = next_hdr - here
    end
    if csize < 0 or csize > p:remaining() then   -- (u64 values >= 2^63 are negative in Lua)
        p:bytes("data (truncated)", p:remaining(), { color = "red" })
        return zip64
    end
    if csize > 0 then p:bytes("data", csize, { color = "blue" }) end
    return zip64
end

local function central_entry(p)
    p:u32("signature", { fmt = "hex", color = "gray" })
    p:u8("version_made_by")
    p:u8("host_os", { enum = HOST_OS })
    p:u16("version_needed")
    local _, csize, usize = common_header(p)
    local name_len = p:u16("name_length")
    local extra_len = p:u16("extra_length")
    local comment_len = p:u16("comment_length")
    p:u16("disk_start")
    p:u16("internal_attrs", { fmt = "hex" })
    p:u32("external_attrs", { fmt = "hex" })
    local offset = p:u32("local_header_offset", { fmt = "hex" })
    local name = p:str("name", name_len, { color = "green" })
    if extra_len > 0 then
        -- Here the ZIP64 record holds only the fields that overflowed, in this order.
        local want = {}
        if usize == U32_MAX then want[#want + 1] = "uncompressed_size" end
        if csize == U32_MAX then want[#want + 1] = "compressed_size" end
        if offset == U32_MAX then want[#want + 1] = "local_header_offset" end
        extra_field(p, extra_len, want)
    end
    if comment_len > 0 then p:str("comment", comment_len) end
    p:label(name)
end

local function eocd(p)
    p:u32("signature", { fmt = "hex", color = "gray" })
    p:u16("disk_number")
    p:u16("cd_disk")
    p:u16("entries_on_disk")
    local total = p:u16("entries_total")
    p:u32("cd_size")
    p:u32("cd_offset", { fmt = "hex" })
    local clen = p:u16("comment_length")
    if clen > 0 then p:str("comment", math.min(clen, p:remaining())) end
    p:label(total == 0xFFFF and "entries in ZIP64 record" or total .. " entries")
end

local function eocd64(p)
    local start = p:tell()
    p:u32("signature", { fmt = "hex", color = "gray" })
    local size = p:u64("record_size", { comment = "bytes after this field" })
    p:u8("version_made_by")
    p:u8("host_os", { enum = HOST_OS })
    p:u16("version_needed")
    p:u32("disk_number")
    p:u32("cd_disk")
    p:u64("entries_on_disk")
    local total = p:u64("entries_total")
    p:u64("cd_size")
    p:u64("cd_offset", { fmt = "hex" })
    local stop = start + 12 + size
    if size >= 0 and stop > p:tell() then
        p:bytes("extensible_data", math.min(stop - p:tell(), p:remaining()))
    end
    p:label(total .. " entries")
end

local function eocd64_locator(p)
    p:u32("signature", { fmt = "hex", color = "gray" })
    p:u32("eocd64_disk")
    p:u64("eocd64_offset", { fmt = "hex" })
    p:u32("total_disks")
end

hx.parser {
    name = "ZIP archive",
    extensions = { "zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "epub", "whl", "nupkg" },

    detect = function(doc)
        local magic = doc:read(0, 4)
        return magic == "PK\3\4" or magic == "PK\5\6"
    end,

    parse = function(p, doc)
        p:endian("le")
        local files, entries = 0, 0
        local zip64 = false   -- last local entry used ZIP64: its data descriptor has 64-bit sizes
        while p:remaining() >= 4 do
            local sig = p:peek("<I4")
            if sig == SIG.LOCAL and p:remaining() >= 30 then
                p:struct(string.format("file[%d]", files), function() zip64 = local_file(p, doc) end)
                files = files + 1
            elseif sig == SIG.DESC and p:remaining() >= (zip64 and 24 or 16) then
                p:struct("data_descriptor", function()
                    p:u32("signature", { fmt = "hex", color = "gray" })
                    p:u32("crc32", { fmt = "hex" })
                    if zip64 then
                        p:u64("compressed_size")
                        p:u64("uncompressed_size")
                    else
                        p:u32("compressed_size")
                        p:u32("uncompressed_size")
                    end
                end)
            elseif sig == SIG.CENTRAL and p:remaining() >= 46 then
                p:struct(string.format("central[%d]", entries), function() central_entry(p) end)
                entries = entries + 1
            elseif sig == SIG.EOCD and p:remaining() >= 22 then
                p:struct("end_of_central_directory", function() eocd(p) end, { color = "purple" })
            elseif sig == SIG.EOCD64 and p:remaining() >= 56 then
                p:struct("zip64_end_of_central_directory", function() eocd64(p) end, { color = "purple" })
            elseif sig == SIG.LOC64 and p:remaining() >= 20 then
                p:struct("zip64_eocd_locator", function() eocd64_locator(p) end, { color = "purple" })
            else
                p:bytes("unknown", p:remaining(), { color = "red", comment = "no ZIP record here" })
            end
        end
        if p:remaining() > 0 then p:bytes("unknown", p:remaining(), { color = "red" }) end
    end,
}
