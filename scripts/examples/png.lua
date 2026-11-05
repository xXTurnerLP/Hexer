-- PNG image parser ---------------------------------------------------------------------------------
--
-- Shows the basics of a Hexer parser:
--   * `detect(doc)` decides whether the parser applies (cheap check of the magic bytes);
--   * `parse(p, doc)` walks the file with the parser context `p`. Every typed reader
--     (p:u32, p:str, p:bytes, ...) reads at p:tell(), advances, adds a field to the Structure
--     panel + a colored range in the hex view, and RETURNS the value so the script can branch on it.
--   * Numeric fields are editable in the Structure panel (double-click the value). Enum fields accept
--     the name ("Indexed") or a number.
--
-- Format reference: https://www.w3.org/TR/png/  (all integers are big-endian)
-- Layout:  8-byte signature, then chunks:  u32 length | 4-char type | data[length] | u32 CRC
--          (the CRC covers type + data).

local SIGNATURE = "\x89PNG\r\n\x1a\n"

-- Enums: value -> name. The tree shows "3 = Indexed (palette)".
local COLOR_TYPE = {
    [0] = "Grayscale", [2] = "Truecolor (RGB)", [3] = "Indexed (palette)",
    [4] = "Grayscale + alpha", [6] = "Truecolor + alpha (RGBA)",
}
local COMPRESSION = { [0] = "deflate" }
local FILTER      = { [0] = "adaptive" }
local INTERLACE   = { [0] = "none", [1] = "Adam7" }
local UNIT        = { [0] = "unknown", [1] = "meter" }

-- Short descriptions, shown as a note on the chunk's type field.
local CHUNK_INFO = {
    IHDR = "image header", PLTE = "palette", IDAT = "image data (zlib stream)", IEND = "end marker",
    tRNS = "transparency", gAMA = "gamma", cHRM = "chromaticities", sRGB = "sRGB intent",
    iCCP = "ICC profile", tEXt = "Latin-1 text", zTXt = "compressed text", iTXt = "UTF-8 text",
    bKGD = "background color", pHYs = "pixel dimensions", tIME = "last modification",
    eXIf = "Exif metadata", acTL = "APNG animation control", fcTL = "APNG frame control",
    fdAT = "APNG frame data",
}

-- Chunk bodies we decode field by field. Each gets the chunk's data length.
local BODY = {}
-- Fixed body sizes: a chunk with any other length is shown as raw bytes (damaged or unknown version).
local BODY_SIZE = { IHDR = 13, pHYs = 9, tIME = 7, gAMA = 4 }

function BODY.IHDR(p)
    p:u32("width")
    p:u32("height")
    p:u8("bit_depth")
    p:u8("color_type", { enum = COLOR_TYPE })
    p:u8("compression", { enum = COMPRESSION })
    p:u8("filter", { enum = FILTER })
    p:u8("interlace", { enum = INTERLACE })
end

function BODY.PLTE(p, len)
    -- One struct per palette entry, named entries[0], entries[1], ...
    -- p:peek reads without emitting a field, so each entry can be tinted with its own color.
    p:array("entries", len // 3, function()
        local r, g, b = p:peek("BBB")
        local rgb = string.format("#%02x%02x%02x", r, g, b)
        p:struct("rgb", function()
            p:u8("r", { fmt = "hex" })
            p:u8("g", { fmt = "hex" })
            p:u8("b", { fmt = "hex" })
            p:label(rgb)
        end, { color = rgb })   -- a struct's color is inherited by its fields
    end)
end

function BODY.pHYs(p)
    p:u32("pixels_per_unit_x")
    p:u32("pixels_per_unit_y")
    p:u8("unit", { enum = UNIT })
end

function BODY.tIME(p)
    local y = p:u16("year")
    local mo, d = p:u8("month"), p:u8("day")
    local h, mi, s = p:u8("hour"), p:u8("minute"), p:u8("second")
    p:label(string.format("%04d-%02d-%02d %02d:%02d:%02d UTC", y, mo, d, h, mi, s))
end

function BODY.gAMA(p)
    local g = p:u32("gamma_x100000")
    p:note(string.format("gamma = %.5f", g / 100000))
end

function BODY.tEXt(p, len)
    -- keyword (1-79 bytes), NUL, text. Check the NUL is inside the chunk before trusting p:cstr.
    if not p:peekbytes(math.min(len, 80)):find("\0", 1, true) then
        p:str("text", len)
        p:note("no NUL after the keyword")
        return
    end
    local start = p:tell()
    local key = p:cstr("keyword")
    local text = p:str("text", len - (p:tell() - start))
    p:label(key .. ": " .. text:sub(1, 40))
end

hx.parser {
    name = "PNG image",
    extensions = { "png", "apng" },

    detect = function(doc)
        return doc:read(0, 8) == SIGNATURE
    end,

    parse = function(p, doc)
        p:endian("be")
        p:bytes("signature", 8, { color = "gray", comment = "\\x89 P N G \\r \\n \\x1a \\n" })

        local index = 0
        while p:remaining() >= 12 do
            local done = false
            p:struct(string.format("chunk[%d]", index), function()
                local len = p:u32("length")
                local ctype = p:str("type", 4)
                p:label(string.format("%s  (%d bytes)", ctype, len))
                if CHUNK_INFO[ctype] then p:note(CHUNK_INFO[ctype]) end

                if len + 4 > p:remaining() then
                    -- Damaged/truncated file: show what is there instead of failing the parse.
                    p:bytes("data (truncated)", p:remaining(), { color = "red" })
                    p:note("length field points past the end of the file")
                    done = true
                    return
                end

                local data_start = p:tell()
                if BODY[ctype] and len > 0 and (BODY_SIZE[ctype] or len) == len then
                    p:struct("data", function() BODY[ctype](p, len) end)
                    p:seek(data_start + len)   -- never trust a body decoder to consume exactly len
                elseif len > 0 then
                    p:bytes("data", len)
                end

                local crc = p:u32("crc", { fmt = "hex" })
                -- Verify the CRC for chunks of reasonable size (doc:read is cheap; hx.crc32 is native).
                if len <= 16 * 1024 * 1024 then
                    local actual = hx.crc32(doc:read(p:base() + data_start - 4, len + 4))  -- doc:* is absolute
                    if actual == crc then
                        p:note("CRC OK")
                    else
                        p:note(string.format("CRC MISMATCH: computed 0x%08X", actual))
                    end
                end
                done = (ctype == "IEND")
            end)
            index = index + 1
            if done then break end
        end

        if p:remaining() > 0 then
            p:bytes("trailing data", p:remaining(), { color = "red", comment = "bytes after IEND" })
        end
    end,
}
