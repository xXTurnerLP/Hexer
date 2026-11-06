-- Custom hash algorithms ------------------------------------------------------------------------------
--
-- hx.hash_algorithm registers a checksum / hash next to the 16 built-ins: it shows up in the Hashes
-- panel (Algorithms...), in hx.hash(name, bytes), doc:hash(name, off, len) and hx.hash_algorithms().
--   init()               -> the state of one run (any Lua value: a table, an integer...)
--   update(state, bytes) -> the new state, or nothing when the state table was changed in place;
--                           called with the data in order, in chunks of up to 4 MiB
--   final(state)         -> the digest as a hex string (string.format("%08x", v) for an integer)
-- The Hashes panel runs it on a worker thread in a Lua state that loaded only this file, so keep the
-- file's top level cheap and self-contained (no globals of other scripts; print output is dropped
-- there). Plain Lua manages roughly 10-50 MB/s, so large files take a while (progress + Cancel).

-- Adler-32 (zlib / RFC 1950): gives the same value as the built-in "Adler-32", so it doubles as a
-- check of the mechanism and a template for your own.
local MOD = 65521
local SLICE = 4096  -- bytes per string.byte call; a and b stay far below 2^63 within a slice

hx.hash_algorithm {
    name = "Adler-32 (Lua)",
    init = function() return { a = 1, b = 0 } end,
    update = function(s, bytes)
        local a, b = s.a, s.b
        local n = #bytes
        for i = 1, n, SLICE do
            local t = { string.byte(bytes, i, math.min(i + SLICE - 1, n)) }
            for k = 1, #t do
                a = a + t[k]
                b = b + a
            end
            a, b = a % MOD, b % MOD
        end
        s.a, s.b = a, b  -- changed in place: no return value needed
    end,
    final = function(s) return string.format("%08x", (s.b << 16) | s.a) end,
}
