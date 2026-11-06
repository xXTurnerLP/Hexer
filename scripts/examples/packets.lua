-- Packet captures from Lua -------------------------------------------------------------------------
--
-- doc:packets{ filter = "...", first = 1, max = 10000 } lists the packets of a pcap / pcapng capture
-- (the Packets panel's index and dissector), optionally only those matching a filter expression
-- (the Packets panel's language: "tcp.port == 80 and not ip.src == 10.0.0.0/8", "udp", ...).
-- It returns the list and the number of the packet to continue at (nil at the end), so a big
-- capture is read in pages; on a document that is not a capture it returns nil and a message.

-- Packets per protocol and the busiest senders (at most `limit` packets looked at).
local function protocol_summary(doc, limit)
    local protos, senders, total = {}, {}, 0
    local first = 1
    while first and total < limit do
        local list, next_first = doc:packets{ first = first, max = math.min(10000, limit - total) }
        if not list then
            hx.warn(next_first)  -- the error message
            return
        end
        for _, p in ipairs(list) do
            protos[p.proto] = (protos[p.proto] or 0) + 1
            if p.src ~= "" then senders[p.src] = (senders[p.src] or 0) + 1 end
        end
        total = total + #list
        first = next_first
    end
    local function sorted(t)
        local out = {}
        for k, n in pairs(t) do out[#out + 1] = { k, n } end
        table.sort(out, function(a, b) return a[2] > b[2] or (a[2] == b[2] and a[1] < b[1]) end)
        return out
    end
    print(string.format("%d packets%s", total, first and " (stopped early)" or ""))
    for _, e in ipairs(sorted(protos)) do print(string.format("  %-10s %d", e[1], e[2])) end
    print("busiest senders:")
    local s = sorted(senders)
    for i = 1, math.min(5, #s) do print(string.format("  %-30s %d", s[i][1], s[i][2])) end
    return total
end

hx.command {
    name = "Capture: Protocol Summary",
    description = "Count the packets of a pcap / pcapng capture per protocol and sender",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        protocol_summary(doc, 1000000)
    end,
}

-- One bookmark per matching packet's payload (e.g. "udp.port == 53" or "tcp.flags.syn").
hx.command {
    name = "Capture: Bookmark Matching Packets...",
    description = "Ask for a packet filter and bookmark the payload of every packet that matches",
    run = function(doc)
        if not doc then return hx.warn("no document") end
        local filter = hx.prompt("Packet filter", "tcp.port == 80", { hint = "same language as the Packets panel" })
        if not filter then return end
        -- A bad filter raises an error ("doc:packets: filter: ... (column 5)"): show it as a warning.
        local ok, list, more = pcall(doc.packets, doc, { filter = filter, max = 1000 })
        if not ok then return hx.warn(list) end
        if not list then return hx.warn(more) end  -- not a capture
        -- more: the number of the next packet when there are more than 1000 matches
        local n = 0
        for _, p in ipairs(list) do
            if p.payload_length > 0 then
                doc:add_bookmark(p.payload, p.payload_length, "#" .. p.number .. " " .. p.proto, "teal", p.summary)
                n = n + 1
            end
        end
        print(string.format("%d bookmarks (%d packets matched%s)", n, #list, more and ", more from #" .. more or ""))
    end,
}
