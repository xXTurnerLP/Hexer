#!/usr/bin/env python3
"""Writes a small demo pcapng capture for the Packets panel (stdlib only).

    python tools/make_pcap.py [out.pcapng]        (default: demo.pcapng)

The capture holds Ethernet frames with ARP, ICMP, TCP and IPv4 / IPv6 UDP packets; the UDP payloads
(port 47000) are packets of the "HXP" protocol that scripts/examples/tlv_protocol.lua parses. Open
the file in Hexer, pick "HXP packet" in the Packets panel's "Parse with" combo, tick "Payload only"
and click a UDP packet (or step with Up / Down): the Structure panel shows the decoded TLV records.
One frame carries an 802.1Q VLAN tag and one HXP packet has a bad CRC, to have something to find.
The capture ends with an HTTP request / response over TCP (port 80) with an out-of-order and a
retransmitted segment: right-click one of its packets > Follow TCP Stream.
"""
import struct
import sys

# ---- HXP (see scripts/examples/tlv_protocol.lua) --------------------------------------------------

MSG = {"HELLO": 1, "DATA": 2, "ACK": 3, "ERROR": 4, "BYE": 5}
TAG = {"DEVICE_ID": 0x01, "TIMESTAMP": 0x02, "TEMPERATURE": 0x03, "NAME": 0x04, "BLOB": 0x05}


def crc16(data):  # CRC-16/CCITT-FALSE
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def rec(tag, value):
    return bytes([TAG[tag]]) + uleb(len(value)) + value


def hxp(msg, records, bad_crc=False):
    payload = b"".join(records)
    body = b"HX" + struct.pack(">BBH", 1, MSG[msg], len(payload)) + payload
    crc = crc16(body) ^ (0x5A5A if bad_crc else 0)
    return body + struct.pack(">H", crc)


# ---- link / network layers ------------------------------------------------------------------------

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
BCAST = b"\xff" * 6
IP_A, IP_B = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
IP6_A = bytes.fromhex("20010db8000000000000000000000001")
IP6_B = bytes.fromhex("20010db8000000000000000000000002")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(dst, src, ethertype, body, vlan=None):
    hdr = dst + src
    if vlan is not None:
        hdr += struct.pack(">HH", 0x8100, vlan)
    frame = hdr + struct.pack(">H", ethertype) + body
    return frame + b"\0" * max(0, 60 - len(frame))  # minimum frame size (padding)


def ipv4(src, dst, proto, body, ident=1):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, 0x4000, 64, proto, 0, src, dst)
    return hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:] + body


def ipv6(src, dst, nh, body):
    return struct.pack(">IHBB", 0x60000000, len(body), nh, 64) + src + dst + body


def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def tcp(sp, dp, flags, seq, ack, payload=b""):
    opts = bytes([2, 4, 0x05, 0xB4, 1, 1, 4, 2]) if flags & 0x02 else b""
    off = (20 + len(opts)) // 4
    return struct.pack(">HHIIBBHHH", sp, dp, seq, ack, off << 4, flags, 64240, 0, 0) + opts + payload


def arp_request(sha, spa, tpa):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + sha + spa + b"\0" * 6 + tpa


def icmp_echo(ident, seq, data):
    body = struct.pack(">BBHHH", 8, 0, 0, ident, seq) + data
    return body[:2] + struct.pack(">H", csum(body)) + body[4:]


# ---- pcapng ---------------------------------------------------------------------------------------

def block(btype, body):
    body += b"\0" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def option(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def shb():
    opts = option(4, b"hexer tools/make_pcap.py") + option(0, b"")  # shb_userappl
    return block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opts)


def idb(linktype=1, snaplen=65535):
    opts = option(2, b"demo0") + option(9, bytes([9])) + option(0, b"")  # if_name, if_tsresol = ns
    return block(1, struct.pack("<HHI", linktype, 0, snaplen) + opts)


def epb(ts_ns, frame):
    return block(6, struct.pack("<IIIII", 0, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(frame), len(frame)) + frame)


def http_conversation():
    """A TCP connection 10.0.0.1:51234 -> 10.0.0.2:80 for Follow TCP Stream: handshake, an HTTP
    request, a response in three segments (the last one arrives before the middle one, which is
    then also retransmitted), FIN both ways."""
    cp, sp = 51234, 80
    c, s = 1000, 5000  # initial sequence numbers

    def c2s(flags, seq, ack, data=b"", ident=20):
        return eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 6, tcp(cp, sp, flags, seq, ack, data), ident))

    def s2c(flags, seq, ack, data=b"", ident=40):
        return eth(MAC_A, MAC_B, 0x0800, ipv4(IP_B, IP_A, 6, tcp(sp, cp, flags, seq, ack, data), ident))

    req = b"GET /sensor/7 HTTP/1.1\r\nHost: 10.0.0.2\r\nUser-Agent: hexer-demo\r\n\r\n"
    body = b'{"device": "sensor-7", "temperature": 23.5, "readings": [235, -41, 240, 999]}\n'
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body)
    b1, b2 = body[:40], body[40:]
    c1, s1 = c + 1, s + 1
    return [
        c2s(0x02, c, 0, ident=20),                                   # SYN
        s2c(0x12, s, c1, ident=40),                                  # SYN, ACK
        c2s(0x10, c1, s1, ident=21),                                 # ACK
        c2s(0x18, c1, s1, req, 22),                                  # request
        s2c(0x10, s1, c1 + len(req), ident=41),
        s2c(0x18, s1, c1 + len(req), head, 42),                      # response headers
        s2c(0x18, s1 + len(head) + len(b1), c1 + len(req), b2, 43),  # body part 2 (out of order)
        c2s(0x10, c1 + len(req), s1 + len(head), ident=23),          # dup ACK: part 1 missing
        s2c(0x18, s1 + len(head), c1 + len(req), b1, 44),            # part 1 (late)
        s2c(0x18, s1 + len(head), c1 + len(req), b1, 46),            # part 1 again (retransmission)
        c2s(0x11, c1 + len(req), s1 + len(head) + len(body), ident=24),          # FIN, ACK
        s2c(0x11, s1 + len(head) + len(body), c1 + len(req) + 1, ident=45),      # FIN, ACK
        c2s(0x10, c1 + len(req) + 1, s1 + len(head) + len(body) + 1, ident=25),  # ACK
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.pcapng"
    t0 = 1767225600 * 1_000_000_000  # 2026-01-01 00:00:00 UTC
    port = 47000

    hello = hxp("HELLO", [rec("DEVICE_ID", struct.pack(">I", 0xC0FFEE42)), rec("NAME", b"sensor-7")])
    ack = hxp("ACK", [])
    data1 = hxp("DATA", [rec("TIMESTAMP", struct.pack(">Q", 1767225601)), rec("TEMPERATURE", struct.pack(">h", 235)),
                         rec("BLOB", b"\xde\xad\xbe\xef")])
    data2 = hxp("DATA", [rec("TIMESTAMP", struct.pack(">Q", 1767225602)), rec("TEMPERATURE", struct.pack(">h", -41))])
    data3 = hxp("DATA", [rec("TEMPERATURE", struct.pack(">h", 240)), rec("NAME", b"over IPv6")])
    broken = hxp("DATA", [rec("TEMPERATURE", struct.pack(">h", 999))], bad_crc=True)
    bye = hxp("BYE", [rec("NAME", b"sensor-7 going to sleep")])

    frames = [
        eth(BCAST, MAC_A, 0x0806, arp_request(MAC_A, IP_A, IP_B)),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 1, icmp_echo(1, 1, b"hexer ping"), 1)),
        eth(MAC_A, MAC_B, 0x0800, ipv4(IP_B, IP_A, 6, tcp(8080, 51000, 0x12, 7000, 1001), 2)),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 17, udp(40000, port, hello), 3)),
        eth(MAC_A, MAC_B, 0x0800, ipv4(IP_B, IP_A, 17, udp(port, 40000, ack), 4)),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 17, udp(40000, port, data1), 5), vlan=10),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 17, udp(40000, port, data2), 6)),
        eth(MAC_B, MAC_A, 0x86DD, ipv6(IP6_A, IP6_B, 17, udp(40001, port, data3))),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 17, udp(40000, port, broken), 7)),
        eth(MAC_B, MAC_A, 0x0800, ipv4(IP_A, IP_B, 17, udp(40000, port, bye), 8)),
    ]
    frames += http_conversation()
    blob = shb() + idb()
    for i, f in enumerate(frames):
        blob += epb(t0 + i * 125_000_000 + i * 1234, f)
    with open(out, "wb") as fh:
        fh.write(blob)
    print("wrote %s: %d packets, %d bytes" % (out, len(frames), len(blob)))


if __name__ == "__main__":
    main()
