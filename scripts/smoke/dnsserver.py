#!/usr/bin/env python3
"""
Minimal authoritative DNS server for the osintscan dependency-bump smoke test.

osintscan's headline direct dependency is github.com/miekg/dns, and every
interesting code path in the CLI is a DNS query. Pointing the CLI at a real
resolver would make the test non-hermetic and dependent on the public internet;
this server makes it hermetic while still exercising the full wire path --
osintscan builds a real query, we parse it and build a real response, and
miekg/dns parses that.

Serves a fixed zone for `smoke.test` over UDP (and TCP, for AXFR-style and
truncation-fallback paths). Supports A, AAAA, CNAME, MX, NS, SOA, TXT and PTR.
Everything outside the zone gets NXDOMAIN.

Usage: dnsserver.py <port>   -- prints "READY" on stdout once bound.
"""

import socket
import socketserver
import struct
import sys

ZONE = "smoke.test."

# name -> list of (rrtype, rdata-builder)
A, NS, CNAME, SOA, PTR, MX, TXT, AAAA = 1, 2, 5, 6, 12, 15, 16, 28

TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR",
              MX: "MX", TXT: "TXT", AAAA: "AAAA"}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def ipv4(addr):
    return socket.inet_aton(addr)


def ipv6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def txt(s):
    b = s.encode("ascii")
    return bytes([len(b)]) + b


def mx(pref, host):
    return struct.pack("!H", pref) + encode_name(host)


def soa():
    return (encode_name("ns1." + ZONE) + encode_name("hostmaster." + ZONE) +
            struct.pack("!IIIII", 2026083101, 7200, 3600, 1209600, 3600))


# The zone. Keys are fully-qualified, lowercase, trailing dot.
RECORDS = {
    ZONE: [
        (A, ipv4("192.0.2.10")),
        (AAAA, ipv6("2001:db8::10")),
        (NS, encode_name("ns1." + ZONE)),
        (NS, encode_name("ns2." + ZONE)),
        (SOA, soa()),
        (MX, mx(10, "mail." + ZONE)),
        (TXT, txt("v=spf1 -all")),
        (TXT, txt("smoke-test-marker")),
    ],
    "www." + ZONE: [
        (CNAME, encode_name(ZONE)),
    ],
    "mail." + ZONE: [
        (A, ipv4("192.0.2.20")),
    ],
    "ns1." + ZONE: [(A, ipv4("192.0.2.2"))],
    "ns2." + ZONE: [(A, ipv4("192.0.2.3"))],
    "10.2.0.192.in-addr.arpa.": [
        (PTR, encode_name(ZONE)),
    ],
}


def parse_question(data):
    """Return (qname, qtype, offset-after-question) or None."""
    off = 12
    labels = []
    while True:
        if off >= len(data):
            return None
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:            # no compression pointers in a question
            return None
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    if off + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
    qname = ".".join(labels).lower() + "."
    return qname, qtype, off + 4


def build_response(data):
    q = parse_question(data)
    if not q:
        return None
    qname, qtype, qend = q
    txid = data[0:2]
    question = data[12:qend]

    answers = []
    entries = RECORDS.get(qname, [])
    if entries:
        rcode = 0
        for rrtype, rdata in entries:
            # ANY(255)/ALL fans out; otherwise exact type, with the usual
            # CNAME fallback so `www` answers an A query with its CNAME.
            if qtype in (255,) or rrtype == qtype or rrtype == CNAME:
                answers.append((qname, rrtype, rdata))
    else:
        rcode = 3  # NXDOMAIN

    flags = 0x8400 | rcode        # QR, AA
    header = txid + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)

    body = b""
    for name, rrtype, rdata in answers:
        body += (encode_name(name) + struct.pack("!HHIH", rrtype, 1, 300,
                                                 len(rdata)) + rdata)
    return header + question + body


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = build_response(data)
        if resp:
            sock.sendto(resp, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        hdr = self.request.recv(2)
        if len(hdr) < 2:
            return
        (length,) = struct.unpack("!H", hdr)
        data = b""
        while len(data) < length:
            chunk = self.request.recv(length - len(data))
            if not chunk:
                return
            data += chunk
        resp = build_response(data)
        if resp:
            self.request.sendall(struct.pack("!H", len(resp)) + resp)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(sys.argv[1])
    udp = UDPServer(("127.0.0.1", port), UDPHandler)
    tcp = TCPServer(("127.0.0.1", port), TCPHandler)
    import threading
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print("READY", flush=True)
    udp.serve_forever()


if __name__ == "__main__":
    main()
