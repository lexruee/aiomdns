# -*- coding:utf-8 -*-

import io
from aiomdns import util
from aiomdns.protocol import Message

"""
mDNS sample message from a wireshark capture

Frame 128642: 179 bytes on wire (1432 bits), 179 bytes captured (1432 bits) on interface 0
Ethernet II, Src: Raspberr_ad:46:18 (b8:27:eb:ad:46:18), Dst: IPv4mcast_fb (01:00:5e:00:00:fb)
Internet Protocol Version 4, Src: 10.0.0.110, Dst: 224.0.0.251
User Datagram Protocol, Src Port: 5353, Dst Port: 5353
Multicast Domain Name System (response)
    Transaction ID: 0x0000
    Flags: 0x8400 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .1.. .... .... = Authoritative: Server is an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...0 .... .... = Recursion desired: Don't do query recursively
        .... .... 0... .... = Recursion available: Server can't do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 0
    Answer RRs: 3
    Authority RRs: 0
    Additional RRs: 0
    Answers
        piserver [b8:27:eb:ad:46:18]._workstation._tcp.local: type SRV, class IN, cache flush, priority 0, weight 0, port 9, target piserver.local
            Service: piserver [b8:27:eb:ad:46:18]
            Protocol: _workstation
            Name: _tcp.local
            Type: SRV (Server Selection) (33)
            .000 0000 0000 0001 = Class: IN (0x0001)
            1... .... .... .... = Cache flush: True
            Time to live: 120
            Data length: 17
            Priority: 0
            Weight: 0
            Port: 9
            Target: piserver.local
        piserver.local: type AAAA, class IN, cache flush, addr fe80::5fbc:a067:7867:385f
            Name: piserver.local
            Type: AAAA (IPv6 Address) (28)
            .000 0000 0000 0001 = Class: IN (0x0001)
            1... .... .... .... = Cache flush: True
            Time to live: 120
            Data length: 16
            AAAA Address: fe80::5fbc:a067:7867:385f
        piserver.local: type A, class IN, cache flush, addr 10.0.0.110
            Name: piserver.local
            Type: A (Host Address) (1)
            .000 0000 0000 0001 = Class: IN (0x0001)
            1... .... .... .... = Cache flush: True
            Time to live: 120
            Data length: 4
            Address: 10.0.0.110
"""

HEADER_DATA = util.unhexlify_string("00 00 84 00 00 00 00 03 00 00 00 00")
RECORDS_DATA = util.unhexlify_string("""
1c 70 69 73
65 72 76 65 72 20 5b 62 38 3a 32 37 3a 65 62 3a
61 64 3a 34 36 3a 31 38 5d 0c 5f 77 6f 72 6b 73
74 61 74 69 6f 6e 04 5f 74 63 70 05 6c 6f 63 61
6c 00 00 21 80 01 00 00 00 78 00 11 00 00 00 00
00 09 08 70 69 73 65 72 76 65 72 c0 3b c0 52 00
1c 80 01 00 00 00 78 00 10 fe 80 00 00 00 00 00
00 5f bc a0 67 78 67 38 5f c0 52 00 01 80 01 00
00 00 78 00 04 0a 00 00 6e
""")

PACKET = HEADER_DATA + RECORDS_DATA

def test_parse_message():
    message = Message()
    message.parse(PACKET)

    assert len(message.records()) == 3
