# -*- coding:utf-8 -*-

import io
from aiomdns import protocol
from aiomdns import util

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


def test_unpack_header():
    stream = io.BytesIO(HEADER_DATA)
    header = protocol.Header()
    header.unpack(stream)
    assert header.id() == 0
    assert header.qr() == 1
    assert header.opcode() == 0
    assert header.aa() == 1
    assert header.tc() == 0
    assert header.rd() == 0
    assert header.ra() == 0
    assert header.z() == 0
    assert header.rcode() == 0
    assert header.qd_count() == 0
    assert header.an_count() == 3
    assert header.ns_count() == 0
    assert header.ar_count() == 0


def test_unpack_records():
    stream = io.BytesIO(PACKET)
    protocol.Header().unpack(stream)
    record1 = protocol.Record().unpack(stream)
    record2 = protocol.Record().unpack(stream)
    record3 = protocol.Record().unpack(stream)

    assert record1.ttl() == 120
    assert record1.rdlength() == 17
    assert record1.rtype() == protocol.MDNS_TYPE_SRV
    assert record1.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record1.cache_flush() == 1
    assert record1.rname() == 'piserver [b8:27:eb:ad:46:18]._workstation._tcp.local'

    assert record2.ttl() == 120
    assert record2.rdlength() == 16
    assert record2.rtype() == protocol.MDNS_TYPE_AAAA
    assert record2.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record2.cache_flush() == 1
    assert record2.rname() == 'piserver.local'

    assert record3.ttl() == 120
    assert record3.rdlength() == 4
    assert record3.rtype() == protocol.MDNS_TYPE_A
    assert record3.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record3.cache_flush() == 1
    assert record3.rname() == 'piserver.local'


def test_unpack_SRVRecord():
    stream = io.BytesIO(PACKET)
    protocol.Header().unpack(stream)
    record = protocol.SRVRecord().unpack(stream)

    assert record.ttl() == 120
    assert record.rdlength() == 17
    assert record.rtype() == protocol.MDNS_TYPE_SRV
    assert record.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record.cache_flush() == 1
    assert record.target() == 'piserver.local'
    assert record.port() == 9
    assert record.weight() == 0
    assert record.priority() == 0
    assert record.rname() == 'piserver [b8:27:eb:ad:46:18]._workstation._tcp.local'


def test_unpack_AAAARecord():
    stream = io.BytesIO(PACKET)
    protocol.Header().unpack(stream)
    protocol.Record().unpack(stream)
    record = protocol.AAAARecord().unpack(stream)

    assert record.ttl() == 120
    assert record.rdlength() == 16
    assert record.rtype() == protocol.MDNS_TYPE_AAAA
    assert record.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record.cache_flush() == 1
    assert record.address() == (0xfe80, 0x00, 0x00, 0x00, 0x5fbc, 0xa067, 0x7867, 0x385f)
    assert record.address_str() == 'fe80:0:0:0:5fbc:a067:7867:385f'
    assert record.rname() == 'piserver.local'


def test_unpack_ARecord():
    stream = io.BytesIO(PACKET)
    protocol.Header().unpack(stream)
    protocol.Record().unpack(stream)
    protocol.Record().unpack(stream)
    record = protocol.ARecord().unpack(stream)

    assert record.ttl() == 120
    assert record.rdlength() == 4
    assert record.rtype() == protocol.MDNS_TYPE_A
    assert record.rclass() == protocol.MDNS_CLASS_IN_FLUSH_CACHE
    assert record.cache_flush() == 1
    assert record.address() == (10, 0, 0, 110)
    assert record.address_str() == '10.0.0.110'
    assert record.rname() == 'piserver.local'

