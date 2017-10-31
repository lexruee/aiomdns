# -*- coding:utf-8 -*-
from aiomdns import protocol as p
from aiomdns import util

HEADER_DATA = util.unhexlify_string("00 00 84 00 00 00 00 03 00 00 00 00")


def test_create_header():
    header = p.Header()
    id = 0
    qr, opcode, aa, tc, rd, ra, z, rcode = 1, 0, 1, 0, 0, 0, 0, 0
    qd_count, an_count, ns_count, ar_count = 0, 3, 0, 0
    header_size = 12

    header.id(id)
    assert header.id() == id
    header.qr(qr)
    assert header.qr() == qr
    header.opcode(opcode)
    assert header.opcode() == opcode
    header.aa(aa)
    assert header.aa() == aa
    header.tc(tc)
    assert header.tc() == tc
    header.rd(rd)
    assert header.rd() == rd
    header.ra(ra)
    assert header.ra() == ra
    header.z(z)
    assert header.z() == z
    header.rcode(rcode)
    assert header.rcode() == rcode
    header.qd_count(qd_count)
    assert header.qd_count() == qd_count
    header.an_count(an_count)
    assert header.an_count() == an_count
    header.ns_count(ns_count)
    assert header.ns_count() == ns_count
    header.ar_count(ar_count)
    assert header.ar_count() == ar_count
    assert header.size() == header_size

    return header


def test_pack_header():
    header = test_create_header()
    byte_data = header.pack()
    assert type(byte_data) is bytes
    assert HEADER_DATA == byte_data


def test_pack_into_header():
    header = test_create_header()
    writeable_buf = bytearray(header.size())
    header.pack_into(writeable_buf)
    assert HEADER_DATA == writeable_buf


def test_create_ARecord():
    record = p.ARecord()
    addr_tuple = (10, 0, 0, 110)
    addr_str = '10.0.0.110'
    rname = 'piserver.local'
    rdlength = 4
    ttl = 120
    cache_flush = 1

    assert record.rdlength() == rdlength
    record.ttl(ttl)
    assert record.ttl() == ttl
    record.rtype(p.MDNS_TYPE_A)
    assert record.rtype() == p.MDNS_TYPE_A
    record.rclass(p.MDNS_CLASS_IN_FLUSH_CACHE)
    assert record.rclass() == p.MDNS_CLASS_IN_FLUSH_CACHE
    record.cache_flush(cache_flush)
    assert record.cache_flush() == cache_flush
    record.address(addr_tuple)
    assert record.address() == addr_tuple
    assert record.address_str() == addr_str
    record.rname(rname)
    assert record.rname() == rname

    return record


def test_create_AAAARecord():
    record = p.AAAARecord()
    addr_tuple = (0xfe80, 0x00, 0x00, 0x00, 0x5fbc, 0xa067, 0x7867, 0x385f)
    addr_str = 'fe80:0:0:0:5fbc:a067:7867:385f'
    rname = 'piserver.local'
    rdlength = 16
    ttl = 120
    cache_flush = 1

    assert record.rdlength() == rdlength
    record.ttl(ttl)
    assert record.ttl() == ttl
    record.rtype(p.MDNS_TYPE_AAAA)
    assert record.rtype() == p.MDNS_TYPE_AAAA
    record.rclass(p.MDNS_CLASS_IN_FLUSH_CACHE)
    assert record.rclass() == p.MDNS_CLASS_IN_FLUSH_CACHE
    record.cache_flush(cache_flush)
    assert record.cache_flush() == cache_flush
    record.address(addr_tuple)
    assert record.address() == addr_tuple
    assert record.address_str() == addr_str
    record.rname(rname)
    assert record.rname() == rname

    return record


def test_create_PTRRecord():
    record = p.PTRRecord()
    rname = '_workstation._tcp.local'
    ptrdname = 'piserver [b8:27:eb:ad:46:18]._workstation._tcp.local'
    rdlength = 16
    ttl = 4500
    cache_flush = 0

    record.ttl(ttl)
    assert record.ttl() == ttl
    #assert record.rdlength() == 31
    record.rtype(p.MDNS_TYPE_PTR)
    assert record.rtype() == p.MDNS_TYPE_PTR
    record.rclass(p.MDNS_CLASS_IN)
    assert record.rclass() == p.MDNS_CLASS_IN
    record.cache_flush(cache_flush)
    assert record.cache_flush() == cache_flush
    record.ptrdname(ptrdname)
    assert record.ptrdname() == ptrdname
    record.rname(rname)
    assert record.rname() == rname

    return record


def test_create_TXTRecord():
    record = p.TXTRecord()
    rname = 'piserver [b8:27:eb:ad:46:18]._workstation._tcp.local'
    ttl = 4500
    cache_flush = 1

    record.ttl(ttl)
    assert record.ttl() == ttl
    #assert record.rdlength() == 1
    record.rtype(p.MDNS_TYPE_TXT)
    assert record.rtype() == p.MDNS_TYPE_TXT
    record.rclass(p.MDNS_CLASS_IN_FLUSH_CACHE)
    assert record.rclass() == p.MDNS_CLASS_IN_FLUSH_CACHE
    record.cache_flush(cache_flush)
    assert record.cache_flush() == cache_flush
    record.rname(rname)
    assert record.rname() == rname

    return record


def test_create_SRVRecord():
    record = p.SRVRecord()
    rname = 'piserver [b8:27:eb:ad:46:18]._workstation._tcp.local'
    target, port, weight, priority = 'piserver.local', 9, 0, 0
    rdlength = 16
    ttl = 4500
    cache_flush = 0

    record.ttl(ttl)
    assert record.ttl() == ttl
    #assert record.rdlength() == 17
    record.rtype(p.MDNS_TYPE_SRV)
    assert record.rtype() == p.MDNS_TYPE_SRV
    record.rclass(p.MDNS_CLASS_IN_FLUSH_CACHE)
    assert record.rclass() == p.MDNS_CLASS_IN_FLUSH_CACHE
    record.cache_flush(cache_flush)
    assert record.cache_flush() == cache_flush
    record.target(target)
    assert record.target() == target
    record.port(port)
    assert record.port() == port
    record.weight(weight)
    assert record.weight() == weight
    record.priority(priority)
    assert record.priority() == priority
    record.rname(rname)
    assert record.rname() == rname

    return record


def test_pack_arecord():
    record = test_create_ARecord()
    byte_data = record.pack()