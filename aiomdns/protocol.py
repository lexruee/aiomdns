# -*- coding:utf-8 -*-

__author__ = 'Alexander Rüedlinger'

import struct
import binascii
import sys
import socket
from . import util

MDNS_UDP_PORT = 5353
MDNS_MULTICAST_ADDR_IPv4 = '224.0.0.251'
MDNS_MULTICAST_ADDR_IPv6 = 'FF02::FB'

def create_socket_ipv4(interface='0.0.0.0'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MDNS_UDP_PORT))
    group = socket.inet_aton(MDNS_MULTICAST_ADDR_IPv4)
    mreq = group + socket.inet_aton(interface)
    sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock

def create_socket_ipv6(interface='0.0.0.0'):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MDNS_UDP_PORT))
    group = socket.inet_pton(socket.AF_INET6, MDNS_MULTICAST_ADDR_IPv6)
    mreq = group + socket.inet_aton(interface)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    return sock


# TYPE value and meaning
MDNS_TYPE_A = 0x0001        # an IPv4 host address
MDNS_TYPE_PTR = 0x000C      # a domain name pointer
MDNS_TYPE_TXT = 0x0010      # text strings
MDNS_TYPE_AAAA = 0x001C     # an IPv6 host address
MDNS_TYPE_SRV = 0x0021      # location of the service
MDNS_TYPE_HINFO = 0x000C    # host information

MDNS_CLASS_IN = 0x0001
MDNS_NAME_REF = 0xC000

MDNS_CLASS_IN_FLUSH_CACHE = 0x8001
MDNS_ANSWERS_ALL = 0x0F
MDNS_ANSWER_PTR = 0x08
MDNS_ANSWER_TXT = 0x04
MDNS_ANSWER_SRV = 0x02
MDNS_ANSWER_A = 0x01
MDNS_MAX_PACKET_SIZE = 9000


to_int = util.py3_to_int
find_pos = util.py3_find_pos
labels_to_string = util.py3_labels_to_string


class ParsingError(Exception):
    pass


class EncodingError(Exception):
    pass


class Base(object):

    def pack(self):
        raise NotImplementedError

    def unpack(self, stream):
        raise NotImplementedError

    @staticmethod
    def _unpack_name(stream):
        labels, next = [], -1
        offset = first = stream.tell()

        while True:
            stream.seek(offset)
            label_len = to_int(stream.read(1))
            offset += 1
            if label_len == 0:  # check if this is the null string
                break

            pointer = label_len & 0xc0  # check if this byte is a label pointer
            if pointer == 0x00:  # byte is not a label pointer
                stream.seek(offset)
                label = stream.read(label_len)
                labels.append(label)
                offset += label_len

            elif pointer == 0xc0:  # byte is a label pointer
                if next < 0:
                    next = offset + 1

                stream.seek(offset)
                offset = ((label_len & 0x3f) << 8) | to_int(stream.read(1))

                if offset >= first:
                    raise ParsingError("Bad domain name")

                first = offset
            else:
                raise ParsingError("Bad domain name")

        if next >= 0:
            stream.seek(next)
        else:
            stream.seek(offset)

        return labels_to_string(labels)

    @staticmethod
    def _unpack_string(stream, length):
        return struct.unpack('>{}c'.format(length), stream.read(length))


class Header(Base):
    """
    Representation of a DNS header.
    According to rfc1035, the header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    Note that each field is two bytes long. Thus, the header is overall 12 bytes long.
    """

    HEADER_FORMAT = '>HHHHHH'

    def __init__(self, id=0, flags=0, qd_count=0, an_count=0, ns_count=0, ar_count=0):
        self._id = id  # this field identifies a specific DNS transaction
        self._flags = flags  # this field contain the control bits
        self._qd_count = qd_count  # this field defines the number of questions in the questions section
        self._an_count = an_count  # this field defines the number of answers in the answer RRs section
        self._ns_count = ns_count  # this field defines the number of name server in the authority RRs section
        self._ar_count = ar_count  # this field defines the number of additionals in the additional RRs section

    def unpack(self, stream):
        data = stream.read(12)  # header is 12 bytes long
        self._id, self._flags, self._qd_count, self._an_count, self._ns_count, self._ar_count = \
            struct.unpack(self.HEADER_FORMAT, data)
        return self

    def pack(self):
        return None

    def id(self, id=None):
        if id:
            self._id = id
        return self._id

    def qd_count(self, value=None):
        if value:
            self._qd_count = value
        return self._qd_count

    def an_count(self, value=None):
        if value:
            self._an_count = value
        return self._an_count

    def ns_count(self, value=None):
        if value:
            self._ns_count = value
        return self._ns_count

    def ar_count(self, value=None):
        if value:
            self._ar_count = value
        return self._ar_count

    def flags(self, value=None):
        if value:
            self._flags = value
        return self._flags

    def qr(self, value=None):
        if value:
            self._flags |= (value << 15)
        return (self._flags & 0x8000) >> 15

    def opcode(self, value=None):
        if value:
            self._flags |= (value << 11)
        return (self._flags & 0x7800) >> 11

    def aa(self, value=None):
        if value:
            self._flags |= (value << 10)
        return (self._flags & 0x0400) >> 10

    def tc(self, value=None):
        if value:
            self._flags |= (value << 9)
        return (self._flags & 0x0200) >> 9

    def rd(self, value=None):
        if value:
            self._flags |= (value << 8)
        return (self._flags & 0x0100) >> 8

    def ra(self, value=None):
        if value:
            self._flags |= (value << 7)
        return (self._flags & 0x0080) >> 7

    def z(self, value=None):
        if value:
            self._flags |= (value << 6)
        return (self._flags & 0x0040) >> 6

    def ad(self, value=None):
        if value:
            self._flags |= (value << 5)
        return (self._flags & 0x0020) >> 5

    def cd(self, value=None):
        if value:
            self._flags |= (value << 4)
        return (self._flags & 0x0010) >> 4

    def rcode(self, value=None):
        if value:
            self._flags |= value
        return self._flags & 0x000f

    def __str__(self):
        return '<Header(id: {}, qr: {}, opcode: {}, aa: {}, tc: {}, rd: {}, ra: {}, z: {}, ' \
               'rcode: {}, qd_count: {}, an_count: {}, ns_count: {}, ar_count: {})>'\
            .format(self._id, self.qr(), self.opcode(), self.aa(), self.tc(), self.rd(), self.ra(), self.z(),
                    self.rcode(), self.qd_count(), self.an_count(), self.ns_count(), self.ar_count())

    __repr__ = __str__


class Question(Base):
    """
    Representation of a question section.
    The question section format is defined as follows:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """

    FORMAT = '>HH'

    def __init__(self, qname='', qtype=0, qclass=0):
        self._qname = qname
        self._qtype = qtype
        self._qclass = qclass

    def pack(self):
        return None

    def unpack(self, stream):
        self._qname = self._unpack_name(stream)
        self._qtype, self._qclass = struct.unpack(self.FORMAT, stream.read(4))
        return self

    def qname(self, value=None):
        if value:
            self._qname = value
        return self._qname

    def qtype(self, value=None):
        if value:
            self._qtype = value
        return self._qtype

    def qclass(self, value=None):
        if value:
            self._qclass = value
        return self._qclass

    def __str__(self):
        return '<Question(qname: {}, qtype: {}, qclass: {})>'.format(self._qname, self._qtype, self._qclass)

    __repr__ = __str__


class Record(Base):
    """
    Representation of a record.
    The resource record format is defined as follows:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    NAME            an owner name, i.e., the name of the node to which this
                    resource record pertains.

    TYPE            two octets containing one of the RR TYPE codes.

    CLASS           two octets containing one of the RR CLASS codes.

    TTL             a 32 bit signed integer that specifies the time interval
                    that the resource record may be cached before the source
                    of the information should again be consulted.  Zero
                    values are interpreted to mean that the RR can only be
                    used for the transaction in progress, and should not be
                    cached.  For example, SOA records are always distributed
                    with a zero TTL to prohibit caching.  Zero values can
                    also be used for extremely volatile data.

    RDLENGTH        an unsigned 16 bit integer that specifies the length in
                    octets of the RDATA field.

    RDATA           a variable length string of octets that describes the
                    resource.  The format of this information varies
                    according to the TYPE and CLASS of the resource record.
    """

    FORMAT = '>HHIH'

    def __init__(self, rname='', rtype=0, rclass=0, ttl=0, rdlength=0, rdata='\x00'):
        self._rname = rname
        self._rtype = rtype
        self._rclass = rclass
        self._ttl = ttl
        self._rdlength = rdlength
        self._rdata = rdata
        self._cache_flush = 0

    def unpack(self, stream):
        self._rname = self._unpack_name(stream)
        self._rtype, self._rclass, self._ttl, self._rdlength =\
            struct.unpack(self.FORMAT, stream.read(10))

        self._cache_flush = self._rclass >> 15

        self._rdata = stream.read(self._rdlength)
        return self

    def pack(self):
        return self

    def rname(self, value=None):
        if value:
            self._rname = value
        return self._rname

    def rtype(self, value=None):
        if value:
            self._rtype = value
        return self._rtype

    def rclass(self, value=None):
        if value:
            self._rclass = value
        return self._rclass

    def cache_flush(self, value=None):
        if value:
            self._cache_flush = value
        return self._cache_flush

    def ttl(self, value=None):
        if value:
            self._ttl = value
        return self._ttl

    def rdlength(self, value=None):
        if value:
            self._rdlength = value
        return self._rdlength

    def rdata(self, value=None):
        if value:
            self._rdata = value
        return self._rdata

    def pretty_rdata(self):
        return '0x{}'.format(binascii.hexlify(self._rdata))

    def __str__(self):
        return '<{}(name: {}, type: {}, class: {}, ttl: {}, rdlength: {}, rdata: {})>'\
            .format(self.__class__.__name__, self._rname, self._rtype, self._rclass,
                    self._ttl, self._rdlength, self.pretty_rdata())

    __repr__ = __str__


class SRVRecord(Record):
    """
    The SRV resource record type is a record that specifies the location of the
    server(s) for a specific protocol and domain.
    The RDATA segment of the record has the following format:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    Priority                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Weight                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Port                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     Target                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    """

    RDATA_FORMAT = '>HHH'

    def __init__(self, rname='', rclass=0, ttl=0, rdlength=0, priority=0, weight=0, port=0, target=''):
        super(SRVRecord, self).__init__(rname, MDNS_TYPE_SRV, rclass, ttl, rdlength)
        self._priority = priority
        self._weight = weight
        self._port = port
        self._target = target

    def unpack(self, stream):
        super(SRVRecord, self).unpack(stream)
        self._priority, self._weight, self._port = struct.unpack(self.RDATA_FORMAT, self._rdata[0:6])
        offset = stream.tell()
        stream.seek(offset-self._rdlength+6)
        self._target = self._unpack_name(stream)
        print(self._target)
        stream.seek(offset)
        return self

    def pack(self):
        return None

    def priority(self, value=None):
        if value:
            self._priority = value
        return self._priority

    def weight(self, value=None):
        if value:
            self._weight = value
        return self._weight

    def target(self, value=None):
        if value:
            self._target = value
        return self._target

    def port(self, value=None):
        if value:
            self._port = value
        return self._port

    def pretty_rdata(self):
        return '{{priority: {}, weight: {}, port: {}, target: {}}}'\
            .format(self._priority, self._weight, self._port, self._target)


class ARecord(Record):
    """
    The A resource record type is a record that stores a single IPv4 address.
    The RDATA segment of the record has the following format:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    ADDRESS         A 32 bit Internet address.
    """

    RDLENGTH = 4
    RDATA_FORMAT = '>BBBB'

    def __init__(self, rname='', rclass=0, ttl=0,  address=''):
        super(ARecord, self).__init__(rname, MDNS_TYPE_A, rclass, ttl, self.RDLENGTH)
        self._address = address

    def unpack(self, stream):
        super(ARecord, self).unpack(stream)
        self._address = struct.unpack(self.RDATA_FORMAT, self._rdata)
        return self

    def address(self, value=None):
        if value:
            self._address = value
        return self._address

    def address_str(self):
        return self.pretty_rdata()

    def pretty_rdata(self):
        return ".".join(str(num) for num in self._address)


class AAAARecord(Record):
    """
    The AAAA resource record type is a record that stores a single IPv6 address.
    The RDATA segment of the record has the following format:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    |                    ADDRESS                    |
    |                                               |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    ADDRESS         A 128 bit Internet address.
    """

    RDLENGTH = 16
    RDATA_FORMAT = '>HHHHHHHH'

    def __init__(self, rname='', rclass=0, ttl=0, address=''):
        super(AAAARecord, self).__init__(rname, MDNS_TYPE_AAAA, rclass, ttl, self.RDLENGTH)
        self._address = address

    def unpack(self, stream):
        super(AAAARecord, self).unpack(stream)
        self._address = struct.unpack(self.RDATA_FORMAT, self._rdata)
        return self

    def address(self, value=None):
        if value:
            self._address = value
        return self._address

    def address_str(self):
        return self.pretty_rdata()

    def pretty_rdata(self):
        return "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}".format(*self._address)


class PTRRecord(Record):
    """
    The PTR resource record type is a record that stores a resource name,
    namely a sequence of labels.
    The RDATA segment of the record has the following format:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   PTRDNAME                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    PTRDNAME        A <domain-name> which points to some location in the
                    domain name space.
    """

    def __init__(self, rname='', rclass=0, ttl=0, rdlength=0, ptrdname=''):
        super(PTRRecord, self).__init__(rname, MDNS_TYPE_PTR, rclass, ttl, rdlength)
        self._ptrdname = ptrdname

    def ptrdname(self, value=None):
        if value:
            self._ptrdname = value
        return self._ptrdname

    def unpack(self, stream):
        super(PTRRecord, self).unpack(stream)
        offset = stream.tell()
        stream.seek(offset-self._rdlength)
        self._ptrdname = self._unpack_name(stream)
        stream.seek(offset)
        return self

    def pretty_rdata(self):
        return self._ptrdname


class TXTRecord(Record):
    """
    The TXT resource record type is a record that stores text data.
    The RDATA segment of the record has the following format:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   TXT-DATA                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    TXT-DATA        One or more <character-string>s.
    """

    def __init__(self, rname='', rclass=0, ttl=0, rdlength=0, txt_data=None):
        super(TXTRecord, self).__init__(rname, MDNS_TYPE_TXT, rclass, ttl, rdlength)
        self._txt_data = txt_data or {}

    def unpack(self, stream):
        super(TXTRecord, self).unpack(stream)
        self._unpack_txt_data()
        return self

    def _unpack_txt_data(self):
        length, offset = self._rdlength, 0
        while offset < length:
            _len = to_int(self._rdata[offset])
            offset += 1
            data = self._rdata[offset:offset+_len]
            offset += _len
            i = find_pos(data, '=')
            if i > 0:
                try:
                    key, value = data[:i], data[i+1:]
                    self._txt_data[key] = value
                except:
                    pass
        return self

    def pretty_rdata(self):
        return self._txt_data


class Message(Base):
    """
    Representation of a DNS message,
    Following the rfc1035, the dns message format is divided into 5 sections, as shown below:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
    """

    def __init__(self, header=None, questions=None, answer_rrs=None, authority_rrs=None, additional_rrs=None):
        self.header = header or Header()
        self._questions = questions or []
        self._answer_rrs = answer_rrs or []
        self._authority_rrs = authority_rrs or []
        self._additional_rrs = additional_rrs or []

    def pack(self):
        return self

    def questions(self, value=None):
        if value:
            self._questions = value
        return self._questions

    def records(self):
        return self._answer_rrs + self._authority_rrs + self._additional_rrs

    def answer_rrs(self, value=None):
        if value:
            self._answer_rrs = value
        return self._answer_rrs

    def authority_rrs(self, value=None):
        if value:
            self._authority_rrs = value
        return self._authority_rrs

    def additional_rrs(self, value=None):
        if value:
            self._additional_rrs = value
        return self._additional_rrs

    def is_query(self):
        return self.header.qr() == 0

    def is_response(self):
        return self.header.qr() == 1

    def _unpack_record(self, stream):
        offset = stream.tell()
        record = Record().unpack(stream)
        new_offset = stream.tell()
        stream.seek(offset)
        if record.rtype() == MDNS_TYPE_A:
            record = ARecord().unpack(stream)
        elif record.rtype() == MDNS_TYPE_AAAA:
            record = AAAARecord().unpack(stream)
        elif record.rtype() == MDNS_TYPE_PTR:
            record = PTRRecord().unpack(stream)
        elif record.rtype() == MDNS_TYPE_SRV:
            record = SRVRecord().unpack(stream)
        elif record.rtype() == MDNS_TYPE_TXT:
            record = TXTRecord().unpack(stream)
        else:
            stream.seek(new_offset)

        return record

    def unpack(self, stream):
        self.header.unpack(stream)

        for i in range(0, self.header._qd_count):
            question = Question()
            question.unpack(stream)
            self._questions.append(question)

        for i in range(0, self.header._an_count):
            self._answer_rrs.append(self._unpack_record(stream))

        for i in range(0, self.header._ns_count):
            self._authority_rrs.append(self._unpack_record(stream))

        for i in range(0, self.header._ar_count):
            self._additional_rrs.append(self._unpack_record(stream))

        return self

    def __str__(self):
        return '<Message(\n  {}\n{}\n)>'\
            .format(self.header, '\n'.join('  ' + str(q) for q in self.questions() + self.records()))

    __repr__ = __str__
