#!/usr/bin/env python3

from socketserver import BaseRequestHandler, UDPServer
from ipaddress import IPv4Address, IPv6Address
import socket
from struct import unpack_from, pack, pack_into
import argparse
import sys

class domain(object):
    def __init__(self, labels):
        self.labels = labels

    def __str__(self):
        return ".".join(self.labels)

    def __repr__(self):
        return ".".join(self.labels)

    def __iter__(self):
        return iter(self.labels)

    def replace_suffix(self, old, new, modify_notify=None):
        neg_len_old = -len(old)
        labels = self.labels
        if labels[neg_len_old:] == old:
            labels[neg_len_old:] = new
            if modify_notify is not None:
                modify_notify.modified = True
            return domain(labels)
        else:
            return self

    def partial_suffix(self, offset):
        return tuple(self.labels[offset:])

class DNSParser(object):
    types = {1   : "A",      # a host address
             2   : "NS",     # an authoritative name server
             3   : "MD",     # a mail destination (Obsolete - use MX)
             4   : "MF",     # a mail forwarder (Obsolete - use MX)
             5   : "CNAME",  # the canonical name for an alias
             6   : "SOA",    # marks the start of a zone of authority
             7   : "MB",     # a mailbox domain name (EXPERIMENTAL)
             8   : "MG",     # a mail group member (EXPERIMENTAL)
             9   : "MR",     # a mail rename domain name (EXPERIMENTAL)
             10  : "NULL",   # a null RR (EXPERIMENTAL)
             11  : "WKS",    # a well known service description
             12  : "PTR",    # a domain name pointer
             13  : "HINFO",  # host information
             14  : "MINFO",  # mailbox or mail list information
             15  : "MX",     # mail exchange
             16  : "TXT",    # text strings
             28  : "AAAA",   # ipv6 host address
             33  : "SRV",    # service location
             41  : "OPT",    #
             43  : "DS",     #
             252 : "AXFR",   # A request for a transfer of an entire zone
             253 : "MAILB",  # A request for mailbox-related records (MB, MG or MR)
             254 : "MAILA",  # A request for mail agent RRs (Obsolete - see MX)
             255 : "*"}      # A request for all records

    classes = {1   : "IN",   # the Internet
               2   : "CS",   # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
               3   : "CH",   # the CHAOS class
               4   : "HS",   # Hesiod [Dyer 87]
               255 : "*"}    # any class

    def __init__(self, data):
        offset, qdcount, ancount, nscount, arcount = self.parse_header(data)
        offset, self.questions = self.parse_questions(data, qdcount, offset)
        offset, self.answers = self.parse_resource_record(data, ancount, offset)
        offset, self.authorities = self.parse_resource_record(data, nscount, offset)
        offset, self.additionals = self.parse_resource_record(data, arcount, offset)
        self.modified = False

    def parse_header(self, data):
        self.reqid, fields, qdcount, ancount, nscount, arcount = unpack_from("!HHHHHH", data)

        self.query_not_response = bool(fields & 0x8000)
        self.opcode = (fields >> 11) & 0xf
        self.authorative_answer = bool(fields & 0x0400)
        self.truncated = bool(fields & 0x0200)
        self.recursion_desired = bool(fields & 0x0100)
        self.recurtion_available = bool(fields & 0x0080)
        self.rcode = fields & 0xf

        return 12, qdcount, ancount, nscount, arcount

    def parse_questions(self, data, count, offset=12):
        questions = []
        for _ in range(count):
            offset, labels = self._parse_label_pointer(data, offset)
            qtype, qclass = unpack_from("!HH", data, offset)
            offset += 4
            questions.append((qtype, qclass, domain(labels)))
        return offset, questions

    def parse_resource_record(self, data, count, offset):
        records = []
        for _ in range(count):
            offset, labels = self._parse_label_pointer(data, offset)
            rtype, rclass, ttl, rdlength = unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset:offset + rdlength]

            if rtype == 1: # A
                rdecode = IPv4Address(rdata)
            elif rtype in (2, 5, 12): # NS, CNAME, PTR
                rdecode = domain(self._parse_label_pointer(data, offset)[1])
            elif rtype == 6: # SOA
                offset_tmp, mname = self._parse_label_pointer(data, offset)
                offset_tmp, rname = self._parse_label_pointer(data, offset_tmp)
                serial, refresh, retry, expire, minimum = unpack_from("!IIIII", data, offset_tmp)
                rdecode = domain(mname), domain(rname), serial, refresh, retry, expire, minimum
            elif rtype == 15: # MX
                preference, = unpack_from("!H", data, offset)
                rdecode = preference, domain(self._parse_label_pointer(data, offset + 2)[1])
            elif rtype == 16: # TXT
                position = 0
                rdecode = []
                while position < len(rdata):
                    length = rdata[position]
                    position += 1
                    rdecode.append(rdata[position:position + length].decode("ascii"))
                    position += length
            elif rtype == 28:
                rdecode = IPv6Address(rdata)
            else:
                rdecode = None

            offset += rdlength
            records.append((rtype, rclass, ttl, domain(labels), rdata, rdecode))

        return offset, records

    def _parse_label_pointer(self, data, offset=0):
        label_len, = unpack_from("!B", data, offset)
        if not label_len:
            return (offset + 1), []

        if label_len & 0xc0:
            # it's an offset pointer
            offset_pointer = unpack_from("!H", data, offset)[0] & 0x3fff
            _, labels = self._parse_label_pointer(data, offset_pointer)
            return (offset + 2), labels

        # the label is here
        offset += 1
        label = data[offset:offset + label_len].decode("ascii")
        offset, labels = self._parse_label_pointer(data, offset + label_len)
        return offset, ([label] + labels)

    def replace_suffix(self, old, new):
        def replace_records(records):
            records_new = []
            for rtype, rclass, ttl, labels, rdata, rdecode in records:
                if rtype in (2, 5, 12): # NS, CNAME, PTR
                    rdata = None
                    rdecode = rdecode.replace_suffix(old, new, self)
                elif rtype == 6: # SOA
                    mname, rname, serial, refresh, retry, expire, minimum = rdecode
                    rdata = None
                    rdecode = mname.replace_suffix(old, new, self), rname, serial, refresh, retry, expire, minimum

                records_new.append((rtype, rclass, ttl, labels.replace_suffix(old, new, self), rdata, rdecode))
            return records_new

        self.questions = [(qtype, qclass, labels.replace_suffix(old, new, self)) for qtype, qclass, labels in self.questions]
        self.answers = replace_records(self.answers)
        self.authorities = replace_records(self.authorities)
        self.additionals = replace_records(self.additionals)

    def blacklist_types(self, blacklist):
        def blacklist_helper(records):
            ret = []
            for rtype, rclass, ttl, labels, rdata, rdecode in records:
                if self.types.get(rtype) in blacklist:
                    self.modified = True
                else:
                    ret.append((rtype, rclass, ttl, labels, rdata, rdecode))
            return ret

        self.answers = blacklist_helper(self.answers)
        self.authorities = blacklist_helper(self.authorities)
        self.additionals = blacklist_helper(self.additionals)

    def encode(self):
        ret = bytearray(pack("!HHHHHH",
                             self.reqid,
                             (self.query_not_response << 15) |
                             (self.opcode << 11) |
                             (self.authorative_answer << 10) |
                             (self.truncated << 9) |
                             (self.recursion_desired << 8) |
                             (self.recurtion_available << 7) |
                             self.rcode,
                             len(self.questions),
                             len(self.answers),
                             len(self.authorities),
                             len(self.additionals)))

        label_pointers = {}

        for qtype, qclass, labels in self.questions:
            for index, label in enumerate(labels):
                label_pointers.setdefault(labels.partial_suffix(index), len(ret))
                ret.extend(pack("!B", len(label)))
                ret.extend(label.encode("ascii"))
            ret.extend(pack("!BHH", 0, qtype, qclass))

        def encode_helper(labels):
            for index, label in enumerate(labels):
                label_pointers_key = labels.partial_suffix(index)
                pointer = label_pointers.get(label_pointers_key)
                if pointer is None:
                    label_pointers[label_pointers_key] = len(ret)
                    ret.extend(pack("!B", len(label)))
                    ret.extend(label.encode("ascii"))
                else:
                    ret.extend(pack("!H", 0xc000 | pointer))
                    break
            else:
                ret.extend(pack("!B", 0))

        def encode_records(records):
            for rtype, rclass, ttl, labels, rdata, rdecode in records:
                encode_helper(labels)
                ret.extend(pack("!HHIH", rtype, rclass, ttl, 0)) # reserve space for two bytes. filled in below when length is known
                current_position = len(ret)
                if rtype == 1: # A
                    ret.extend(rdecode.packed)
                elif rtype in (2, 5, 12): # NS, CNAME, PTR
                    encode_helper(rdecode)
                elif rtype == 6: # SOA
                    mname, rname, serial, refresh, retry, expire, minimum = rdecode
                    encode_helper(mname)
                    encode_helper(rname)
                    ret.extend(pack("!IIIII", serial, refresh, retry, expire, minimum))
                elif rtype == 15: # MX
                    preference, exchange = rdecode
                    ret.extend(pack("!H", preference))
                    encode_helper(exchange)
                elif rtype == 16: # TXT
                    for text in rdecode:
                        ret.append(len(text))
                        ret.extend(text.encode("ascii"))
                elif rtype == 28:
                    ret.extend(rdecode.packed)
                else:
                    ret.extend(rdata)
                pack_into("!H", ret, current_position - 2, len(ret) - current_position)
        
        encode_records(self.answers)
        encode_records(self.authorities)
        encode_records(self.additionals)

        return ret

    def __str__(self):
        ret = ["  id: {:#06x}".format(self.reqid),
               "    query (True)/ response (False): {}".format(self.query_not_response),
               "    opcode: {:d}".format(self.opcode),
               "    authorative answer: {}".format(self.authorative_answer),
               "    truncated: {}".format(self.truncated),
               "    recursion desired: {}".format(self.recursion_desired),
               "    recursion available: {}".format(self.recurtion_available),
               "    rcode: {:d}".format(self.rcode),
               "    questions: ({})".format(len(self.questions))]

        for qtype, qclass, labels in self.questions:
            ret.append("      {} {} {}".format(self.types.get(qtype),
                                               self.classes.get(qclass),
                                               ".".join(labels)))

        for name, records in (("answers", self.answers),
                              ("authorities", self.authorities),
                              ("additionals", self.additionals)):
            ret.append("    {}: ({})".format(name, len(records)))
            for rtype, rclass, ttl, labels, rdata, rdecode in records:
                ret.append("      {} {} {} {} {}".format(self.types.get(rtype),
                                                         self.classes.get(rclass),
                                                         ttl,
                                                         ".".join(labels),
                                                         rdecode))
        return "\n".join(ret)

class DNSHandler(BaseRequestHandler):
    replace_suffix = None
    forward_host_port = None, None
    type_blacklist = []
    verbose = False

    def log(self, msg):
        if self.verbose:
            print(msg)

    def handle(self):
        request_data, request_socket = self.request

        parser = DNSParser(request_data)
        self.log("request")
        self.log(parser)
        for old, new in self.replace_suffix:
            parser.replace_suffix(old, new)
        if parser.modified:
            request_data = parser.encode()
            self.log("request - modified")
            self.log(parser)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(request_data, self.forward_host_port)
            response_data = sock.recv(0x10000)

        parser = DNSParser(response_data)
        self.log("response")
        self.log(parser)
        parser.blacklist_types(self.type_blacklist)
        for old, new in self.replace_suffix:
            parser.replace_suffix(new, old)
        if parser.modified:
            response_data = parser.encode()
            self.log("response - modified")
            self.log(parser)

        request_socket.sendto(response_data, self.client_address)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", type=str, default="localhost")
    parser.add_argument("--listen-port", type=int, default=5300)
    parser.add_argument("--forward-host", type=str, required=True)
    parser.add_argument("--forward-port", type=int, default=53)
    parser.add_argument("--replace-suffix", type=str, nargs="*", default=[])
    parser.add_argument("--type-blacklist", type=str, nargs="*", default=[])
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    DNSHandler.replace_suffix = [tuple(part.strip(".").split(".") for part in replace_suffix.split(":")) for replace_suffix in args.replace_suffix]
    DNSHandler.forward_host_port = args.forward_host, args.forward_port
    DNSHandler.type_blacklist = args.type_blacklist
    DNSHandler.verbose = args.verbose

    server = UDPServer((args.listen_host, args.listen_port), DNSHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if args.verbose:
            print("done")

if __name__ == "__main__":
    main(sys.argv)
