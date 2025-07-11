#!/usr/bin/env python3
"""
enhanced dns resolver with cli support, multiple record types, and caching
"""

import socket
import struct
import random
import time
import argparse
import json
import os
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timedelta

# dns record types
RECORD_TYPES = {
    1: 'A',      # ipv4 address
    2: 'NS',     # name server
    5: 'CNAME',  # canonical name
    6: 'SOA',    # start of authority
    15: 'MX',    # mail exchange
    16: 'TXT',   # text record
    28: 'AAAA',  # ipv6 address
    33: 'SRV',   # service record
    12: 'PTR',   # pointer record
}

# reverse lookup for record types
RECORD_TYPE_CODES = {v: k for k, v in RECORD_TYPES.items()}

class DNSCache:
    """simple dns cache implementation"""
    
    def __init__(self, cache_file: str = "dns_cache.json"):
        self.cache_file = cache_file
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.load_cache()
    
    def load_cache(self):
        """load cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
        except Exception as e:
            print(f"warning: could not load cache: {e}")
            self.cache = {}
    
    def save_cache(self):
        """save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"warning: could not save cache: {e}")
    
    def get(self, domain: str, record_type: str) -> Optional[List[str]]:
        """get cached result if not expired"""
        key = f"{domain}:{record_type}"
        if key in self.cache:
            entry = self.cache[key]
            expiry = datetime.fromisoformat(entry['expiry'])
            if datetime.now() < expiry:
                return entry['data']
            else:
                # remove expired entry
                del self.cache[key]
        return None
    
    def set(self, domain: str, record_type: str, data: List[str], ttl: int):
        """cache result with ttl"""
        key = f"{domain}:{record_type}"
        expiry = datetime.now() + timedelta(seconds=ttl)
        self.cache[key] = {
            'data': data,
            'expiry': expiry.isoformat(),
            'ttl': ttl
        }
        self.save_cache()

class DNSHeader:
    """dns header as defined in rfc 1035 section 4.1.1"""
    
    def __init__(self, id: int = None, flags: int = 0x0100, qdcount: int = 1, 
                 ancount: int = 0, nscount: int = 0, arcount: int = 0):
        self.id = id if id is not None else random.randint(0, 65535)
        self.flags = flags  # default: recursion desired
        self.qdcount = qdcount  # number of questions
        self.ancount = ancount  # number of answers
        self.nscount = nscount  # number of authority records
        self.arcount = arcount  # number of additional records
    
    def to_bytes(self) -> bytes:
        """convert header to bytes (big endian)"""
        return struct.pack('>HHHHHH', 
                          self.id, self.flags, self.qdcount, 
                          self.ancount, self.nscount, self.arcount)
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['DNSHeader', int]:
        """parse header from bytes"""
        if len(data) - offset < 12:
            raise ValueError("insufficient data for dns header")
        
        header_data = data[offset:offset + 12]
        id_val, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', header_data)
        
        return cls(id_val, flags, qdcount, ancount, nscount, arcount), offset + 12

class DNSQuestion:
    """dns question as defined in rfc 1035 section 4.1.2"""
    
    def __init__(self, name: str, qtype: int = 1, qclass: int = 1):
        self.name = name
        self.qtype = qtype  # record type code
        self.qclass = qclass  # 1 for in class
    
    def encode_name(self) -> bytes:
        """encode domain name as per rfc 1035 (e.g., dns.google.com -> 3dns6google3com0)"""
        encoded = b''
        for part in self.name.split('.'):
            encoded += bytes([len(part)]) + part.encode('ascii')
        encoded += b'\x00'  # null terminator
        return encoded
    
    def to_bytes(self) -> bytes:
        """convert question to bytes"""
        return self.encode_name() + struct.pack('>HH', self.qtype, self.qclass)
    
    @classmethod
    def decode_name(cls, data: bytes, offset: int) -> Tuple[str, int]:
        """decode domain name with compression support"""
        name_parts = []
        original_offset = offset
        
        while True:
            if offset >= len(data):
                raise ValueError("invalid dns name encoding")
            
            length = data[offset]
            offset += 1
            
            if length == 0:
                break
            
            # check for compression (bit 6 and 7 set to 1)
            if (length & 0xC0) == 0xC0:
                if offset >= len(data):
                    raise ValueError("invalid compression pointer")
                
                # get the pointer (14 bits)
                pointer = ((length & 0x3F) << 8) | data[offset]
                offset += 1
                
                # recursively decode the name at the pointer
                compressed_name, _ = cls.decode_name(data, pointer)
                name_parts.append(compressed_name)
                break
            else:
                # regular label
                if offset + length > len(data):
                    raise ValueError("invalid label length")
                
                label = data[offset:offset + length].decode('ascii')
                name_parts.append(label)
                offset += length
        
        return '.'.join(name_parts), offset
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['DNSQuestion', int]:
        """parse question from bytes"""
        name, offset = cls.decode_name(data, offset)
        
        if offset + 4 > len(data):
            raise ValueError("insufficient data for dns question")
        
        qtype, qclass = struct.unpack('>HH', data[offset:offset + 4])
        return cls(name, qtype, qclass), offset + 4

class DNSResourceRecord:
    """dns resource record as defined in rfc 1035 section 4.1.3"""
    
    def __init__(self, name: str, rtype: int, rclass: int, ttl: int, rdata: bytes):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> Tuple['DNSResourceRecord', int]:
        """parse resource record from bytes"""
        name, offset = DNSQuestion.decode_name(data, offset)
        
        if offset + 10 > len(data):
            raise ValueError("insufficient data for dns resource record")
        
        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        
        if offset + rdlength > len(data):
            raise ValueError("invalid resource record data length")
        
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        
        return cls(name, rtype, rclass, ttl, rdata), offset
    
    def get_ip_address(self) -> Optional[str]:
        """extract ip address from a record data"""
        if self.rtype == 1 and len(self.rdata) == 4:  # a record
            return '.'.join(str(b) for b in self.rdata)
        return None
    
    def get_ipv6_address(self) -> Optional[str]:
        """extract ipv6 address from aaaa record data"""
        if self.rtype == 28 and len(self.rdata) == 16:  # aaaa record
            # convert to hex and format as ipv6
            hex_parts = []
            for i in range(0, 16, 2):
                hex_parts.append(f"{self.rdata[i]:02x}{self.rdata[i+1]:02x}")
            return ':'.join(hex_parts)
        return None
    
    def get_cname(self) -> Optional[str]:
        """extract canonical name from cname record data"""
        if self.rtype == 5:  # cname record
            try:
                name, _ = DNSQuestion.decode_name(self.rdata, 0)
                return name
            except:
                return None
        return None
    
    def get_mx_record(self) -> Optional[Tuple[int, str]]:
        """extract mx record data (priority, exchange)"""
        if self.rtype == 15 and len(self.rdata) >= 3:  # mx record
            try:
                priority = struct.unpack('>H', self.rdata[:2])[0]
                exchange, _ = DNSQuestion.decode_name(self.rdata, 2)
                return (priority, exchange)
            except:
                return None
        return None
    
    def get_txt_record(self) -> Optional[str]:
        """extract txt record data"""
        if self.rtype == 16 and len(self.rdata) > 0:  # txt record
            try:
                length = self.rdata[0]
                if len(self.rdata) >= length + 1:
                    return self.rdata[1:length+1].decode('utf-8', errors='ignore')
            except:
                return None
        return None
    
    def get_name_server(self) -> Optional[str]:
        """extract name server from ns record data"""
        if self.rtype == 2:  # ns record
            try:
                name, _ = DNSQuestion.decode_name(self.rdata, 0)
                return name
            except:
                return None
        return None
    
    def get_soa_record(self) -> Optional[Dict[str, Any]]:
        """extract soa record data"""
        if self.rtype == 6:  # soa record
            try:
                offset = 0
                mname, offset = DNSQuestion.decode_name(self.rdata, offset)
                rname, offset = DNSQuestion.decode_name(self.rdata, offset)
                
                if offset + 20 <= len(self.rdata):
                    serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', self.rdata[offset:offset+20])
                    return {
                        'mname': mname,
                        'rname': rname,
                        'serial': serial,
                        'refresh': refresh,
                        'retry': retry,
                        'expire': expire,
                        'minimum': minimum
                    }
            except:
                return None
        return None

class DNSMessage:
    """complete dns message"""
    
    def __init__(self, header: DNSHeader, question: DNSQuestion, 
                 answers: List[DNSResourceRecord] = None,
                 authorities: List[DNSResourceRecord] = None,
                 additionals: List[DNSResourceRecord] = None):
        self.header = header
        self.question = question
        self.answers = answers or []
        self.authorities = authorities or []
        self.additionals = additionals or []
    
    def to_bytes(self) -> bytes:
        """convert entire message to bytes"""
        message = self.header.to_bytes() + self.question.to_bytes()
        
        # add answers, authorities, and additionals
        for record in self.answers + self.authorities + self.additionals:
            # for simplicity, we'll just add the name encoding
            # in a full implementation, you'd need to handle the full rr format
            pass
        
        return message
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSMessage':
        """parse complete dns message from bytes"""
        offset = 0
        
        # parse header
        header, offset = DNSHeader.from_bytes(data, offset)
        
        # parse question
        question, offset = DNSQuestion.from_bytes(data, offset)
        
        # parse answers
        answers = []
        for _ in range(header.ancount):
            if offset >= len(data):
                break
            answer, offset = DNSResourceRecord.from_bytes(data, offset)
            answers.append(answer)
        
        # parse authorities
        authorities = []
        for _ in range(header.nscount):
            if offset >= len(data):
                break
            authority, offset = DNSResourceRecord.from_bytes(data, offset)
            authorities.append(authority)
        
        # parse additionals
        additionals = []
        for _ in range(header.arcount):
            if offset >= len(data):
                break
            additional, offset = DNSResourceRecord.from_bytes(data, offset)
            additionals.append(additional)
        
        return cls(header, question, answers, authorities, additionals)

class DNSResolver:
    """enhanced dns resolver implementation"""
    
    def __init__(self, use_cache: bool = True, cache_file: str = "dns_cache.json"):
        self.root_servers = [
            '198.41.0.4',      # a.root-servers.net
            '199.9.14.201',    # b.root-servers.net
            '192.33.4.12',     # c.root-servers.net
            '199.7.91.13',     # d.root-servers.net
            '192.203.230.10',  # e.root-servers.net
            '192.5.5.241',     # f.root-servers.net
            '192.112.36.4',    # g.root-servers.net
            '198.97.190.53',   # h.root-servers.net
            '192.36.148.17',   # i.root-servers.net
            '192.58.128.30',   # j.root-servers.net
            '193.0.14.129',    # k.root-servers.net
            '199.7.83.42',     # l.root-servers.net
            '202.12.27.33'     # m.root-servers.net
        ]
        self.cache = DNSCache(cache_file) if use_cache else None
        self.verbose = False
    
    def set_verbose(self, verbose: bool):
        """set verbose mode for detailed output"""
        self.verbose = verbose
    
    def create_query(self, domain: str, record_type: str = 'A', recursion_desired: bool = True) -> DNSMessage:
        """create a dns query message"""
        flags = 0x0100 if recursion_desired else 0x0000  # recursion desired flag
        header = DNSHeader(flags=flags)
        qtype = RECORD_TYPE_CODES.get(record_type.upper(), 1)  # default to a record
        question = DNSQuestion(domain, qtype)
        return DNSMessage(header, question)
    
    def send_query(self, message: DNSMessage, server: str, port: int = 53, timeout: int = 5) -> DNSMessage:
        """send dns query to server and return response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        try:
            # send query
            query_bytes = message.to_bytes()
            sock.sendto(query_bytes, (server, port))
            
            # receive response
            response_data, _ = sock.recvfrom(512)  # dns responses are typically < 512 bytes
            
            # parse response
            response = DNSMessage.from_bytes(response_data)
            
            # verify response id matches query id
            if response.header.id != message.header.id:
                raise ValueError("response id doesn't match query id")
            
            return response
            
        finally:
            sock.close()
    
    def parse_records(self, records: List[DNSResourceRecord], record_type: str) -> List[str]:
        """parse records based on record type"""
        results = []
        
        for record in records:
            if record.rtype == RECORD_TYPE_CODES.get(record_type.upper(), 1):
                if record_type.upper() == 'A':
                    ip = record.get_ip_address()
                    if ip:
                        results.append(ip)
                elif record_type.upper() == 'AAAA':
                    ipv6 = record.get_ipv6_address()
                    if ipv6:
                        results.append(ipv6)
                elif record_type.upper() == 'CNAME':
                    cname = record.get_cname()
                    if cname:
                        results.append(cname)
                elif record_type.upper() == 'MX':
                    mx = record.get_mx_record()
                    if mx:
                        results.append(f"{mx[0]} {mx[1]}")
                elif record_type.upper() == 'TXT':
                    txt = record.get_txt_record()
                    if txt:
                        results.append(txt)
                elif record_type.upper() == 'NS':
                    ns = record.get_name_server()
                    if ns:
                        results.append(ns)
                elif record_type.upper() == 'SOA':
                    soa = record.get_soa_record()
                    if soa:
                        results.append(f"mname={soa['mname']}, rname={soa['rname']}, serial={soa['serial']}")
        
        return results
    
    def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        """resolve domain to records of specified type"""
        if self.verbose:
            print(f"resolving {domain} ({record_type} record)...")
        
        # check cache first
        if self.cache:
            cached_result = self.cache.get(domain, record_type)
            if cached_result:
                if self.verbose:
                    print(f"cache hit for {domain} ({record_type})")
                return cached_result
        
        # start with root servers
        current_servers = self.root_servers.copy()
        queried_domain = domain
        max_iterations = 10  # prevent infinite loops
        iteration = 0
        
        while current_servers and iteration < max_iterations:
            iteration += 1
            
            for server in current_servers:
                try:
                    if self.verbose:
                        print(f"querying {server} for {queried_domain} ({record_type})")
                    
                    # create query (no recursion for root/authoritative servers)
                    recursion = len(current_servers) == len(self.root_servers)  # only recursive for first query
                    query = self.create_query(queried_domain, record_type, recursion_desired=recursion)
                    
                    # send query
                    response = self.send_query(query, server)
                    
                    # check if we got an answer
                    results = self.parse_records(response.answers, record_type)
                    
                    if results:
                        if self.verbose:
                            print(f"found {record_type} records: {results}")
                        
                        # cache the result
                        if self.cache and response.answers:
                            min_ttl = min(r.ttl for r in response.answers if r.ttl > 0)
                            self.cache.set(domain, record_type, results, min_ttl)
                        
                        return results
                    
                    # handle cname records
                    cname_results = self.parse_records(response.answers, 'CNAME')
                    if cname_results:
                        if self.verbose:
                            print(f"found cname: {cname_results[0]}, following...")
                        # follow cname
                        return self.resolve(cname_results[0], record_type)
                    
                    # look for name servers in authorities
                    name_servers = self.parse_records(response.authorities, 'NS')
                    
                    # look for ip addresses of name servers in additionals
                    ns_ips = []
                    for additional in response.additionals:
                        if additional.rtype == 1:  # a record
                            ip = additional.get_ip_address()
                            if ip:
                                ns_ips.append(ip)
                    
                    # if we have name servers but no ips, resolve the name servers
                    if name_servers and not ns_ips:
                        for ns_name in name_servers:
                            try:
                                ns_ips.extend(self.resolve(ns_name, 'A'))
                            except Exception as e:
                                if self.verbose:
                                    print(f"failed to resolve {ns_name}: {e}")
                    
                    if ns_ips:
                        current_servers = ns_ips
                        break
                    
                except Exception as e:
                    if self.verbose:
                        print(f"failed to query {server}: {e}")
                    continue
            else:
                # if we get here, all servers failed
                raise Exception(f"failed to resolve {domain}")
        
        raise Exception(f"could not resolve {domain}")

def main():
    """main function with cli support"""
    parser = argparse.ArgumentParser(description='custom dns resolver')
    parser.add_argument('domain', help='domain name to resolve')
    parser.add_argument('--type', '-t', default='A', 
                       choices=['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'],
                       help='dns record type (default: A)')
    parser.add_argument('--no-cache', action='store_true', 
                       help='disable caching')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='verbose output')
    parser.add_argument('--cache-file', default='dns_cache.json',
                       help='cache file path (default: dns_cache.json)')
    
    args = parser.parse_args()
    
    # create resolver
    resolver = DNSResolver(use_cache=not args.no_cache, cache_file=args.cache_file)
    resolver.set_verbose(args.verbose)
    
    try:
        start_time = time.time()
        results = resolver.resolve(args.domain, args.type)
        end_time = time.time()
        
        print(f"\n{args.domain} ({args.type}):")
        for result in results:
            print(f"  {result}")
        
        if args.verbose:
            print(f"\nresolution completed in {end_time - start_time:.2f} seconds")
        
    except Exception as e:
        print(f"error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
