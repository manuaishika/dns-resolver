#!/usr/bin/env python3
"""
parallel dns resolver with threading, retry logic, and enhanced features
"""

import socket
import struct
import random
import time
import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
}

RECORD_TYPE_CODES = {v: k for k, v in RECORD_TYPES.items()}

class EnhancedCache:
    """enhanced cache with memory and file storage"""
    
    def __init__(self, cache_file: str = "dns_cache.json"):
        self.cache_file = cache_file
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.file_cache: Dict[str, Dict[str, Any]] = {}
        self.load_cache()
    
    def load_cache(self):
        """load cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.file_cache = json.load(f)
        except Exception as e:
            print(f"warning: could not load cache: {e}")
            self.file_cache = {}
    
    def save_cache(self):
        """save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.file_cache, f, indent=2)
        except Exception as e:
            print(f"warning: could not save cache: {e}")
    
    def get(self, domain: str, record_type: str) -> Optional[List[str]]:
        """get cached result if not expired"""
        key = f"{domain}:{record_type}"
        
        # check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            expiry = datetime.fromisoformat(entry['expiry'])
            if datetime.now() < expiry:
                return entry['data']
            else:
                del self.memory_cache[key]
        
        # check file cache
        if key in self.file_cache:
            entry = self.file_cache[key]
            expiry = datetime.fromisoformat(entry['expiry'])
            if datetime.now() < expiry:
                self.memory_cache[key] = entry
                return entry['data']
            else:
                del self.file_cache[key]
        
        return None
    
    def set(self, domain: str, record_type: str, data: List[str], ttl: int):
        """cache result with ttl"""
        key = f"{domain}:{record_type}"
        expiry = datetime.now() + timedelta(seconds=ttl)
        entry = {
            'data': data,
            'expiry': expiry.isoformat(),
            'ttl': ttl
        }
        
        self.memory_cache[key] = entry
        self.file_cache[key] = entry
        self.save_cache()

class DNSHeader:
    """dns header as defined in rfc 1035 section 4.1.1"""
    
    def __init__(self, id: int = None, flags: int = 0x0100, qdcount: int = 1, 
                 ancount: int = 0, nscount: int = 0, arcount: int = 0):
        self.id = id if id is not None else random.randint(0, 65535)
        self.flags = flags
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount
    
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
        self.qtype = qtype
        self.qclass = qclass
    
    def encode_name(self) -> bytes:
        """encode domain name as per rfc 1035"""
        encoded = b''
        for part in self.name.split('.'):
            encoded += bytes([len(part)]) + part.encode('ascii')
        encoded += b'\x00'
        return encoded
    
    def to_bytes(self) -> bytes:
        """convert question to bytes"""
        return self.encode_name() + struct.pack('>HH', self.qtype, self.qclass)
    
    @classmethod
    def decode_name(cls, data: bytes, offset: int) -> Tuple[str, int]:
        """decode domain name with compression support"""
        name_parts = []
        
        while True:
            if offset >= len(data):
                raise ValueError("invalid dns name encoding")
            
            length = data[offset]
            offset += 1
            
            if length == 0:
                break
            
            # check for compression
            if (length & 0xC0) == 0xC0:
                if offset >= len(data):
                    raise ValueError("invalid compression pointer")
                
                pointer = ((length & 0x3F) << 8) | data[offset]
                offset += 1
                
                compressed_name, _ = cls.decode_name(data, pointer)
                name_parts.append(compressed_name)
                break
            else:
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
        if self.rtype == 1 and len(self.rdata) == 4:
            return '.'.join(str(b) for b in self.rdata)
        return None
    
    def get_ipv6_address(self) -> Optional[str]:
        """extract ipv6 address from aaaa record data"""
        if self.rtype == 28 and len(self.rdata) == 16:
            hex_parts = []
            for i in range(0, 16, 2):
                hex_parts.append(f"{self.rdata[i]:02x}{self.rdata[i+1]:02x}")
            return ':'.join(hex_parts)
        return None
    
    def get_cname(self) -> Optional[str]:
        """extract canonical name from cname record data"""
        if self.rtype == 5:
            try:
                name, _ = DNSQuestion.decode_name(self.rdata, 0)
                return name
            except:
                return None
        return None
    
    def get_mx_record(self) -> Optional[Tuple[int, str]]:
        """extract mx record data (priority, exchange)"""
        if self.rtype == 15 and len(self.rdata) >= 3:
            try:
                priority = struct.unpack('>H', self.rdata[:2])[0]
                exchange, _ = DNSQuestion.decode_name(self.rdata, 2)
                return (priority, exchange)
            except:
                return None
        return None
    
    def get_txt_record(self) -> Optional[str]:
        """extract txt record data"""
        if self.rtype == 16 and len(self.rdata) > 0:
            try:
                length = self.rdata[0]
                if len(self.rdata) >= length + 1:
                    return self.rdata[1:length+1].decode('utf-8', errors='ignore')
            except:
                return None
        return None
    
    def get_name_server(self) -> Optional[str]:
        """extract name server from ns record data"""
        if self.rtype == 2:
            try:
                name, _ = DNSQuestion.decode_name(self.rdata, 0)
                return name
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

class ParallelDNSResolver:
    """parallel dns resolver with threading and retry logic"""
    
    def __init__(self, use_cache: bool = True, cache_file: str = "dns_cache.json", 
                 max_workers: int = 5, max_retries: int = 3):
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
        self.cache = EnhancedCache(cache_file) if use_cache else None
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.verbose = False
        self.resolution_steps = []
    
    def set_verbose(self, verbose: bool):
        """set verbose mode for detailed output"""
        self.verbose = verbose
    
    def create_query(self, domain: str, record_type: str = 'A', recursion_desired: bool = True) -> DNSMessage:
        """create a dns query message"""
        flags = 0x0100 if recursion_desired else 0x0000
        header = DNSHeader(flags=flags)
        qtype = RECORD_TYPE_CODES.get(record_type.upper(), 1)
        question = DNSQuestion(domain, qtype)
        return DNSMessage(header, question)
    
    def send_query_with_retry(self, message: DNSMessage, server: str, record_type: str, 
                            domain: str) -> Tuple[bool, DNSMessage, float, str]:
        """send query with retry logic"""
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                query_bytes = message.to_bytes()
                sock.sendto(query_bytes, (server, 53))
                
                response_data, _ = sock.recvfrom(512)
                sock.close()
                
                response = DNSMessage.from_bytes(response_data)
                
                if response.header.id != message.header.id:
                    raise ValueError("response id doesn't match query id")
                
                response_time = time.time() - start_time
                return True, response, response_time, None
                
            except Exception as e:
                sock.close()
                if attempt == self.max_retries - 1:
                    response_time = time.time() - start_time
                    return False, None, response_time, str(e)
                time.sleep(0.1 * (attempt + 1))
    
    def query_servers_parallel(self, servers: List[str], domain: str, record_type: str, 
                             recursion_desired: bool = True) -> Tuple[bool, DNSMessage, str, float]:
        """query multiple servers in parallel"""
        query = self.create_query(domain, record_type, recursion_desired)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_server = {
                executor.submit(self.send_query_with_retry, query, server, record_type, domain): server
                for server in servers
            }
            
            for future in as_completed(future_to_server, timeout=10):
                server = future_to_server[future]
                try:
                    success, response, response_time, error = future.result()
                    if success:
                        return True, response, server, response_time
                except Exception as e:
                    if self.verbose:
                        print(f"failed to query {server}: {e}")
        
        return False, None, "", 0.0
    
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
        
        return results
    
    def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        """resolve domain to records of specified type with parallel queries"""
        self.resolution_steps = []
        
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
        max_iterations = 10
        iteration = 0
        
        while current_servers and iteration < max_iterations:
            iteration += 1
            
            # query servers in parallel
            success, response, server, response_time = self.query_servers_parallel(
                current_servers, queried_domain, record_type, 
                recursion_desired=(len(current_servers) == len(self.root_servers))
            )
            
            if not success:
                self.resolution_steps.append({
                    'server': server,
                    'domain': queried_domain,
                    'record_type': record_type,
                    'response_time': response_time,
                    'success': False,
                    'error': 'all servers failed'
                })
                raise Exception(f"failed to resolve {domain}")
            
            # record step
            results = self.parse_records(response.answers, record_type)
            authorities = self.parse_records(response.authorities, 'NS')
            additionals = []
            for additional in response.additionals:
                if additional.rtype == 1:
                    ip = additional.get_ip_address()
                    if ip:
                        additionals.append(ip)
            
            self.resolution_steps.append({
                'server': server,
                'domain': queried_domain,
                'record_type': record_type,
                'response_time': response_time,
                'success': True,
                'results': results,
                'authorities': authorities,
                'additionals': additionals
            })
            
            if self.verbose:
                print(f"querying {server} for {queried_domain} ({record_type}) - {response_time:.3f}s")
            
            # check if we got an answer
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
                return self.resolve(cname_results[0], record_type)
            
            # look for name servers in authorities
            name_servers = self.parse_records(response.authorities, 'NS')
            
            # look for ip addresses of name servers in additionals
            ns_ips = []
            for additional in response.additionals:
                if additional.rtype == 1:
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
            else:
                raise Exception(f"no name servers found for {queried_domain}")
        
        raise Exception(f"could not resolve {domain}")
    
    def print_resolution_steps(self):
        """print the resolution steps"""
        print("\n" + "="*60)
        print("dns resolution steps:")
        print("="*60)
        
        for i, step in enumerate(self.resolution_steps, 1):
            print(f"\nstep {i}:")
            print(f"  server: {step['server']}")
            print(f"  domain: {step['domain']}")
            print(f"  record type: {step['record_type']}")
            print(f"  response time: {step['response_time']:.3f}s")
            print(f"  success: {step['success']}")
            
            if step['success']:
                if step['results']:
                    print(f"  results: {step['results']}")
                if step['authorities']:
                    print(f"  authorities: {step['authorities']}")
                if step['additionals']:
                    print(f"  additionals: {step['additionals']}")
            else:
                print(f"  error: {step['error']}")
        
        print("="*60)

def main():
    """main function with advanced cli support"""
    parser = argparse.ArgumentParser(description='parallel dns resolver')
    parser.add_argument('domain', help='domain name to resolve')
    parser.add_argument('--type', '-t', default='A', 
                       choices=['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'],
                       help='dns record type (default: A)')
    parser.add_argument('--no-cache', action='store_true', 
                       help='disable caching')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='verbose output')
    parser.add_argument('--cache-file', default='dns_cache.json',
                       help='cache file path (default: dns_cache.json)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='maximum parallel workers (default: 5)')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='maximum retries per server (default: 3)')
    parser.add_argument('--show-steps', action='store_true',
                       help='show resolution steps')
    
    args = parser.parse_args()
    
    # create resolver
    resolver = ParallelDNSResolver(
        use_cache=not args.no_cache, 
        cache_file=args.cache_file,
        max_workers=args.max_workers,
        max_retries=args.max_retries
    )
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
        
        if args.show_steps:
            resolver.print_resolution_steps()
        
    except Exception as e:
        print(f"error: {e}")
        if args.show_steps and resolver.resolution_steps:
            resolver.print_resolution_steps()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 