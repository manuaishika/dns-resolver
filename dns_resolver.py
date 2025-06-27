import socket
import struct
import random
import time
from typing import List, Tuple, Optional

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
        self.qtype = qtype  # 1 for a record
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
    
    def get_name_server(self) -> Optional[str]:
        """extract name server from ns record data"""
        if self.rtype == 2:  # ns record
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
    """dns resolver implementation"""
    
    def __init__(self):
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
    
    def create_query(self, domain: str, recursion_desired: bool = True) -> DNSMessage:
        """create a dns query message"""
        flags = 0x0100 if recursion_desired else 0x0000  # recursion desired flag
        header = DNSHeader(flags=flags)
        question = DNSQuestion(domain)
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
    
    def resolve(self, domain: str) -> List[str]:
        """resolve domain to ip addresses"""
        print(f"resolving {domain}...")
        
        # start with root servers
        current_servers = self.root_servers.copy()
        queried_domain = domain
        
        while current_servers:
            for server in current_servers:
                try:
                    print(f"querying {server} for {queried_domain}")
                    
                    # create query (no recursion for root/authoritative servers)
                    recursion = len(current_servers) == len(self.root_servers)  # only recursive for first query
                    query = self.create_query(queried_domain, recursion_desired=recursion)
                    
                    # send query
                    response = self.send_query(query, server)
                    
                    # check if we got an answer
                    ip_addresses = []
                    for answer in response.answers:
                        if answer.rtype == 1:  # a record
                            ip = answer.get_ip_address()
                            if ip:
                                ip_addresses.append(ip)
                    
                    if ip_addresses:
                        print(f"found ip addresses: {ip_addresses}")
                        return ip_addresses
                    
                    # look for name servers in authorities
                    name_servers = []
                    for authority in response.authorities:
                        if authority.rtype == 2:  # ns record
                            ns_name = authority.get_name_server()
                            if ns_name:
                                name_servers.append(ns_name)
                    
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
                                ns_ips.extend(self.resolve(ns_name))
                            except Exception as e:
                                print(f"failed to resolve {ns_name}: {e}")
                    
                    if ns_ips:
                        current_servers = ns_ips
                        break
                    
                except Exception as e:
                    print(f"failed to query {server}: {e}")
                    continue
            else:
                # if we get here, all servers failed
                raise Exception(f"failed to resolve {domain}")
        
        raise Exception(f"could not resolve {domain}")

def main():
    """main function to test the dns resolver"""
    resolver = DNSResolver()
    
    # test with google's dns server
    test_domains = [
        'dns.google.com',
        'google.com',
        'github.com',
        'stackoverflow.com'
    ]
    
    for domain in test_domains:
        try:
            print(f"\n{'='*50}")
            print(f"testing resolution of: {domain}")
            print(f"{'='*50}")
            
            start_time = time.time()
            ips = resolver.resolve(domain)
            end_time = time.time()
            
            print(f"resolution completed in {end_time - start_time:.2f} seconds")
            print(f"ip addresses: {ips}")
            
        except Exception as e:
            print(f"error resolving {domain}: {e}")
        
        print()

if __name__ == "__main__":
    main() 