#!/usr/bin/env python3
"""
simple test script for the dns resolver
"""

from dns_resolver import DNSResolver

def test_simple_resolution():
    """test basic domain resolution"""
    resolver = DNSResolver()
    
    # test with a simple domain
    domain = "dns.google.com"
    print(f"testing resolution of {domain}")
    
    try:
        ips = resolver.resolve(domain)
        print(f"success! ip addresses: {ips}")
        return True
    except Exception as e:
        print(f"failed: {e}")
        return False

def test_multiple_domains():
    """test resolution of multiple domains"""
    resolver = DNSResolver()
    
    test_domains = [
        "google.com",
        "github.com", 
        "stackoverflow.com",
        "example.com"
    ]
    
    results = {}
    
    for domain in test_domains:
        print(f"\ntesting {domain}...")
        try:
            ips = resolver.resolve(domain)
            results[domain] = ips
            print(f"✓ {domain} -> {ips}")
        except Exception as e:
            results[domain] = None
            print(f"✗ {domain} -> failed: {e}")
    
    return results

if __name__ == "__main__":
    print("dns resolver test")
    print("=" * 50)
    
    # run simple test
    print("\n1. simple resolution test:")
    test_simple_resolution()
    
    # run multiple domain test
    print("\n2. multiple domain test:")
    test_multiple_domains()
    
    print("\ntest completed!") 