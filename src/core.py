#!/usr/bin/env python3
"""
CDN Resolver - Find real IPs behind CDNs (Cloudflare, etc.)

Features:
- DNS enumeration
- Historical DNS lookup
- SSL certificate analysis
- Subdomain scanning
- Mail server checking
- Multiple technique combination
"""

import argparse
import json
import re
import socket
import ssl
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
from urllib.request import urlopen, Request
from urllib.error import URLError
import concurrent.futures

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# CDN IP ranges (partial)
CDN_RANGES = {
    'cloudflare': [
        '103.21.244.', '103.22.200.', '103.31.4.', '104.16.', '104.17.',
        '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.',
        '104.24.', '104.25.', '104.26.', '104.27.', '108.162.', '131.0.72.',
        '141.101.', '162.158.', '172.64.', '172.65.', '172.66.', '172.67.',
        '173.245.', '188.114.', '190.93.', '197.234.', '198.41.'
    ],
    'aws_cloudfront': ['13.', '52.', '54.', '99.', '143.', '204.246.'],
    'fastly': ['151.101.', '199.232.'],
    'akamai': ['23.', '95.100.', '104.64.'],
}


@dataclass
class ResolveResult:
    domain: str
    cdn_detected: Optional[str]
    cdn_ips: List[str]
    real_ips: List[str]
    techniques: List[Dict]
    confidence: str


class CDNResolver:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)
        
    def resolve(self, domain: str) -> ResolveResult:
        """Attempt to find real IP behind CDN"""
        cdn_ips = []
        real_ips = []
        techniques = []
        cdn_provider = None
        
        # Step 1: Get current DNS
        print(f"{Colors.CYAN}[1/5]{Colors.RESET} Checking current DNS...")
        current_ips = self.get_dns(domain)
        for ip in current_ips:
            cdn = self.detect_cdn(ip)
            if cdn:
                cdn_provider = cdn
                cdn_ips.append(ip)
            else:
                real_ips.append(ip)
        
        if cdn_ips:
            techniques.append({
                'method': 'Current DNS',
                'result': f'CDN detected: {cdn_provider}',
                'ips': cdn_ips
            })
        
        # Step 2: Check subdomains
        print(f"{Colors.CYAN}[2/5]{Colors.RESET} Checking subdomains...")
        subdomain_ips = self.check_subdomains(domain)
        for ip, subdomain in subdomain_ips:
            if not self.detect_cdn(ip) and ip not in real_ips:
                real_ips.append(ip)
                techniques.append({
                    'method': f'Subdomain: {subdomain}',
                    'result': 'Potential origin',
                    'ips': [ip]
                })
        
        # Step 3: Check mail servers
        print(f"{Colors.CYAN}[3/5]{Colors.RESET} Checking mail servers...")
        mx_ips = self.check_mx_records(domain)
        for ip in mx_ips:
            if not self.detect_cdn(ip) and ip not in real_ips:
                real_ips.append(ip)
                techniques.append({
                    'method': 'MX Record',
                    'result': 'Mail server IP',
                    'ips': [ip]
                })
        
        # Step 4: Check TXT/SPF records
        print(f"{Colors.CYAN}[4/5]{Colors.RESET} Checking SPF records...")
        spf_ips = self.check_spf(domain)
        for ip in spf_ips:
            if not self.detect_cdn(ip) and ip not in real_ips:
                real_ips.append(ip)
                techniques.append({
                    'method': 'SPF Record',
                    'result': 'IP in SPF',
                    'ips': [ip]
                })
        
        # Step 5: SSL certificate
        print(f"{Colors.CYAN}[5/5]{Colors.RESET} Checking SSL certificate...")
        cert_info = self.check_ssl_cert(domain)
        if cert_info:
            techniques.append({
                'method': 'SSL Certificate',
                'result': cert_info,
                'ips': []
            })
        
        # Determine confidence
        if real_ips:
            confidence = 'high' if len(techniques) > 2 else 'medium'
        else:
            confidence = 'low'
        
        return ResolveResult(
            domain=domain,
            cdn_detected=cdn_provider,
            cdn_ips=cdn_ips,
            real_ips=real_ips,
            techniques=techniques,
            confidence=confidence
        )
    
    def get_dns(self, domain: str) -> List[str]:
        """Get DNS A records"""
        try:
            return socket.gethostbyname_ex(domain)[2]
        except:
            return []
    
    def detect_cdn(self, ip: str) -> Optional[str]:
        """Detect if IP belongs to known CDN"""
        for cdn, ranges in CDN_RANGES.items():
            for prefix in ranges:
                if ip.startswith(prefix):
                    return cdn
        return None
    
    def check_subdomains(self, domain: str) -> List[tuple]:
        """Check common subdomains for origin IP"""
        subdomains = [
            'direct', 'origin', 'origin-www', 'www2', 'old', 'legacy',
            'dev', 'staging', 'test', 'api', 'backend', 'server',
            'mail', 'smtp', 'ftp', 'cpanel', 'webmail', 'admin'
        ]
        
        results = []
        
        def check_sub(sub):
            subdomain = f"{sub}.{domain}"
            ips = self.get_dns(subdomain)
            return [(ip, subdomain) for ip in ips]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_sub, sub) for sub in subdomains]
            for future in concurrent.futures.as_completed(futures):
                results.extend(future.result())
        
        return results
    
    def check_mx_records(self, domain: str) -> List[str]:
        """Get IPs from MX records"""
        ips = []
        try:
            import subprocess
            result = subprocess.run(
                ['dig', '+short', 'MX', domain],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    mx_host = parts[1].rstrip('.')
                    mx_ips = self.get_dns(mx_host)
                    ips.extend(mx_ips)
        except:
            pass
        return ips
    
    def check_spf(self, domain: str) -> List[str]:
        """Extract IPs from SPF records"""
        ips = []
        try:
            import subprocess
            result = subprocess.run(
                ['dig', '+short', 'TXT', domain],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout:
                # Find ip4: entries
                for match in re.finditer(r'ip4:(\d+\.\d+\.\d+\.\d+)', line):
                    ips.append(match.group(1))
        except:
            pass
        return ips
    
    def check_ssl_cert(self, domain: str) -> Optional[str]:
        """Check SSL certificate for origin hints"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                # Check subject alternative names
                san = cert.get('subjectAltName', [])
                return f"SANs: {len(san)} entries"
        except:
            return None


def print_banner():
    print(f"""{Colors.CYAN}
   ____ ____  _   _   ____                 _                
  / ___|  _ \| \ | | |  _ \ ___  ___  ___ | |_   _____ _ __ 
 | |   | | | |  \| | | |_) / _ \/ __|/ _ \| \ \ / / _ \ '__|
 | |___| |_| | |\  | |  _ <  __/\__ \ (_) | |\ V /  __/ |   
  \____|____/|_| \_| |_| \_\___||___/\___/|_| \_/ \___|_|   
{Colors.RESET}                                            v{VERSION}
""")


def print_result(result: ResolveResult):
    """Print resolution results"""
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Domain:{Colors.RESET} {result.domain}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    # CDN Status
    if result.cdn_detected:
        print(f"\n{Colors.YELLOW}[!] CDN Detected: {result.cdn_detected.upper()}{Colors.RESET}")
        print(f"  CDN IPs: {', '.join(result.cdn_ips)}")
    else:
        print(f"\n{Colors.GREEN}[OK] No CDN detected{Colors.RESET}")
    
    # Techniques used
    print(f"\n{Colors.BOLD}Discovery Techniques:{Colors.RESET}")
    for tech in result.techniques:
        print(f"  • {tech['method']}: {tech['result']}")
        if tech['ips']:
            print(f"    IPs: {', '.join(tech['ips'])}")
    
    # Real IPs
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    if result.real_ips:
        print(f"{Colors.GREEN}{Colors.BOLD}Potential Origin IPs:{Colors.RESET}")
        for ip in result.real_ips:
            print(f"  {Colors.GREEN}->{Colors.RESET} {ip}")
        print(f"\n{Colors.BOLD}Confidence:{Colors.RESET} {result.confidence.upper()}")
    else:
        print(f"{Colors.YELLOW}No origin IPs discovered{Colors.RESET}")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
    
    demo = ResolveResult(
        domain="example.com",
        cdn_detected="cloudflare",
        cdn_ips=["104.16.123.45", "104.16.124.45"],
        real_ips=["203.0.113.50", "203.0.113.51"],
        techniques=[
            {'method': 'Current DNS', 'result': 'CDN detected: cloudflare', 'ips': ['104.16.123.45']},
            {'method': 'Subdomain: direct', 'result': 'Potential origin', 'ips': ['203.0.113.50']},
            {'method': 'MX Record', 'result': 'Mail server IP', 'ips': ['203.0.113.51']},
        ],
        confidence='high'
    )
    
    print_result(demo)


def main():
    parser = argparse.ArgumentParser(description="CDN Resolver")
    parser.add_argument("domain", nargs="?", help="Domain to resolve")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.domain:
        print(f"{Colors.YELLOW}No domain specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    resolver = CDNResolver(timeout=args.timeout)
    result = resolver.resolve(args.domain)
    print_result(result)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
