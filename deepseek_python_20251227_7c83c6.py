#!/usr/bin/env python3
"""
REAL BUG BOUNTY RECON SCANNER v1.0
Professional reconnaissance with real techniques
"""

import asyncio
import aiohttp
import aiodns
import sys
import re
import json
import time
import socket
import ssl
import ipaddress
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import whois
import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import warnings
warnings.filterwarnings('ignore')

# ==================== REAL CONFIGURATION ====================

@dataclass
class Subdomain:
    domain: str
    ip: str
    status: int
    technology: List[str]
    ports: List[int]
    takeovers: List[str]

@dataclass
class Endpoint:
    url: str
    method: str
    parameters: Dict[str, List[str]]
    status: int
    length: int
    technology: List[str]
    sensitive: bool

class RealReconScanner:
    """Professional reconnaissance scanner"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[Subdomain] = set()
        self.endpoints: Set[Endpoint] = set()
        self.vulnerabilities: List[Dict] = []
        
        # Real wordlists
        self.subdomain_wordlist = [
            'www', 'api', 'admin', 'dashboard', 'secure', 'portal',
            'mail', 'email', 'webmail', 'smtp', 'pop', 'imap',
            'ftp', 'sftp', 'vpn', 'ssh', 'git', 'svn',
            'test', 'dev', 'stage', 'staging', 'prod', 'production',
            'mobile', 'm', 'wap', 'app', 'apps', 'application',
            'cdn', 'content', 'static', 'assets', 'media',
            'blog', 'news', 'forum', 'community', 'support',
            'shop', 'store', 'cart', 'checkout', 'payment',
            'auth', 'login', 'signin', 'register', 'account',
            'internal', 'intranet', 'private', 'secure',
            'api-docs', 'docs', 'documentation', 'help'
        ]
        
        # Common ports
        self.common_ports = [80, 443, 8080, 8443, 3000, 8000, 8888]
        
        # Technology fingerprints
        self.tech_fingerprints = {
            'wordpress': ['wp-content', 'wp-includes', '/wp-admin/'],
            'joomla': ['/media/system/', '/components/com_'],
            'drupal': ['/sites/default/', '/modules/node/'],
            'laravel': ['/vendor/laravel/', 'csrf-token'],
            'react': ['__reactInternalInstance', 'react-root'],
            'vue': ['__vue__', 'vue-app'],
            'nginx': ['nginx/', 'X-Powered-By: nginx'],
            'apache': ['Apache/', 'X-Powered-By: Apache'],
            'cloudflare': ['__cfduid', 'cf-ray', 'server: cloudflare'],
            'aws': ['aws', 'amazonaws.com', 'X-Amz-'],
            'azure': ['azure', 'windows.net', 'X-AspNet']
        }
    
    async def full_recon(self):
        """Complete reconnaissance workflow"""
        print(f"[*] Starting reconnaissance on: {self.domain}")
        print(f"[*] Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 1. Subdomain enumeration
        print(f"\n[1] Subdomain Enumeration")
        await self.enumerate_subdomains()
        
        # 2. Port scanning
        print(f"\n[2] Port Scanning")
        await self.scan_ports()
        
        # 3. Technology detection
        print(f"\n[3] Technology Detection")
        await self.detect_technologies()
        
        # 4. Endpoint discovery
        print(f"\n[4] Endpoint Discovery")
        await self.discover_endpoints()
        
        # 5. Vulnerability checks
        print(f"\n[5] Vulnerability Checks")
        await self.check_vulnerabilities()
        
        # 6. Generate report
        print(f"\n[6] Report Generation")
        self.generate_report()
    
    async def enumerate_subdomains(self):
        """Real subdomain enumeration techniques"""
        methods = [
            self._subdomain_bruteforce,
            self._subdomain_crtsh,
            self._subdomain_dns,
            self._subdomain_securitytrails
        ]
        
        for method in methods:
            try:
                subs = await method()
                for sub in subs:
                    self.subdomains.add(sub)
                print(f"  [+] {method.__name__}: Found {len(subs)} subdomains")
            except Exception as e:
                print(f"  [-] {method.__name__}: Error - {e}")
    
    async def _subdomain_bruteforce(self) -> List[Subdomain]:
        """Brute-force subdomains dengan wordlist"""
        found = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for word in self.subdomain_wordlist:
                subdomain = f"{word}.{self.domain}"
                task = self._check_subdomain(session, subdomain)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Subdomain):
                    found.append(result)
        
        return found
    
    async def _check_subdomain(self, session: aiohttp.ClientSession, 
                              subdomain: str) -> Optional[Subdomain]:
        """Check if subdomain exists"""
        try:
            # Check HTTP
            async with session.get(f"http://{subdomain}", 
                                  timeout=5, ssl=False) as resp:
                if resp.status < 400:
                    return Subdomain(
                        domain=subdomain,
                        ip=await self._resolve_ip(subdomain),
                        status=resp.status,
                        technology=[],
                        ports=[],
                        takeovers=[]
                    )
        except:
            pass
        
        try:
            # Check HTTPS
            async with session.get(f"https://{subdomain}", 
                                  timeout=5, ssl=False) as resp:
                if resp.status < 400:
                    return Subdomain(
                        domain=subdomain,
                        ip=await self._resolve_ip(subdomain),
                        status=resp.status,
                        technology=[],
                        ports=[],
                        takeovers=[]
                    )
        except:
            pass
        
        return None
    
    async def _resolve_ip(self, domain: str) -> str:
        """Resolve domain to IP"""
        try:
            resolver = aiodns.DNSResolver()
            result = await resolver.query(domain, 'A')
            return result[0].host if result else "N/A"
        except:
            return "N/A"
    
    async def _subdomain_crtsh(self) -> List[Subdomain]:
        """Query crt.sh for subdomains"""
        found = []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            names = name_value.split('\n')
                            
                            for name in names:
                                if self.domain in name and '*' not in name:
                                    sub = name.strip()
                                    if sub not in [s.domain for s in found]:
                                        found.append(Subdomain(
                                            domain=sub,
                                            ip=await self._resolve_ip(sub),
                                            status=0,
                                            technology=[],
                                            ports=[],
                                            takeovers=[]
                                        ))
        except Exception as e:
            print(f"    [-] crt.sh error: {e}")
        
        return found
    
    async def scan_ports(self):
        """Scan common ports on discovered subdomains"""
        for subdomain in list(self.subdomains)[:10]:  # Limit untuk demo
            if subdomain.ip != "N/A":
                open_ports = []
                
                for port in self.common_ports:
                    if await self._check_port(subdomain.ip, port):
                        open_ports.append(port)
                
                if open_ports:
                    # Update subdomain with ports
                    subdomain.ports = open_ports
                    print(f"  [+] {subdomain.domain}: Ports {open_ports}")
    
    async def _check_port(self, ip: str, port: int) -> bool:
        """Check if port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def detect_technologies(self):
        """Detect technologies on web servers"""
        for subdomain in list(self.subdomains)[:5]:  # Limit untuk demo
            if subdomain.status < 400:
                techs = await self._detect_tech(subdomain.domain)
                if techs:
                    subdomain.technology = techs
                    print(f"  [+] {subdomain.domain}: {', '.join(techs[:3])}")
    
    async def _detect_tech(self, domain: str) -> List[str]:
        """Detect web technologies"""
        detected = []
        urls = [f"http://{domain}", f"https://{domain}"]
        
        async with aiohttp.ClientSession() as session:
            for url in urls:
                try:
                    async with session.get(url, timeout=5, ssl=False) as resp:
                        headers = dict(resp.headers)
                        body = await resp.text()
                        
                        # Check headers
                        for tech, patterns in self.tech_fingerprints.items():
                            for pattern in patterns:
                                if any(pattern.lower() in str(h).lower() 
                                      for h in headers.values()):
                                    if tech not in detected:
                                        detected.append(tech)
                                
                                if pattern.lower() in body.lower():
                                    if tech not in detected:
                                        detected.append(tech)
                        
                        # Check common headers
                        server = headers.get('server', '').lower()
                        powered = headers.get('x-powered-by', '').lower()
                        
                        if 'nginx' in server:
                            detected.append('nginx')
                        if 'apache' in server:
                            detected.append('apache')
                        if 'php' in powered:
                            detected.append('php')
                        if 'asp.net' in powered:
                            detected.append('asp.net')
                        
                        # Check cookies
                        cookies = headers.get('set-cookie', '')
                        if 'wordpress' in cookies.lower():
                            detected.append('wordpress')
                        if 'joomla' in cookies.lower():
                            detected.append('joomla')
                
                except:
                    continue
        
        return list(set(detected))
    
    async def discover_endpoints(self):
        """Discover endpoints from main domain"""
        urls_to_crawl = [f"https://{self.domain}", f"http://{self.domain}"]
        crawled = set()
        
        for url in urls_to_crawl:
            endpoints = await self._crawl_site(url, crawled, depth=2)
            self.endpoints.update(endpoints)
    
    async def _crawl_site(self, url: str, crawled: Set[str], 
                         depth: int = 2) -> Set[Endpoint]:
        """Crawl website for endpoints"""
        if depth == 0 or url in crawled:
            return set()
        
        crawled.add(url)
        endpoints = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        
                        # Create endpoint for this URL
                        parsed = urlparse(url)
                        params = self._extract_params(url)
                        
                        endpoint = Endpoint(
                            url=url,
                            method="GET",
                            parameters=params,
                            status=resp.status,
                            length=len(body),
                            technology=await self._detect_tech(parsed.netloc),
                            sensitive=self._is_sensitive(url, params)
                        )
                        endpoints.add(endpoint)
                        
                        # Extract links for further crawling
                        if depth > 1:
                            links = self._extract_links(body, url)
                            
                            for link in links[:10]:  # Limit links
                                if link not in crawled:
                                    sub_endpoints = await self._crawl_site(
                                        link, crawled, depth-1
                                    )
                                    endpoints.update(sub_endpoints)
        
        except Exception as e:
            pass
        
        return endpoints
    
    def _extract_params(self, url: str) -> Dict[str, List[str]]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
        
        return params
    
    def _is_sensitive(self, url: str, params: Dict) -> bool:
        """Check if endpoint is sensitive"""
        sensitive_paths = [
            '/admin', '/dashboard', '/login', '/register', '/api',
            '/config', '/backup', '/sql', '/db', '/phpmyadmin',
            '/wp-admin', '/administrator', '/console'
        ]
        
        sensitive_params = [
            'password', 'pass', 'pwd', 'token', 'key', 'secret',
            'auth', 'access', 'admin', 'debug', 'test'
        ]
        
        # Check path
        for path in sensitive_paths:
            if path in url.lower():
                return True
        
        # Check parameters
        for param in params.keys():
            if any(sp in param.lower() for sp in sensitive_params):
                return True
        
        return False
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            href = tag.get('href') or tag.get('src') or tag.get('action')
            
            if href:
                # Resolve relative URLs
                absolute = urljoin(base_url, href)
                
                # Filter out external links and fragments
                if self.domain in absolute and '#' not in absolute:
                    links.append(absolute)
        
        return list(set(links))
    
    async def check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        print(f"  [*] Checking for common vulnerabilities...")
        
        # Check each endpoint
        for endpoint in list(self.endpoints)[:20]:  # Limit untuk demo
            vulns = await self._check_endpoint_vulns(endpoint)
            self.vulnerabilities.extend(vulns)
    
    async def _check_endpoint_vulns(self, endpoint: Endpoint) -> List[Dict]:
        """Check vulnerabilities for single endpoint"""
        vulns = []
        
        # 1. Check for IDOR patterns
        if self._check_idor_pattern(endpoint):
            vulns.append({
                'type': 'IDOR',
                'endpoint': endpoint.url,
                'confidence': 0.7,
                'evidence': 'Numeric ID in parameter'
            })
        
        # 2. Check for SQLi potential
        if self._check_sqli_potential(endpoint):
            vulns.append({
                'type': 'SQL Injection Potential',
                'endpoint': endpoint.url,
                'confidence': 0.6,
                'evidence': 'SQL-related parameters'
            })
        
        # 3. Check for XSS potential
        if self._check_xss_potential(endpoint):
            vulns.append({
                'type': 'XSS Potential',
                'endpoint': endpoint.url,
                'confidence': 0.6,
                'evidence': 'Reflection parameters present'
            })
        
        # 4. Check for sensitive data exposure
        if endpoint.sensitive:
            vulns.append({
                'type': 'Sensitive Endpoint',
                'endpoint': endpoint.url,
                'confidence': 0.8,
                'evidence': 'Admin/API endpoint discovered'
            })
        
        return vulns
    
    def _check_idor_pattern(self, endpoint: Endpoint) -> bool:
        """Check for IDOR patterns"""
        id_patterns = ['id', 'user', 'account', 'uid', 'pid', 'docid']
        
        for param in endpoint.parameters.keys():
            if any(pattern in param.lower() for pattern in id_patterns):
                return True
        
        return False
    
    def _check_sqli_potential(self, endpoint: Endpoint) -> bool:
        """Check for SQLi potential"""
        sql_patterns = ['id', 'select', 'query', 'search', 'filter', 'sort']
        
        for param in endpoint.parameters.keys():
            if any(pattern in param.lower() for pattern in sql_patterns):
                return True
        
        return False
    
    def _check_xss_potential(self, endpoint: Endpoint) -> bool:
        """Check for XSS potential"""
        xss_patterns = ['q', 'search', 'query', 'term', 'message', 'comment']
        
        for param in endpoint.parameters.keys():
            if any(pattern in param.lower() for pattern in xss_patterns):
                return True
        
        return False
    
    def generate_report(self):
        """Generate professional recon report"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"recon_{self.domain}_{timestamp}.json"
        
        report = {
            'domain': self.domain,
            'timestamp': timestamp,
            'subdomains': [asdict(s) for s in self.subdomains],
            'endpoints': [asdict(e) for e in self.endpoints],
            'vulnerabilities': self.vulnerabilities,
            'statistics': {
                'total_subdomains': len(self.subdomains),
                'total_endpoints': len(self.endpoints),
                'total_vulnerabilities': len(self.vulnerabilities),
                'unique_technologies': list(set(
                    tech for s in self.subdomains for tech in s.technology
                ))
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved: {filename}")
        print(f"[+] Subdomains found: {len(self.subdomains)}")
        print(f"[+] Endpoints found: {len(self.endpoints)}")
        print(f"[+] Potential vulnerabilities: {len(self.vulnerabilities)}")

# ==================== REAL VULNERABILITY SCANNER ====================

class RealVulnerabilityScanner:
    """Real vulnerability scanner (focused on specific vulnerabilities)"""
    
    def __init__(self):
        self.session = None
        self.results = []
        
        # Real SQL error patterns
        self.sql_errors = {
            'mysql': [
                r"you have an error in your sql syntax",
                r"warning: mysql",
                r"MySQL server version",
                r"mysqli?_.*error",
                r"SQL syntax.*MySQL"
            ],
            'postgres': [
                r"PostgreSQL.*ERROR",
                r"pg_.*error",
                r"PSQLException",
                r"org\.postgresql\.util\.PSQLException"
            ],
            'oracle': [
                r"ORA-\d{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"oracle\.jdbc"
            ],
            'mssql': [
                r"Microsoft OLE DB Provider",
                r"SQL Server.*Driver",
                r"System\.Data\.SqlClient\.SqlException",
                r"Unclosed quotation mark"
            ]
        }
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*</script>",
            r"onerror\s*=",
            r"onload\s*=",
            r"onmouseover\s*=",
            r"javascript:",
            r"data:text/html"
        ]
    
    async def scan_sql_injection(self, url: str, param: str) -> Dict:
        """Real SQL injection scanning"""
        print(f"[*] Testing SQLi: {url} - Parameter: {param}")
        
        test_cases = [
            # Error-based
            {"payload": "'", "type": "error", "expected": "syntax"},
            {"payload": "\"", "type": "error", "expected": "syntax"},
            {"payload": "' OR '1'='1", "type": "boolean", "expected": "true"},
            {"payload": "' AND '1'='2", "type": "boolean", "expected": "false"},
            
            # Time-based
            {"payload": "' OR SLEEP(5)--", "type": "time", "expected": "delay"},
            {"payload": "') OR SLEEP(5)--", "type": "time", "expected": "delay"},
            
            # Union-based
            {"payload": "' UNION SELECT NULL--", "type": "union", "expected": "union"},
            {"payload": "' UNION SELECT NULL,NULL--", "type": "union", "expected": "union"}
        ]
        
        vulnerabilities = []
        
        for test in test_cases:
            result = await self._test_sqli_case(url, param, test)
            if result['vulnerable']:
                vulnerabilities.append(result)
        
        if len(vulnerabilities) >= 2:  # Need multiple confirmations
            confidence = self._calculate_confidence(vulnerabilities)
            
            if confidence >= 0.8:
                return {
                    'vulnerable': True,
                    'confidence': confidence,
                    'evidence': vulnerabilities,
                    'url': url,
                    'parameter': param,
                    'type': 'SQL Injection'
                }
        
        return {'vulnerable': False}
    
    async def _test_sqli_case(self, url: str, param: str, test: Dict) -> Dict:
        """Test single SQLi test case"""
        from urllib.parse import urlencode, urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return {'vulnerable': False}
        
        # Prepare test URL
        test_params = params.copy()
        test_params[param] = [test['payload']]
        test_query = urlencode(test_params, doseq=True)
        
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        try:
            start_time = time.time()
            
            timeout = 15 if test['type'] == 'time' else 10
            async with self.session.get(test_url, timeout=timeout) as resp:
                response_time = time.time() - start_time
                content = await resp.text()
                
                # Analyze response
                analysis = self._analyze_sqli_response(
                    content, response_time, test['type']
                )
                
                if analysis['vulnerable']:
                    return {
                        'vulnerable': True,
                        'type': test['type'],
                        'payload': test['payload'],
                        'response_time': response_time,
                        'evidence': analysis['evidence']
                    }
        
        except asyncio.TimeoutError:
            if test['type'] == 'time':
                return {
                    'vulnerable': True,
                    'type': 'time',
                    'payload': test['payload'],
                    'response_time': 15,
                    'evidence': ['Request timeout on SLEEP payload']
                }
        
        return {'vulnerable': False}
    
    def _analyze_sqli_response(self, content: str, response_time: float, 
                              test_type: str) -> Dict:
        """Analyze SQLi response"""
        evidence = []
        vulnerable = False
        
        # Check for SQL errors
        for db_type, patterns in self.sql_errors.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    evidence.append(f"SQL error ({db_type}): {pattern}")
                    vulnerable = True
        
        # Check for time-based delays
        if test_type == 'time' and response_time > 5:
            evidence.append(f"Time delay: {response_time:.2f}s")
            vulnerable = True
        
        # Check for content differences (simplified)
        if len(content) < 100 or len(content) > 10000:
            # This is just an example - real implementation would compare with baseline
            evidence.append("Content length anomaly")
            vulnerable = True
        
        return {
            'vulnerable': vulnerable,
            'evidence': evidence
        }
    
    def _calculate_confidence(self, vulnerabilities: List[Dict]) -> float:
        """Calculate confidence score"""
        if not vulnerabilities:
            return 0.0
        
        scores = []
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'error':
                scores.append(0.9)  # High confidence for error-based
            elif vuln['type'] == 'time':
                scores.append(0.8)  # Good confidence for time-based
            elif vuln['type'] == 'boolean':
                scores.append(0.7)  # Moderate confidence for boolean
            elif vuln['type'] == 'union':
                scores.append(0.6)  # Lower confidence for union
        
        return sum(scores) / len(scores)

# ==================== MAIN EXECUTION ====================

async def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real Bug Bounty Scanner')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-m', '--mode', choices=['recon', 'scan'], 
                       default='recon', help='Scanning mode')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    print(f"""
    ╔══════════════════════════════════════════╗
    ║     REAL BUG BOUNTY SCANNER v1.0         ║
    ║     No Bullshit • Professional Grade     ║
    ╚══════════════════════════════════════════╝
    
    Target: {args.domain}
    Mode: {args.mode}
    Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
    """)
    
    if args.mode == 'recon':
        # Run reconnaissance
        scanner = RealReconScanner(args.domain)
        await scanner.full_recon()
    
    elif args.mode == 'scan':
        # Run vulnerability scanning
        vuln_scanner = RealVulnerabilityScanner()
        
        # Example URL for testing
        test_url = f"http://{args.domain}/test.php?id=1"
        
        async with aiohttp.ClientSession() as session:
            vuln_scanner.session = session
            result = await vuln_scanner.scan_sql_injection(test_url, 'id')
            
            if result['vulnerable']:
                print(f"\n[!] VULNERABILITY FOUND!")
                print(f"    Type: {result['type']}")
                print(f"    Confidence: {result['confidence']:.1%}")
                print(f"    URL: {result['url']}")
                print(f"    Parameter: {result['parameter']}")
                print(f"    Evidence: {result['evidence']}")

if __name__ == "__main__":
    asyncio.run(main())