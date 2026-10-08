"""
CYBERSHIELD X - Attack Surface Discovery Engine
Performs Subdomain enumeration, DNS mapping, TLS inspection, Security Header auditing, and Port probing.
"""
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import aiohttp
import dns.asyncresolver
import dns.resolver

COMMON_SUBDOMAINS = [
    "api", "dev", "vpn", "mail", "admin", "staging", "portal",
    "auth", "app", "cdn", "test", "demo", "status", "webmail", "remote"
]

TOP_PORTS = [
    {"port": 21, "service": "FTP"},
    {"port": 22, "service": "SSH"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 80, "service": "HTTP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 3306, "service": "MySQL"},
    {"port": 3389, "service": "RDP"},
    {"port": 5432, "service": "PostgreSQL"},
    {"port": 6379, "service": "Redis"},
    {"port": 8080, "service": "HTTP-Proxy/Alt"},
    {"port": 8443, "service": "HTTPS-Alt"},
    {"port": 9200, "service": "Elasticsearch"}
]

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

class ASMScanner:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def scan_domain(self, domain: str, discover_subdomains: bool = True) -> Dict[str, Any]:
        """
        Executes unified attack surface mapping on a domain.
        """
        domain = domain.strip().lower()

        # 1. DNS Resolution
        dns_data = await self.resolve_dns(domain)
        ips = dns_data.get("A", []) + dns_data.get("AAAA", [])

        # 2. Port Probing
        target_ip = ips[0] if ips else domain
        open_ports = await self.probe_ports(target_ip)

        # 3. TLS Certificate Analysis
        tls_info = await self.analyze_tls(domain)

        # 4. HTTP Surface & Security Headers
        http_info = await self.probe_http(domain)

        # 5. Subdomain Enumeration
        subdomains = [domain]
        if discover_subdomains:
            found = await self.enumerate_subdomains(domain)
            for sub in found:
                if sub not in subdomains:
                    subdomains.append(sub)

        return {
            "domain": domain,
            "root_domain": domain,
            "ip_addresses": ips,
            "dns_records": dns_data,
            "open_ports": open_ports,
            "tls_info": tls_info,
            "security_headers": http_info.get("headers", {}),
            "missing_headers": http_info.get("missing_headers", []),
            "technologies": http_info.get("technologies", []),
            "status_code": http_info.get("status_code"),
            "discovered_subdomains": subdomains
        }

    async def resolve_dns(self, domain: str) -> Dict[str, List[str]]:
        records = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                answers = await resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = str(rdata).strip('"')
                    if rtype == "MX":
                        val = str(rdata.exchange).rstrip(".")
                    elif rtype in ("NS", "CNAME"):
                        val = val.rstrip(".")
                    records[rtype].append(val)
            except Exception:
                pass
        return records

    async def probe_single_port(self, host: str, port_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        port = port_info["port"]
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return {
                "port": port,
                "service": port_info["service"],
                "state": "open",
                "transport": "tcp"
            }
        except Exception:
            return None

    async def probe_ports(self, host: str) -> List[Dict[str, Any]]:
        tasks = [self.probe_single_port(host, p) for p in TOP_PORTS]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def analyze_tls(self, domain: str) -> Dict[str, Any]:
        loop = asyncio.get_running_loop()
        def _check_ssl():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "cert": cert,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "tls_version": version
                    }
        try:
            res = await loop.run_in_executor(None, _check_ssl)
            cert = res.get("cert") or {}
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            san = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]

            return {
                "common_name": subject.get("commonName", domain),
                "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                "valid_until": not_after,
                "tls_version": res.get("tls_version"),
                "cipher": res.get("cipher"),
                "subject_alt_names": san[:10]
            }
        except Exception as e:
            return {"error": str(e), "tls_supported": False}

    async def probe_http(self, domain: str) -> Dict[str, Any]:
        url = f"https://{domain}"
        result = {
            "status_code": 0,
            "headers": {},
            "missing_headers": [],
            "technologies": []
        }
        headers = {"User-Agent": "CyberShield-X/2.0 (Security-Operations-Agent)"}
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Try HTTPS, fallback to HTTP if needed
            for target_url in [url, f"http://{domain}"]:
                try:
                    async with session.get(target_url, headers=headers, allow_redirects=True) as resp:
                        result["status_code"] = resp.status
                        hdrs = {k: v for k, v in resp.headers.items()}
                        result["headers"] = hdrs

                        # Missing headers check
                        missing = []
                        for sec_h in REQUIRED_SECURITY_HEADERS:
                            if not any(k.lower() == sec_h.lower() for k in hdrs.keys()):
                                missing.append(sec_h)
                        result["missing_headers"] = missing

                        # Tech fingerprinting
                        techs = set()
                        server = hdrs.get("Server") or hdrs.get("server")
                        if server:
                            techs.add(f"Server: {server}")
                        powered = hdrs.get("X-Powered-By")
                        if powered:
                            techs.add(f"Framework: {powered}")
                        if "cf-ray" in hdrs:
                            techs.add("Cloudflare CDN")
                        if "x-amz-cf-id" in hdrs:
                            techs.add("AWS CloudFront")

                        body_sample = (await resp.text())[:1500].lower()
                        if "wordpress" in body_sample:
                            techs.add("WordPress")
                        if "react" in body_sample or "react-dom" in body_sample:
                            techs.add("React.js")
                        if "next.js" in body_sample:
                            techs.add("Next.js")

                        result["technologies"] = list(techs)
                        break
                except Exception:
                    continue
        return result

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        found = set()

        # Method 1: Query Certificate Transparency (crt.sh)
        try:
            crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3.5)) as session:
                async with session.get(crt_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data[:30]:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(domain) and "*" not in sub:
                                    found.add(sub)
        except Exception:
            pass

        # Method 2: Active DNS probe for common subdomains
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5

        async def _check_sub(sub_prefix: str):
            candidate = f"{sub_prefix}.{domain}"
            try:
                await resolver.resolve(candidate, "A")
                found.add(candidate)
            except Exception:
                pass

        await asyncio.gather(*[_check_sub(sub) for sub in COMMON_SUBDOMAINS])
        return sorted(list(found))
