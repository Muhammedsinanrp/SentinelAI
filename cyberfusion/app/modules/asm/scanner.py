import asyncio
import socket
import ssl
from typing import Dict, List, Any
import aiohttp
import dns.asyncresolver

COMMON_SUBDOMAINS = [
    "api", "dev", "vpn", "mail", "admin", "staging", "portal",
    "auth", "app", "cdn", "cloud", "internal", "corp"
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
    {"port": 8443, "service": "HTTPS-Alt"}
]

class ASMScanner:
    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()

        # DNS
        dns_records = await self._resolve_dns(domain)
        ips = dns_records.get("A", []) + dns_records.get("AAAA", [])

        # Ports
        target_ip = ips[0] if ips else domain
        open_ports = await self._probe_ports(target_ip)

        # Web & Tech
        web_info = await self._probe_http(domain)

        # Subdomains
        subdomains = await self._enumerate_subdomains(domain)

        return {
            "domain": domain,
            "root_domain": domain,
            "ip_addresses": ips,
            "dns_records": dns_records,
            "open_ports": open_ports,
            "technologies": web_info.get("technologies", []),
            "security_headers": web_info.get("headers", {}),
            "missing_headers": web_info.get("missing_headers", []),
            "tls_info": web_info.get("tls_info", {}),
            "discovered_subdomains": subdomains
        }

    async def _resolve_dns(self, domain: str) -> Dict[str, List[str]]:
        records = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                answers = await resolver.resolve(domain, rtype)
                for rdata in answers:
                    records[rtype].append(str(rdata).strip('"'))
            except Exception:
                pass
        return records

    async def _probe_ports(self, host: str) -> List[Dict[str, Any]]:
        async def _check(p):
            try:
                conn = asyncio.open_connection(host, p["port"])
                _, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return {"port": p["port"], "service": p["service"], "state": "open"}
            except Exception:
                return None
        res = await asyncio.gather(*[_check(p) for p in TOP_PORTS])
        return [r for r in res if r]

    async def _probe_http(self, domain: str) -> Dict[str, Any]:
        result = {"technologies": [], "headers": {}, "missing_headers": [], "tls_info": {}}
        url = f"https://{domain}"
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for u in [url, f"http://{domain}"]:
                try:
                    async with session.get(u, allow_redirects=True) as resp:
                        hdrs = {k: v for k, v in resp.headers.items()}
                        result["headers"] = hdrs
                        techs = set()
                        if s := hdrs.get("Server"): techs.add(f"Server: {s}")
                        if p := hdrs.get("X-Powered-By"): techs.add(f"Framework: {p}")
                        if "cf-ray" in hdrs: techs.add("Cloudflare CDN")
                        result["technologies"] = list(techs)
                        break
                except Exception:
                    continue
        return result

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        found = {domain}
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5

        async def _probe(sub):
            candidate = f"{sub}.{domain}"
            try:
                await resolver.resolve(candidate, "A")
                found.add(candidate)
            except Exception:
                pass
        await asyncio.gather(*[_probe(sub) for sub in COMMON_SUBDOMAINS])
        return sorted(list(found))
