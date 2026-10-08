"""
CYBERSHIELD X - Attack Surface Scope Enforcement Gate
Guarantees authorization before executing any network discovery or scan.
"""
from urllib.parse import urlparse
import re
from typing import List, Tuple

def extract_host(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    return host.lower()

def match_pattern(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower()
    host = host.strip().lower()
    if pattern.startswith("*."):
        suffix = pattern[1:] # .example.com
        return host.endswith(suffix) and len(host) > len(suffix)
    return pattern == host

def check_scope(target: str, in_scope: List[str], out_of_scope: List[str]) -> Tuple[bool, str]:
    try:
        host = extract_host(target)
    except Exception as e:
        return False, f"Invalid target syntax: {e}"

    if not host:
        return False, "Target contains empty hostname"

    # Check out of scope exclusions first
    for pat in out_of_scope:
        if match_pattern(pat, host):
            return False, f"Matches out-of-scope restriction pattern '{pat}'"

    # Check in scope allowlist
    for pat in in_scope:
        if match_pattern(pat, host):
            return True, f"Authorized under in-scope pattern '{pat}'"

    return False, f"Target '{host}' does not match any authorized in-scope rules"

def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target.rstrip("/")
