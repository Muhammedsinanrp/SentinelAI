from urllib.parse import urlparse
from typing import List, Tuple

def extract_host(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return (parsed.hostname or "").lower()

def match_pattern(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower()
    host = host.strip().lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return pattern == host

def check_scope(target: str, in_scope: List[str], out_of_scope: List[str]) -> Tuple[bool, str]:
    try:
        host = extract_host(target)
    except Exception as e:
        return False, f"Invalid target syntax: {e}"

    if not host:
        return False, "Target contains empty hostname"

    for pat in out_of_scope:
        if match_pattern(pat, host):
            return False, f"Matches out-of-scope restriction pattern '{pat}'"

    for pat in in_scope:
        if match_pattern(pat, host):
            return True, f"Authorized under in-scope pattern '{pat}'"

    return False, f"Target '{host}' is not in authorized in-scope list"
