package scope

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Check reports whether a raw target (URL or domain) is authorized.
// It matches against both in-scope and out-of-scope glob patterns.
func Check(target string, inScope, outOfScope []string) (bool, string) {
	host, err := extractHost(target)
	if err != nil {
		return false, fmt.Sprintf("invalid target: %v", err)
	}
	for _, pat := range outOfScope {
		if match(pat, host) {
			return false, "matches out-of-scope exclusion"
		}
	}
	for _, pat := range inScope {
		if match(pat, host) {
			return true, fmt.Sprintf("matches in-scope pattern %q", pat)
		}
	}
	return false, "does not match any in-scope pattern"
}

func extractHost(target string) (string, error) {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot parse %q", target)
	}
	return strings.ToLower(u.Hostname()), nil
}

// match supports "sub.example.com" and "*.example.com" wildcards.
func match(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

// InScopeURL normalizes a target into a fetchable URL.
func InScopeURL(target string) string {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, _ := url.Parse(target)
	return path.Clean(u.String())
}
