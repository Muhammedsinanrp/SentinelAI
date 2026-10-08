package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Finding struct {
	Type    string
	Detail  string
	Headers map[string]string
}

// Probe fetches a target with benign GETs and collects surface data.
func Probe(ctx context.Context, do func(*http.Request) (*http.Response, error), target string) ([]Finding, error) {
	var findings []Finding

	resp, err := get(ctx, do, target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain, cap 1MB

	hdrs := map[string]string{}
	for k, v := range resp.Header {
		hdrs[k] = strings.Join(v, ", ")
	}
	findings = append(findings, Finding{Type: "http", Detail: resp.Status, Headers: hdrs})

	if v := hdrs["Server"]; v != "" {
		findings = append(findings, Finding{Type: "server", Detail: v})
	}
	for _, sec := range []string{
		"Strict-Transport-Security", "Content-Security-Policy",
		"X-Content-Type-Options", "X-Frame-Options",
	} {
		if _, ok := hdrs[sec]; !ok {
			findings = append(findings, Finding{Type: "missing-header", Detail: sec})
		}
	}

	// robots.txt discovery (in-scope only, called with authorized target)
	if r, err := get(ctx, do, strings.TrimRight(target, "/")+"/robots.txt"); err == nil {
		defer r.Body.Close()
		io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
		if r.StatusCode == http.StatusOK {
			findings = append(findings, Finding{Type: "robots", Detail: "robots.txt is exposed"})
		}
	}
	return findings, nil
}

func get(ctx context.Context, do func(*http.Request) (*http.Response, error), url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoBounty/1.0 (authorized-testing)")
	resp, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	_ = time.Now()
	return resp, nil
}
