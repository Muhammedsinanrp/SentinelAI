package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gobounty/internal/ai"
	"gobounty/internal/config"
	"gobounty/internal/httputil"
	"gobounty/internal/recon"
	"gobounty/internal/scope"
	"gobounty/internal/triage"
)

func main() {
	configPath := flag.String("config", "scope.yaml", "path to scope config")
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	failIf(err)

	switch flag.Arg(0) {
	case "status":
		status(cfg)
	case "check-scope":
		requireArgs(flag.Args(), 2)
		checkScope(cfg, flag.Arg(1))
	case "scan":
		requireArgs(flag.Args(), 2)
		scan(cfg, flag.Arg(1))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`GoBounty — AI-assisted, scope-enforced bug bounty pipeline

Usage:
  gobounty -config scope.yaml status
  gobounty check-scope <target>
  gobounty scan <target>

Environment:
  AI_BASE_URL   OpenAI-compatible endpoint (default https://api.openai.com/v1)
  AI_API_KEY    API key for the endpoint
  PROXY_URL     optional HTTP proxy, e.g. http://127.0.0.1:8080`)
}

func requireArgs(args []string, n int) {
	if len(args) < n {
		usage()
		os.Exit(2)
	}
}

func failIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func status(c *config.Config) {
	fmt.Printf("Program : %s\n", c.Program)
	fmt.Printf("In-scope: %d patterns\n", len(c.InScope))
	for _, s := range c.InScope {
		fmt.Printf("   - %s\n", s)
	}
	fmt.Printf("Exclusions: %d\n", len(c.OutOfScope))
	fmt.Printf("Rate limit: %.1f req/sec\n", c.RateLimit.RequestsPerSecond)
}

func checkScope(c *config.Config, target string) {
	ok, reason := scope.Check(target, c.InScope, c.OutOfScope)
	if ok {
		fmt.Printf("[IN SCOPE]     %s (%s)\n", target, reason)
	} else {
		fmt.Printf("[OUT OF SCOPE] %s (%s)\n", target, reason)
	}
}

func scan(c *config.Config, target string) {
	// 1. Scope gate — refuse to proceed if target is out of scope.
	ok, reason := scope.Check(target, c.InScope, c.OutOfScope)
	if !ok {
		fmt.Fprintf(os.Stderr, "ABORTED: %s is out of scope — %s\n", target, reason)
		os.Exit(1)
	}
	fmt.Printf("[✓] Scope check passed: %s\n", reason)

	// 2. Build a rate-limited HTTP client (optionally through a proxy).
	proxyURL := os.Getenv("PROXY_URL")
	httpClient, err := httputil.New(c.RateLimit.RequestsPerSecond, c.RateLimit.Burst, proxyURL)
	failIf(err)

	// 3. Normalize target into a fetchable URL.
	targetURL := scope.InScopeURL(target)
	fmt.Printf("[→] Probing %s …\n", targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 4. Passive recon.
	findings, err := recon.Probe(ctx, httpClient.Do, targetURL)
	failIf(err)

	fmt.Printf("[✓] %d finding(s) collected\n\n", len(findings))
	for i, f := range findings {
		fmt.Printf("  %d. [%s] %s\n", i+1, f.Type, f.Detail)
	}
	fmt.Println()

	// 5. Ask the AI for triage (skip if no API key is set).
	baseURL, apiKey, model := c.AIEndpoint()
	if apiKey == "" {
		fmt.Println("[!] AI_API_KEY not set — skipping AI triage.")
		writeReport(target, findings, nil)
		return
	}

	aiClient := &ai.Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Model:   model,
		MaxTok:  c.AI.MaxTokens,
		HTTP:    ai.DefaultHTTP(),
	}

	fmt.Printf("[→] Sending findings to AI model (%s) …\n", model)
	assessments, err := triage.Assess(ctx, aiClient, targetURL, findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] AI triage failed: %v — saving raw findings only\n", err)
		writeReport(target, findings, nil)
		return
	}

	fmt.Printf("[✓] AI triage complete — %d assessment(s)\n\n", len(assessments))
	for _, a := range assessments {
		fmt.Printf("  [%-13s] %s\n    → %s\n\n", a.Severity, a.Title, a.Rationale)
	}

	writeReport(target, findings, assessments)
}

// writeReport saves a plain-text report to a timestamped file in reports/.
func writeReport(target string, findings []recon.Finding, assessments []triage.Assessment) {
	if err := os.MkdirAll("reports", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] could not create reports dir: %v\n", err)
		return
	}

	ts := time.Now().Format("20060102-150405")
	// Sanitize target for use in a filename.
	safe := ""
	for _, r := range target {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			safe += string(r)
		} else {
			safe += "_"
		}
	}
	name := filepath.Join("reports", fmt.Sprintf("%s_%s.txt", ts, safe))

	f, err := os.Create(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] could not create report file: %v\n", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "GoBounty Report\n")
	fmt.Fprintf(w, "Generated : %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(w, "Target    : %s\n\n", target)

	fmt.Fprintf(w, "=== RAW FINDINGS (%d) ===\n", len(findings))
	for i, finding := range findings {
		fmt.Fprintf(w, "%d. [%s] %s\n", i+1, finding.Type, finding.Detail)
	}

	if len(assessments) > 0 {
		fmt.Fprintf(w, "\n=== AI TRIAGE (%d) ===\n", len(assessments))
		for _, a := range assessments {
			fmt.Fprintf(w, "[%-13s] %s\n  %s\n\n", a.Severity, a.Title, a.Rationale)
		}
	}

	w.Flush()
	fmt.Printf("[✓] Report saved → %s\n", name)
}
