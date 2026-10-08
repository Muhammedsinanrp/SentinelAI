# SentinelAI — AI-Assisted Bug Bounty Pipeline

> Scope-enforced, rate-limited recon + GPT-powered triage in a single Go binary.

## Features

- ✅ **Scope gate** — refuses to probe out-of-scope targets
- 🔍 **Passive recon** — HTTP headers, missing security headers, robots.txt
- 🤖 **AI triage** — sends findings to any OpenAI-compatible model for severity rating
- 🐢 **Rate limiting** — configurable req/sec + burst to stay within program rules
- 🌐 **Proxy support** — route traffic through Burp Suite or any HTTP proxy
- 📄 **Auto reports** — timestamped plain-text reports saved to `reports/`

## Install

### Prerequisites
- Go 1.22+

```bash
git clone https://github.com/Muhammedsinanrp/SentinelAI.git
cd SentinelAI
go mod tidy
go build -o sentinelai .
```

## Usage

### Set environment variables
```bash
export AI_API_KEY="your-openai-api-key"
export AI_BASE_URL="https://api.openai.com/v1"   # default
export PROXY_URL="http://127.0.0.1:8080"          # optional
```

### Commands
```bash
# Show current scope config
./sentinelai status

# Check if a target is in scope
./sentinelai check-scope httpbin.org

# Full scan: recon + AI triage + report
./sentinelai scan httpbin.org

# Use a custom scope file
./sentinelai -config my-scope.yaml scan target.com
```

## Configuration — `scope.yaml`

```yaml
program: "Demo Program (Live Sandbox)"
in_scope:
  - "httpbin.org"
  - "*.httpbin.org"
  - "example.com"
out_of_scope:
  - "status.example.com"
rate_limit:
  requests_per_second: 2
  burst: 5
ai:
  model: "gpt-4o-mini"
  max_tokens: 1024
```

## Project Structure

```
.
├── main.go                  # CLI entrypoint
├── scope.yaml               # Scope + rate-limit + AI config
├── go.mod
└── internal/
    ├── config/config.go     # YAML config loader
    ├── scope/scope.go       # Wildcard scope gate
    ├── httputil/client.go   # Rate-limited HTTP client
    ├── ai/ai.go             # OpenAI-compatible chat client
    ├── recon/recon.go       # Passive HTTP recon
    └── triage/triage.go     # AI-powered triage
```

## AI Triage Output Example

```
[high        ] Missing Strict-Transport-Security Header
  → HSTS is not enforced, allowing downgrade attacks.

[informational] robots.txt Exposed
  → Disallow paths may reveal hidden endpoints.
```

## ⚠️ Legal Notice

This tool is intended **only** for authorized bug bounty testing on in-scope targets.
Unauthorized use against systems you do not have permission to test is illegal.

## License

MIT

