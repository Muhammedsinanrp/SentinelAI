package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gobounty/internal/ai"
	"gobounty/internal/recon"
)

type Assessment struct {
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Rationale string `json:"rationale"`
}

const systemPrompt = `You are a bug bounty triage analyst. You receive raw recon findings
from an authorized, in-scope target. For each finding, assess severity
(informational/low/medium/high), give a short title, and explain the
rationale. Respond ONLY with a JSON array of objects with keys:
severity, title, rationale.`

// Assess sends findings to the AI model and parses the verdicts.
func Assess(ctx context.Context, client *ai.Client, target string, findings []recon.Finding) ([]Assessment, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Target: %s\n\nFindings:\n", target)
	for i, f := range findings {
		fmt.Fprintf(&sb, "%d. [%s] %s\n", i+1, f.Type, f.Detail)
	}

	reply, err := client.Chat(ctx, systemPrompt, sb.String())
	if err != nil {
		return nil, err
	}
	start, end := strings.Index(reply, "["), strings.LastIndex(reply, "]")
	if start < 0 || end < start {
		return nil, fmt.Errorf("AI response is not a JSON array: %.200s", reply)
	}
	var out []Assessment
	if err := json.Unmarshal([]byte(reply[start:end+1]), &out); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	return out, nil
}
