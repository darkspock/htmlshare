package htmlshare

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

type AbuseCase struct {
	Reason           string `json:"reason"`
	Details          string `json:"details"`
	PublicationTitle string `json:"publication_title"`
	PublicationSlug  string `json:"publication_slug"`
	ReporterEmail    string `json:"reporter_email"`
}

type AbuseDecision struct {
	Severity string `json:"severity"`
	Block    bool   `json:"block"`
	Summary  string `json:"summary"`
}

type AbuseAnalyzer interface {
	AnalyzeAbuse(AbuseCase) AbuseDecision
}

type HybridAbuseAnalyzer struct {
	Endpoint string
	APIKey   string
}

func NewAbuseAnalyzerFromEnv() AbuseAnalyzer {
	return HybridAbuseAnalyzer{
		Endpoint: os.Getenv("ABUSE_LLM_ENDPOINT"),
		APIKey:   os.Getenv("ABUSE_LLM_API_KEY"),
	}
}

func (a HybridAbuseAnalyzer) AnalyzeAbuse(input AbuseCase) AbuseDecision {
	if a.Endpoint != "" && a.APIKey != "" {
		if decision, ok := a.callLLM(input); ok {
			return normalizeDecision(decision)
		}
	}
	return heuristicAbuseDecision(input)
}

func (a HybridAbuseAnalyzer) callLLM(input AbuseCase) (AbuseDecision, bool) {
	payload, _ := json.Marshal(map[string]any{
		"task": "Analyze an abuse report for an HTML file sharing service. Return strict JSON with severity one of low, medium, high, critical; block boolean; summary string. Block only clear phishing, malware, scams, credential theft, harassment, doxxing, illegal content, or repeated spam.",
		"case": input,
	})
	req, err := http.NewRequest(http.MethodPost, a.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return AbuseDecision{}, false
	}
	req.Header.Set("authorization", "Bearer "+a.APIKey)
	req.Header.Set("content-type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return AbuseDecision{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AbuseDecision{}, false
	}
	var decision AbuseDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return AbuseDecision{}, false
	}
	return decision, true
}

func heuristicAbuseDecision(input AbuseCase) AbuseDecision {
	text := strings.ToLower(input.Reason + " " + input.Details + " " + input.PublicationTitle)
	critical := []string{"phishing", "credential", "password", "malware", "virus", "ransomware", "child sexual", "csam", "doxx"}
	high := []string{"scam", "fraud", "impersonation", "harassment", "hate", "threat", "spam", "illegal"}
	for _, token := range critical {
		if strings.Contains(text, token) {
			return AbuseDecision{Severity: "critical", Block: true, Summary: "Automatic review found a critical abuse signal: " + token}
		}
	}
	for _, token := range high {
		if strings.Contains(text, token) {
			return AbuseDecision{Severity: "high", Block: true, Summary: "Automatic review found a high-risk abuse signal: " + token}
		}
	}
	if strings.TrimSpace(text) == "" {
		return AbuseDecision{Severity: "low", Block: false, Summary: "No abuse details were provided."}
	}
	return AbuseDecision{Severity: "medium", Block: false, Summary: "Abuse report recorded for human review."}
}

func normalizeDecision(decision AbuseDecision) AbuseDecision {
	switch decision.Severity {
	case "low", "medium", "high", "critical":
	default:
		decision.Severity = "medium"
	}
	if strings.TrimSpace(decision.Summary) == "" {
		decision.Summary = "Automatic moderation completed."
	}
	return decision
}
