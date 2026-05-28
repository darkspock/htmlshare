package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		handle(req)
	}
}

func handle(req request) {
	switch req.Method {
	case "initialize":
		reply(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "htmlshare", "version": "0.1.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})
	case "tools/list":
		reply(req.ID, map[string]any{"tools": []map[string]any{
			{
				"name":        "publish_html",
				"description": "Publish an HTML/CSS/JS file bundle to htmlshare.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"title":                map[string]string{"type": "string"},
						"visibility":           map[string]string{"type": "string"},
						"require_registration": map[string]string{"type": "boolean"},
						"files":                map[string]any{"type": "object", "additionalProperties": map[string]string{"type": "string"}},
						"share":                map[string]string{"type": "object"},
					},
					"required": []string{"title", "files"},
				},
			},
			{
				"name":        "share_html",
				"description": "Share an existing publication by email.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"publication_id_or_slug": map[string]string{"type": "string"},
						"emails":                 map[string]any{"type": "array", "items": map[string]string{"type": "string"}},
						"message":                map[string]string{"type": "string"},
					},
					"required": []string{"publication_id_or_slug", "emails"},
				},
			},
		}})
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &params)
		result, err := callTool(params.Name, params.Arguments)
		if err != nil {
			replyErr(req.ID, err.Error())
			return
		}
		reply(req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": result}}})
	default:
		if req.ID != nil {
			replyErr(req.ID, "unknown method")
		}
	}
}

func callTool(name string, args json.RawMessage) (string, error) {
	switch name {
	case "publish_html":
		return post("/api/publish", args)
	case "share_html":
		var req struct {
			PublicationIDOrSlug string   `json:"publication_id_or_slug"`
			Emails              []string `json:"emails"`
			Message             string   `json:"message"`
		}
		if err := json.Unmarshal(args, &req); err != nil {
			return "", err
		}
		body, _ := json.Marshal(map[string]any{"id": req.PublicationIDOrSlug, "emails": req.Emails, "message": req.Message})
		return post("/api/share", body)
	default:
		return "", fmt.Errorf("unknown tool %s", name)
	}
}

func post(path string, body []byte) (string, error) {
	base := getenv("HTMLSHARE_URL", "http://localhost:4545")
	token := os.Getenv("HTMLSHARE_TOKEN")
	request, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("content-type", "application/json")
	if token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s: %s", resp.Status, string(raw))
	}
	return string(raw), nil
}

func reply(id, result any) {
	_ = json.NewEncoder(os.Stdout).Encode(response{JSONRPC: "2.0", ID: id, Result: result})
}

func replyErr(id any, message string) {
	_ = json.NewEncoder(os.Stdout).Encode(response{JSONRPC: "2.0", ID: id, Error: map[string]any{"code": -32000, "message": message}})
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
