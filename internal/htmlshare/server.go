package htmlshare

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Store          *Store
	Mailer         Mailer
	AbuseAnalyzer  AbuseAnalyzer
	AppURL         string
	SessionSecret  string
	GoogleClient   string
	GoogleSecret   string
	GoogleRedirect string
}

const (
	publicLoginEnabled = true
	commentsEnabled    = false
	apiVersion         = "v1"
)

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})
	mux.HandleFunc("/api", s.openapi)
	mux.HandleFunc("/api/", s.apiIndex)
	mux.HandleFunc("/api/v1", s.openapi)
	mux.HandleFunc("/api/v1/", s.apiV1Index)
	mux.HandleFunc("/api/ai/signup", s.aiSignup)
	mux.HandleFunc("/api/v1/ai/signup", s.aiSignup)
	mux.HandleFunc("/api/auth/config", s.authConfig)
	mux.HandleFunc("/api/v1/auth/config", s.authConfig)
	mux.HandleFunc("/api/session", s.session)
	mux.HandleFunc("/api/v1/session", s.session)
	mux.HandleFunc("/api/api-keys", s.apiKeys)
	mux.HandleFunc("/api/v1/api-keys", s.apiKeys)
	mux.HandleFunc("/api/publish", s.publish)
	mux.HandleFunc("/api/v1/publish", s.publish)
	mux.HandleFunc("/api/share", s.share)
	mux.HandleFunc("/api/v1/share", s.share)
	mux.HandleFunc("/api/library", s.library)
	mux.HandleFunc("/api/v1/library", s.library)
	mux.HandleFunc("/api/library/", s.libraryActions)
	mux.HandleFunc("/api/v1/library/", s.libraryActions)
	mux.HandleFunc("/api/history", s.history)
	mux.HandleFunc("/api/v1/history", s.history)
	mux.HandleFunc("/api/shared-with-me", s.sharedWithMe)
	mux.HandleFunc("/api/v1/shared-with-me", s.sharedWithMe)
	mux.HandleFunc("/api/bookmarks", s.bookmarks)
	mux.HandleFunc("/api/v1/bookmarks", s.bookmarks)
	mux.HandleFunc("/api/bookmarks/", s.bookmarkActions)
	mux.HandleFunc("/api/v1/bookmarks/", s.bookmarkActions)
	mux.HandleFunc("/api/public-comments/", s.publicPublicationComments)
	mux.HandleFunc("/api/v1/public-comments/", s.publicPublicationComments)
	mux.HandleFunc("/api/comments/", s.commentActions)
	mux.HandleFunc("/api/v1/comments/", s.commentActions)
	mux.HandleFunc("/api/abuse-reports", s.abuseReports)
	mux.HandleFunc("/api/v1/abuse-reports", s.abuseReports)
	mux.HandleFunc("/mcp", s.mcp)
	mux.HandleFunc("/abuse", s.abusePage)
	mux.HandleFunc("/auth/magic", s.magic)
	mux.HandleFunc("/auth/signed", s.signedAccess)
	mux.HandleFunc("/auth/google", s.googleStart)
	mux.HandleFunc("/auth/google/id-token", s.googleIDToken)
	mux.HandleFunc("/auth/google/callback", s.googleCallback)
	mux.HandleFunc("/f/", s.publicationAsset)
	mux.HandleFunc("/app/", s.app)
	if s.AbuseAnalyzer == nil {
		s.AbuseAnalyzer = NewAbuseAnalyzerFromEnv()
	}
	return securityHeaders(s.banMiddleware(s.cleanupMiddleware(mux)))
}

func (s *Server) banMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/" || r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.png" || r.URL.Path == "/logo.png" || r.URL.Path == "/logo-white.png" || r.URL.Path == "/llms.txt" || r.URL.Path == "/terms" || strings.HasPrefix(r.URL.Path, "/app/") || r.URL.Path == "/api/abuse-reports" || r.URL.Path == "/abuse" {
			next.ServeHTTP(w, r)
			return
		}
		email := ""
		if user := s.currentUser(r); user != nil {
			email = user.Email
		}
		if ban, ok := s.activeBan(clientIP(r), email, time.Now()); ok {
			http.Error(w, "temporarily banned: "+ban.Reason, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cleanupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = s.cleanupExpiredAutomaticRegistrations(time.Now())
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cleanupExpiredAutomaticRegistrations(now time.Time) error {
	var publicationIDs []string
	err := s.Store.WithDB(func(db *DB) error {
		db.Bans = filterActiveBans(db.Bans, now)
		db.Strikes = filterActiveStrikes(db.Strikes, now)
		expiredUsers := map[string]bool{}
		for _, user := range db.Users {
			if user.AutoProvisioned && !user.EmailConfirmed() && !user.ConfirmationDeadline.IsZero() && now.After(user.ConfirmationDeadline) {
				expiredUsers[user.ID] = true
			}
		}
		if len(expiredUsers) == 0 {
			return nil
		}

		expiredPublications := map[string]bool{}
		var users []User
		for _, user := range db.Users {
			if !expiredUsers[user.ID] {
				users = append(users, user)
			}
		}
		db.Users = users

		var publications []Publication
		for _, publication := range db.Publications {
			if expiredUsers[publication.OwnerID] {
				expiredPublications[publication.ID] = true
				publicationIDs = append(publicationIDs, publication.ID)
				continue
			}
			publications = append(publications, publication)
		}
		db.Publications = publications

		db.Sessions = filterSessions(db.Sessions, expiredUsers)
		db.MagicLinks = filterMagicLinks(db.MagicLinks, expiredUsers, expiredPublications)
		db.APIKeys = filterAPIKeys(db.APIKeys, expiredUsers)
		db.Shares = filterShares(db.Shares, expiredUsers, expiredPublications)
		db.AccessLogs = filterAccessLogs(db.AccessLogs, expiredUsers, expiredPublications)
		return nil
	})
	for _, publicationID := range publicationIDs {
		if removeErr := s.Store.DeletePublicationDir(publicationID); err == nil && removeErr != nil {
			err = removeErr
		}
	}
	return err
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/logo.png" {
		setPublicCache(w, 24*time.Hour)
		http.ServeFile(w, r, "web/home/logo.png")
		return
	}
	if r.URL.Path == "/logo-white.png" {
		setPublicCache(w, 24*time.Hour)
		http.ServeFile(w, r, "web/home/logo-white.png")
		return
	}
	if r.URL.Path == "/favicon.png" || r.URL.Path == "/favicon.ico" {
		setPublicCache(w, 7*24*time.Hour)
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "web/home/favicon.png")
		return
	}
	if r.URL.Path == "/llms.txt" {
		setPublicCache(w, 5*time.Minute)
		http.ServeFile(w, r, "web/home/llms.txt")
		return
	}
	if r.URL.Path == "/terms" || r.URL.Path == "/terms/" {
		setPublicCache(w, 5*time.Minute)
		http.ServeFile(w, r, "web/home/terms.html")
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	setPublicCache(w, 5*time.Minute)
	http.ServeFile(w, r, "web/home/index.html")
}

func (s *Server) apiIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/" || r.URL.Path == "/api/openapi.json" {
		s.openapi(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) apiV1Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/" || r.URL.Path == "/api/v1/openapi.json" {
		s.openapi(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "htmlshare API",
			"version":     apiVersion,
			"description": "AI-first API for publishing and sharing generated HTML pages.",
		},
		"servers": []map[string]string{{"url": s.AppURL + "/api/" + apiVersion}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]string{"type": "http", "scheme": "bearer"},
				"sessionCookie": map[string]any{
					"type": "apiKey",
					"in":   "cookie",
					"name": "htmlshare_session",
				},
			},
			"schemas": map[string]any{
				"APIKeyRequest": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]string{"type": "string"},
					},
				},
				"PublishRequest": map[string]any{
					"type":     "object",
					"required": []string{"files"},
					"properties": map[string]any{
						"mode":                 map[string]any{"type": "string", "enum": []string{"fast", "registered"}},
						"agent_id":             map[string]string{"type": "string"},
						"agent_name":           map[string]string{"type": "string"},
						"title":                map[string]string{"type": "string"},
						"visibility":           map[string]any{"type": "string", "enum": []string{"private", "magic", "recipients", "signed", "public"}},
						"require_registration": map[string]string{"type": "boolean"},
						"expires_at":           map[string]string{"type": "string", "format": "date-time"},
						"ttl_seconds":          map[string]string{"type": "integer"},
						"files":                map[string]any{"type": "object", "additionalProperties": map[string]string{"type": "string"}},
						"share": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"emails":  map[string]any{"type": "array", "items": map[string]string{"type": "string"}},
								"message": map[string]string{"type": "string"},
							},
						},
					},
				},
				"ShareRequest": map[string]any{
					"type":     "object",
					"required": []string{"emails"},
					"properties": map[string]any{
						"id":             map[string]string{"type": "string"},
						"publication_id": map[string]string{"type": "string"},
						"slug":           map[string]string{"type": "string"},
						"emails":         map[string]any{"type": "array", "items": map[string]string{"type": "string"}},
						"message":        map[string]string{"type": "string"},
					},
				},
			},
		},
		"paths": map[string]any{
			"/publish": map[string]any{
				"post": map[string]any{
					"summary":     "Publish an HTML bundle",
					"description": "Canonical agent endpoint. Use mode=fast with an agent_id for short-lived public or recipient-restricted publishing without bearer auth. Use mode=registered with bearer/session auth for account-owned sharing, dashboard control, signed access, or long-lived library storage.",
					"security":    []map[string][]string{{}, {"bearerAuth": []string{}}, {"sessionCookie": []string{}}},
					"requestBody": openAPIJSONBody("PublishRequest"),
					"responses":   openAPIResponses("201", "HTML published"),
				},
			},
			"/share": map[string]any{
				"post": map[string]any{
					"summary":     "Share an existing publication by email",
					"description": "Creates magic links for recipients and sends email when email delivery is configured.",
					"security":    []map[string][]string{{"bearerAuth": []string{}}},
					"requestBody": openAPIJSONBody("ShareRequest"),
					"responses":   openAPIResponses("201", "Publication shared"),
				},
			},
			"/ai/signup": map[string]any{
				"post": map[string]any{
					"summary":   "Start registered-account automation signup with a magic link",
					"responses": openAPIResponses("201", "Magic link created"),
				},
			},
			"/api-keys": map[string]any{
				"post": map[string]any{
					"summary":     "Create an agent API key",
					"description": "Requires a confirmed authenticated session. For a new email, /api/ai/signup returns a temporary hsk_... token and sends a confirmation email. For an existing confirmed email, /api/ai/signup emails a new token to the account owner instead of returning it.",
					"security":    []map[string][]string{{"sessionCookie": []string{}}},
					"requestBody": openAPIJSONBody("APIKeyRequest"),
					"responses":   openAPIResponses("201", "Agent key created"),
				},
			},
			"/abuse-reports": map[string]any{
				"post": map[string]any{
					"summary":   "Submit abuse or illegal content notice",
					"responses": openAPIResponses("201", "Abuse notice accepted"),
				},
			},
			"/mcp": map[string]any{
				"post": map[string]any{
					"summary":     "Remote MCP JSON-RPC endpoint",
					"description": "Use Authorization: Bearer hsk_... and JSON-RPC methods initialize, tools/list, and tools/call.",
					"security":    []map[string][]string{{"bearerAuth": []string{}}},
					"responses":   openAPIResponses("200", "MCP JSON-RPC response"),
				},
			},
		},
	})
}

func openAPIJSONBody(schema string) map[string]any {
	return map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]string{"$ref": "#/components/schemas/" + schema},
			},
		},
	}
}

func openAPIResponses(code, description string) map[string]any {
	return map[string]any{code: map[string]string{"description": description}}
}

func (s *Server) app(w http.ResponseWriter, r *http.Request) {
	dist := filepath.Join("web", "app", "dist")
	path := strings.TrimPrefix(r.URL.Path, "/app/")
	if path == "" {
		path = "index.html"
	}
	target := filepath.Join(dist, filepath.Clean(path))
	if _, err := os.Stat(target); err == nil {
		if strings.HasPrefix(path, "assets/") {
			setImmutableCache(w)
		} else {
			setNoCache(w)
		}
		http.ServeFile(w, r, target)
		return
	}
	setNoCache(w)
	http.ServeFile(w, r, filepath.Join(dist, "index.html"))
}

type aiSignupRequest struct {
	Email  string `json:"email"`
	Name   string `json:"name"`
	Agent  string `json:"agent"`
	Intent string `json:"intent"`
}

func (s *Server) aiSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req aiSignupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(req.Email, "@") {
		http.Error(w, "valid email required", http.StatusBadRequest)
		return
	}
	if ban, ok := s.activeBan(clientIP(r), req.Email, time.Now()); ok {
		http.Error(w, "temporarily banned: "+ban.Reason, http.StatusTooManyRequests)
		return
	}
	now := time.Now()
	var user User
	existing := false
	err := s.Store.WithDB(func(db *DB) error {
		for i := range db.Users {
			if db.Users[i].Email == req.Email {
				user = db.Users[i]
				existing = true
				return nil
			}
		}
		user = User{
			ID:                   NewID("usr"),
			Email:                req.Email,
			Name:                 req.Name,
			Provider:             "magic",
			AutoProvisioned:      true,
			ConfirmationDeadline: now.Add(24 * time.Hour),
			CreatedAt:            now,
		}
		db.Users = append(db.Users, user)
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if existing && user.EmailConfirmed() {
		apiKey, prefix, err := s.createAPIKey(user.ID, agentKeyName(req.Agent), now.Add(365*24*time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		text := "A new htmlshare agent key was requested for " + user.Email + ".\n\nToken: " + apiKey + "\n\nStore it in your agent secret store. It expires in 1 year."
		html := `<p>A new htmlshare agent key was requested for <strong>` + htmlEscape(user.Email) + `</strong>.</p><p><code>` + htmlEscape(apiKey) + `</code></p><p>Store it in your agent secret store. It expires in 1 year.</p>`
		_ = s.Mailer.Send(user.Email, "Your htmlshare agent key", text, html)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"existing_account": true,
			"email":            user.Email,
			"token_sent":       true,
			"prefix":           prefix,
			"next":             "This email is already registered. A new agent token has been sent to the account owner. The LLM must ask the user to provide/store that token.",
		})
		return
	}
	apiKey, prefix, err := s.createAPIKey(user.ID, agentKeyName(req.Agent), now.Add(24*time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	magicURL, err := s.createMagicLink(user, "signup", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Mailer.Send(user.Email, "Confirm your htmlshare agent token", "Confirm your htmlshare account:\n\n"+magicURL, `<p>Confirm your htmlshare account and extend your temporary agent token:</p><p><a href="`+magicURL+`">Confirm htmlshare</a></p>`)
	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id":           user.ID,
		"email":             user.Email,
		"api_key":           apiKey,
		"prefix":            prefix,
		"token_expires_at":  now.Add(24 * time.Hour),
		"confirmation_sent": true,
		"expires_at":        user.ConfirmationDeadline,
		"next":              "Store the hsk_... token. It is valid for 24 hours until the user confirms by pressing the button in the email page; after confirmation it is extended to 1 year.",
	})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	if user == nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(*user)})
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	if !publicLoginEnabled {
		writeJSON(w, http.StatusOK, map[string]any{"google_client_id": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"google_client_id": s.GoogleClient})
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request) {
	user := s.requireUser(w, r)
	if user == nil {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !user.EmailConfirmed() {
		http.Error(w, "email confirmation required", http.StatusForbidden)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Name == "" {
		req.Name = "agent key"
	}
	raw, prefix, err := s.createAPIKey(user.ID, req.Name, time.Now().Add(365*24*time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_key": raw, "prefix": prefix})
}

func (s *Server) createAPIKey(userID, name string, expiresAt time.Time) (string, string, error) {
	if name == "" {
		name = "agent key"
	}
	raw := "hsk_" + RandomToken(28)
	key := APIKey{ID: NewID("key"), UserID: userID, Name: name, TokenPrefix: raw[:12], TokenHash: HashToken(raw), CreatedAt: time.Now(), ExpiresAt: expiresAt}
	if err := s.Store.WithDB(func(db *DB) error {
		db.APIKeys = append(db.APIKeys, key)
		return nil
	}); err != nil {
		return "", "", err
	}
	return raw, key.TokenPrefix, nil
}

func agentKeyName(agent string) string {
	agent = strings.TrimSpace(agent)
	if agent == "" {
		return "agent signup key"
	}
	return agent + " signup key"
}

type publishRequest struct {
	Title               string            `json:"title"`
	Mode                string            `json:"mode"`
	AgentID             string            `json:"agent_id"`
	AgentName           string            `json:"agent_name"`
	Visibility          string            `json:"visibility"`
	RequireRegistration bool              `json:"require_registration"`
	ExpiresAt           time.Time         `json:"expires_at"`
	TTLSeconds          int               `json:"ttl_seconds"`
	Files               map[string]string `json:"files"`
	Share               struct {
		Emails  []string `json:"emails"`
		Message string   `json:"message"`
	} `json:"share"`
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.createPublication(w, r, nil)
		return
	}
	methodNotAllowed(w)
}

func (s *Server) library(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	if r.Method == http.MethodGet {
		s.listPublications(w, user)
		return
	}
	methodNotAllowed(w)
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		ID            string   `json:"id"`
		PublicationID string   `json:"publication_id"`
		Slug          string   `json:"slug"`
		Emails        []string `json:"emails"`
		Message       string   `json:"message"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	idOrSlug := strings.TrimSpace(req.ID)
	if idOrSlug == "" {
		idOrSlug = strings.TrimSpace(req.PublicationID)
	}
	if idOrSlug == "" {
		idOrSlug = strings.TrimSpace(req.Slug)
	}
	if idOrSlug == "" {
		http.Error(w, "publication_id or slug required", http.StatusBadRequest)
		return
	}
	publication, ok := s.findPublicationOwned(idOrSlug, user.ID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.createShares(w, publication, req.Emails, req.Message)
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"name":        "htmlshare MCP",
			"endpoint":    s.AppURL + "/mcp",
			"transport":   "http-json-rpc",
			"auth":        "Authorization: Bearer hsk_...",
			"openapi_url": s.AppURL + "/api",
		})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req mcpRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.JSONRPC == "" {
		req.JSONRPC = "2.0"
	}
	var result any
	var err error
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "htmlshare", "version": "1.0.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}
	case "tools/list":
		if s.requireAutomationUser(w, r) == nil {
			return
		}
		result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		user := s.requireAutomationUser(w, r)
		if user == nil {
			return
		}
		result, err = s.mcpToolCall(r, user, req.Params)
	default:
		err = fmt.Errorf("unknown method %s", req.Method)
	}
	if err != nil {
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: req.ID, Error: map[string]any{"code": -32000, "message": err.Error()}})
		return
	}
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (s *Server) mcpToolCall(r *http.Request, user *User, raw json.RawMessage) (any, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, err
	}
	switch params.Name {
	case "publish_html":
		rec := &captureWriter{header: http.Header{}}
		req := r.Clone(r.Context())
		req.Body = io.NopCloser(bytes.NewReader(params.Arguments))
		s.createPublication(rec, req, user)
		return mcpCapturedContent(rec)
	case "share_html":
		var req struct {
			ID      string   `json:"id"`
			Slug    string   `json:"slug"`
			Emails  []string `json:"emails"`
			Message string   `json:"message"`
		}
		if err := json.Unmarshal(params.Arguments, &req); err != nil {
			return nil, err
		}
		idOrSlug := strings.TrimSpace(req.ID)
		if idOrSlug == "" {
			idOrSlug = strings.TrimSpace(req.Slug)
		}
		publication, ok := s.findPublicationOwned(idOrSlug, user.ID)
		if !ok {
			return nil, errors.New("publication not found")
		}
		rec := &captureWriter{header: http.Header{}}
		s.createShares(rec, publication, req.Emails, req.Message)
		return mcpCapturedContent(rec)
	default:
		return nil, fmt.Errorf("unknown tool %s", params.Name)
	}
}

func mcpCapturedContent(rec *captureWriter) (any, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	if rec.status < 200 || rec.status >= 300 {
		return nil, fmt.Errorf("%d: %s", rec.status, strings.TrimSpace(rec.body.String()))
	}
	text := strings.TrimSpace(rec.body.String())
	if text == "" {
		text = "{}"
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}, nil
}

func mcpTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "publish_html",
			"description": "Publish an HTML/CSS/JS bundle and return its share URL.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"title", "files"},
				"properties": map[string]any{
					"title":                map[string]string{"type": "string"},
					"visibility":           map[string]any{"type": "string", "enum": []string{"private", "magic", "recipients", "signed", "public"}},
					"require_registration": map[string]string{"type": "boolean"},
					"expires_at":           map[string]string{"type": "string", "format": "date-time"},
					"ttl_seconds":          map[string]string{"type": "integer"},
					"files":                map[string]any{"type": "object", "additionalProperties": map[string]string{"type": "string"}},
					"share":                map[string]string{"type": "object"},
				},
			},
		},
		{
			"name":        "share_html",
			"description": "Share an existing publication by email.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"emails"},
				"properties": map[string]any{
					"id":      map[string]string{"type": "string"},
					"slug":    map[string]string{"type": "string"},
					"emails":  map[string]any{"type": "array", "items": map[string]string{"type": "string", "format": "email"}},
					"message": map[string]string{"type": "string"},
				},
			},
		},
	}
}

type captureWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *captureWriter) Header() http.Header {
	return w.header
}

func (w *captureWriter) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(raw)
}

func (w *captureWriter) WriteHeader(status int) {
	w.status = status
}

func (s *Server) listPublications(w http.ResponseWriter, user *User) {
	var publications []Publication
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if publication.OwnerID == user.ID {
				publications = append(publications, publication)
			}
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"publications": publications})
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	type item struct {
		Publication Publication `json:"publication"`
		LastOpened  time.Time   `json:"last_opened_at"`
		Path        string      `json:"path"`
		Visits      int         `json:"visits"`
	}
	byID := map[string]*item{}
	_ = s.Store.ReadDB(func(db DB) error {
		publications := map[string]Publication{}
		for _, publication := range db.Publications {
			publications[publication.ID] = publication
		}
		for _, log := range db.AccessLogs {
			if log.UserID != user.ID || !log.Allowed {
				continue
			}
			publication, ok := publications[log.PublicationID]
			if !ok {
				continue
			}
			current := byID[publication.ID]
			if current == nil {
				byID[publication.ID] = &item{Publication: publication, LastOpened: log.CreatedAt, Path: log.Path, Visits: 1}
				continue
			}
			current.Visits++
			if log.CreatedAt.After(current.LastOpened) {
				current.LastOpened = log.CreatedAt
				current.Path = log.Path
			}
		}
		return nil
	})
	var items []item
	for _, current := range byID {
		items = append(items, *current)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastOpened.After(items[j].LastOpened) })
	writeJSON(w, http.StatusOK, map[string]any{"history": items})
}

func (s *Server) sharedWithMe(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	var publications []Publication
	_ = s.Store.ReadDB(func(db DB) error {
		publications = publicationsSharedWithUser(db, *user)
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"publications": publications})
}

func (s *Server) bookmarks(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listBookmarks(w, user)
	case http.MethodPost:
		var req struct {
			PublicationID string `json:"publication_id"`
			Slug          string `json:"slug"`
			Kind          string `json:"kind"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		s.createBookmark(w, req.PublicationID, req.Slug, req.Kind, user)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) bookmarkActions(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	idOrSlug := strings.Trim(strings.TrimPrefix(trimAPIVersionPath(r.URL.Path), "/api/bookmarks/"), "/")
	s.deleteBookmark(w, idOrSlug, user)
}

func (s *Server) listBookmarks(w http.ResponseWriter, user *User) {
	type item struct {
		Bookmark    Bookmark    `json:"bookmark"`
		Publication Publication `json:"publication"`
	}
	var items []item
	_ = s.Store.ReadDB(func(db DB) error {
		publications := map[string]Publication{}
		for _, publication := range db.Publications {
			publications[publication.ID] = publication
		}
		for _, bookmark := range db.Bookmarks {
			if bookmark.UserID != user.ID {
				continue
			}
			publication, ok := publications[bookmark.PublicationID]
			if ok {
				items = append(items, item{Bookmark: bookmark, Publication: publication})
			}
		}
		return nil
	})
	sort.Slice(items, func(i, j int) bool { return items[i].Bookmark.CreatedAt.After(items[j].Bookmark.CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"bookmarks": items})
}

func (s *Server) createBookmark(w http.ResponseWriter, publicationID, slug, kind string, user *User) {
	if kind == "" {
		kind = "read_later"
	}
	publication, ok := s.findAccessiblePublication(publicationID, slug, *user)
	if !ok {
		http.Error(w, "publication not found", http.StatusNotFound)
		return
	}
	bookmark := Bookmark{ID: NewID("bmk"), UserID: user.ID, PublicationID: publication.ID, Kind: kind, CreatedAt: time.Now()}
	if err := s.Store.UpsertBookmark(bookmark); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"bookmark": bookmark, "publication": publication})
}

func (s *Server) deleteBookmark(w http.ResponseWriter, idOrSlug string, user *User) {
	publication, ok := s.findAccessiblePublication(idOrSlug, idOrSlug, *user)
	if !ok {
		http.Error(w, "publication not found", http.StatusNotFound)
		return
	}
	if err := s.Store.DeleteBookmark(user.ID, publication.ID, "read_later"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) createPublication(w http.ResponseWriter, r *http.Request, user *User) {
	var req publishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	req.AgentID = strings.TrimSpace(req.AgentID)
	fastMode := req.Mode == "fast" || (req.Mode == "" && req.AgentID != "" && user == nil)
	if fastMode {
		s.createFastPublication(w, r, req)
		return
	}
	if req.Mode == "" {
		req.Mode = "registered"
	}
	if req.Mode != "registered" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if user == nil {
		user = s.requireAutomationUser(w, r)
		if user == nil {
			return
		}
	}
	if req.Title == "" {
		req.Title = "Untitled file"
	}
	if len(req.Files) == 0 {
		http.Error(w, "files required", http.StatusBadRequest)
		return
	}
	if _, ok := req.Files["index.html"]; !ok {
		http.Error(w, "files.index.html required", http.StatusBadRequest)
		return
	}
	visibility := req.Visibility
	if visibility == "" {
		visibility = "recipients"
	}
	if !validVisibility(visibility) {
		http.Error(w, "invalid visibility", http.StatusBadRequest)
		return
	}
	now := time.Now()
	expiresAt := req.ExpiresAt
	if req.TTLSeconds > 0 {
		expiresAt = now.Add(time.Duration(req.TTLSeconds) * time.Second)
	}
	publication := Publication{
		ID:                  NewID("pub"),
		OwnerID:             user.ID,
		Mode:                "registered",
		CreatedIP:           clientIP(r),
		Title:               req.Title,
		Slug:                Slugify(req.Title),
		Visibility:          visibility,
		RequireRegistration: req.RequireRegistration,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
	}
	for name, content := range req.Files {
		publication.SizeBytes += int64(len([]byte(content)))
		clean, err := s.Store.WritePublicationFile(publication.ID, name, []byte(content))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		publication.Files = append(publication.Files, clean)
	}
	if err := s.Store.AddPublication(publication); err != nil {
		_ = s.Store.DeletePublicationDir(publication.ID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	shareCount := 0
	for _, target := range req.Share.Emails {
		_, err := s.sharePublication(publication, target, req.Share.Message)
		if err == nil {
			shareCount++
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": publication.ID, "slug": publication.Slug, "url": s.AppURL + "/f/" + publication.Slug + "/", "share_count": shareCount,
	})
}

func (s *Server) createFastPublication(w http.ResponseWriter, r *http.Request, req publishRequest) {
	now := time.Now()
	ip := clientIP(r)
	if ban, ok := s.activeBan(ip, "", now); ok {
		http.Error(w, "temporarily banned: "+ban.Reason, http.StatusTooManyRequests)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "agent_id required for fast mode", http.StatusBadRequest)
		return
	}
	if len(req.AgentID) < 8 || len(req.AgentID) > 200 {
		http.Error(w, "agent_id must be between 8 and 200 characters", http.StatusBadRequest)
		return
	}
	if req.Title == "" {
		req.Title = "Untitled file"
	}
	if len(req.Files) == 0 {
		http.Error(w, "files required", http.StatusBadRequest)
		return
	}
	if _, ok := req.Files["index.html"]; !ok {
		http.Error(w, "files.index.html required", http.StatusBadRequest)
		return
	}
	limits := fastPublishLimitsFromEnv()
	if len(req.Files) > limits.MaxFiles {
		http.Error(w, "too many files", http.StatusRequestEntityTooLarge)
		return
	}
	var sizeBytes int64
	for name, content := range req.Files {
		if _, err := cleanPublicationPath(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fileSize := int64(len([]byte(content)))
		if fileSize > limits.MaxFileBytes {
			http.Error(w, "file too large: "+name, http.StatusRequestEntityTooLarge)
			return
		}
		sizeBytes += fileSize
	}
	if sizeBytes > limits.MaxRequestBytes {
		http.Error(w, "publish request too large", http.StatusRequestEntityTooLarge)
		return
	}
	agent, err := s.Store.EnsureAgent(HashToken("agent:"+req.AgentID), req.AgentName, ip, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !agent.BlockedAt.IsZero() {
		http.Error(w, "agent blocked: "+agent.BlockedReason, http.StatusTooManyRequests)
		return
	}
	usage, err := s.Store.FastUsage(agent.ID, ip, now.Add(-time.Hour), now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if usage.IPCount >= limits.MaxIPPublishesPerHour || usage.AgentCount >= limits.MaxAgentPublishesPerHour {
		http.Error(w, "fast publish rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if usage.IPStorage+sizeBytes > limits.MaxIPStorageBytes || usage.AgentStorage+sizeBytes > limits.MaxAgentStorageBytes {
		http.Error(w, "fast publish storage limit exceeded", http.StatusRequestEntityTooLarge)
		return
	}
	expiresAt := req.ExpiresAt
	if req.TTLSeconds > 0 {
		expiresAt = now.Add(time.Duration(req.TTLSeconds) * time.Second)
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(limits.DefaultTTL)
	}
	if expiresAt.After(now.Add(limits.MaxTTL)) {
		http.Error(w, "fast publications must expire within "+limits.MaxTTL.String(), http.StatusBadRequest)
		return
	}
	visibility := strings.ToLower(strings.TrimSpace(req.Visibility))
	if visibility == "" {
		visibility = "public"
	}
	if visibility != "public" && visibility != "recipients" {
		http.Error(w, "fast mode supports visibility public or recipients", http.StatusBadRequest)
		return
	}
	shareTargets, err := normalizeShareTargets(req.Share.Emails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if visibility == "recipients" && len(shareTargets) == 0 {
		http.Error(w, "share.emails required for fast recipient sharing", http.StatusBadRequest)
		return
	}
	publication := Publication{
		ID:                  NewID("pub"),
		AgentID:             agent.ID,
		Mode:                "fast",
		CreatedIP:           ip,
		Title:               req.Title,
		Slug:                Slugify(req.Title),
		Visibility:          visibility,
		RequireRegistration: visibility == "recipients" || req.RequireRegistration,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
		SizeBytes:           sizeBytes,
	}
	for name, content := range req.Files {
		clean, err := s.Store.WritePublicationFile(publication.ID, name, []byte(content))
		if err != nil {
			_ = s.Store.DeletePublicationDir(publication.ID)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		publication.Files = append(publication.Files, clean)
	}
	if err := s.Store.AddPublication(publication); err != nil {
		_ = s.Store.DeletePublicationDir(publication.ID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	shareCount := 0
	for _, target := range shareTargets {
		_, err := s.sharePublication(publication, target, req.Share.Message)
		if err == nil {
			shareCount++
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          publication.ID,
		"slug":        publication.Slug,
		"url":         s.AppURL + "/f/" + publication.Slug + "/",
		"mode":        publication.Mode,
		"visibility":  publication.Visibility,
		"share_count": shareCount,
		"expires_at":  publication.ExpiresAt,
	})
}

func (s *Server) libraryActions(w http.ResponseWriter, r *http.Request) {
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	parts := strings.Split(strings.TrimPrefix(trimAPIVersionPath(r.URL.Path), "/api/library/"), "/")
	if len(parts) == 1 && r.Method == http.MethodPatch {
		publication, ok := s.findPublicationOwned(parts[0], user.ID)
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.updatePublication(w, r, publication)
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	publication, ok := s.findPublicationOwned(parts[0], user.ID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if parts[1] == "stats" && r.Method == http.MethodGet {
		s.publicationStats(w, publication)
		return
	}
	if parts[1] == "shares" && r.Method == http.MethodGet {
		s.publicationShares(w, publication)
		return
	}
	if parts[1] == "comments" {
		s.publicationComments(w, r, publication, user)
		return
	}
	if parts[1] == "signed-access" && r.Method == http.MethodPost {
		s.createSignedAccess(w, r, publication)
		return
	}
	if parts[1] != "share" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Emails  []string `json:"emails"`
		Message string   `json:"message"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.createShares(w, publication, req.Emails, req.Message)
}

func (s *Server) createShares(w http.ResponseWriter, publication Publication, emails []string, message string) {
	shareCount := 0
	targets, err := normalizeShareTargets(emails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, target := range targets {
		_, err := s.sharePublication(publication, target, message)
		if err == nil {
			shareCount++
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"share_count": shareCount})
}

func (s *Server) updatePublication(w http.ResponseWriter, r *http.Request, publication Publication) {
	var req struct {
		Title               *string `json:"title"`
		Visibility          *string `json:"visibility"`
		RequireRegistration *bool   `json:"require_registration"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.Store.WithDB(func(db *DB) error {
		for i := range db.Publications {
			if db.Publications[i].ID == publication.ID {
				if req.Title != nil && strings.TrimSpace(*req.Title) != "" {
					db.Publications[i].Title = strings.TrimSpace(*req.Title)
				}
				if req.Visibility != nil && validVisibility(*req.Visibility) {
					db.Publications[i].Visibility = *req.Visibility
				}
				if req.RequireRegistration != nil {
					db.Publications[i].RequireRegistration = *req.RequireRegistration
				}
				publication = db.Publications[i]
				return nil
			}
		}
		return errors.New("publication not found")
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publication": publication})
}

func (s *Server) publicationStats(w http.ResponseWriter, publication Publication) {
	var logs []AccessLog
	_ = s.Store.ReadDB(func(db DB) error {
		for _, log := range db.AccessLogs {
			if log.PublicationID == publication.ID {
				logs = append(logs, log)
			}
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"publication_id": publication.ID,
		"slug":           publication.Slug,
		"visits":         len(logs),
		"logs":           logs,
	})
}

func (s *Server) publicationShares(w http.ResponseWriter, publication Publication) {
	var shares []Share
	_ = s.Store.ReadDB(func(db DB) error {
		for _, share := range db.Shares {
			if share.PublicationID == publication.ID {
				shares = append(shares, share)
			}
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"shares": shares})
}

func (s *Server) publicationComments(w http.ResponseWriter, r *http.Request, publication Publication, user *User) {
	if !commentsEnabled {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"comments": []Comment{}})
			return
		}
		http.Error(w, "comments are disabled in this version", http.StatusGone)
		return
	}
	switch r.Method {
	case http.MethodGet:
		var comments []Comment
		_ = s.Store.ReadDB(func(db DB) error {
			for _, comment := range db.Comments {
				if comment.PublicationID == publication.ID && comment.DeletedAt.IsZero() {
					comments = append(comments, comment)
				}
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"comments": comments})
	case http.MethodPost:
		var req struct {
			Body           string `json:"body"`
			ParentID       string `json:"parent_id"`
			Scope          string `json:"scope"`
			AnchorText     string `json:"anchor_text"`
			AnchorSelector string `json:"anchor_selector"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		req.Body = strings.TrimSpace(req.Body)
		if req.Body == "" {
			http.Error(w, "comment body required", http.StatusBadRequest)
			return
		}
		if req.Scope != "inline" {
			req.Scope = "general"
		}
		comment := Comment{
			ID:             NewID("cmt"),
			PublicationID:  publication.ID,
			ParentID:       req.ParentID,
			UserID:         user.ID,
			Email:          user.Email,
			IP:             clientIP(r),
			Body:           req.Body,
			Scope:          req.Scope,
			AnchorText:     strings.TrimSpace(req.AnchorText),
			AnchorSelector: strings.TrimSpace(req.AnchorSelector),
			CreatedAt:      time.Now(),
		}
		if err := s.Store.WithDB(func(db *DB) error {
			db.Comments = append(db.Comments, comment)
			return nil
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"comment": comment})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) publicPublicationComments(w http.ResponseWriter, r *http.Request) {
	if !commentsEnabled {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"comments": []Comment{}})
			return
		}
		http.Error(w, "comments are disabled in this version", http.StatusGone)
		return
	}
	slug := strings.Trim(strings.TrimPrefix(trimAPIVersionPath(r.URL.Path), "/api/public-comments/"), "/")
	publication, ok := s.findPublicationBySlug(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.canReadPublication(r, publication) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	user := s.currentUser(r)
	switch r.Method {
	case http.MethodGet:
		var comments []Comment
		_ = s.Store.ReadDB(func(db DB) error {
			for _, comment := range db.Comments {
				if comment.PublicationID == publication.ID && comment.DeletedAt.IsZero() && comment.ArchivedAt.IsZero() {
					comments = append(comments, comment)
				}
			}
			return nil
		})
		writeJSON(w, http.StatusOK, map[string]any{"comments": comments})
	case http.MethodPost:
		if user == nil {
			http.Error(w, "signed access or login required to comment", http.StatusUnauthorized)
			return
		}
		s.publicationComments(w, r, publication, user)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) commentActions(w http.ResponseWriter, r *http.Request) {
	if !commentsEnabled {
		http.Error(w, "comments are disabled in this version", http.StatusGone)
		return
	}
	user := s.requireAutomationUser(w, r)
	if user == nil {
		return
	}
	commentID := strings.Trim(strings.TrimPrefix(trimAPIVersionPath(r.URL.Path), "/api/comments/"), "/")
	if commentID == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Archived *bool `json:"archived"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		var comment Comment
		err := s.Store.WithDB(func(db *DB) error {
			ownedPublications := ownedPublicationSet(db.Publications, user.ID)
			for i := range db.Comments {
				if db.Comments[i].ID == commentID && ownedPublications[db.Comments[i].PublicationID] {
					if req.Archived != nil {
						if *req.Archived {
							db.Comments[i].ArchivedAt = time.Now()
						} else {
							db.Comments[i].ArchivedAt = time.Time{}
						}
					}
					comment = db.Comments[i]
					return nil
				}
			}
			return errors.New("comment not found")
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"comment": comment})
	case http.MethodDelete:
		err := s.Store.WithDB(func(db *DB) error {
			ownedPublications := ownedPublicationSet(db.Publications, user.ID)
			for i := range db.Comments {
				if db.Comments[i].ID == commentID && ownedPublications[db.Comments[i].PublicationID] {
					db.Comments[i].DeletedAt = time.Now()
					return nil
				}
			}
			return errors.New("comment not found")
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) createSignedAccess(w http.ResponseWriter, r *http.Request, publication Publication) {
	var req struct {
		Email   string `json:"email"`
		Message string `json:"message"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(email, "@") {
		http.Error(w, "valid email required", http.StatusBadRequest)
		return
	}
	raw := "hsa_" + RandomToken(32)
	token := SignedAccessToken{
		ID:            NewID("sat"),
		PublicationID: publication.ID,
		Email:         email,
		TokenHash:     HashToken(raw),
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
	}
	if err := s.Store.WithDB(func(db *DB) error {
		db.SignedTokens = append(db.SignedTokens, token)
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	link := s.AppURL + "/auth/signed?token=" + raw
	text := strings.TrimSpace(req.Message + "\n\nLegal signed access for " + publication.Title + "\n" + link)
	html := `<p>` + htmlEscape(req.Message) + `</p><p>Legal signed access for <strong>` + htmlEscape(publication.Title) + `</strong>:</p><p><a href="` + link + `">Open signed link</a></p>`
	_ = s.Mailer.Send(email, "Signed access: "+publication.Title, text, html)
	writeJSON(w, http.StatusCreated, map[string]any{"email": email, "signed_url": link, "expires_at": token.ExpiresAt})
}

func (s *Server) abuseReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createAbuseReport(w, r)
	case http.MethodGet:
		user := s.requireAutomationUser(w, r)
		if user == nil {
			return
		}
		s.listAbuseReports(w, user)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) abusePage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderAbusePage(w, r, "")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		slug := strings.TrimSpace(r.FormValue("slug"))
		answer := strings.TrimSpace(r.FormValue("captcha_answer"))
		token := strings.TrimSpace(r.FormValue("captcha_token"))
		if !s.validateCaptcha(slug, answer, token) {
			s.renderAbusePage(w, r, "Incorrect captcha. Please try again.")
			return
		}
		publication, ok := s.findPublicationForAbuse("", slug)
		if !ok {
			http.NotFound(w, r)
			return
		}
		abuse, decision, err := s.createAbuseReportData(publication, strings.ToLower(strings.TrimSpace(r.FormValue("reporter_email"))), strings.TrimSpace(r.FormValue("reason")), strings.TrimSpace(r.FormValue("details")), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, abuseSubmittedHTML(publication, abuse, decision))
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) renderAbusePage(w http.ResponseWriter, r *http.Request, message string) {
	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	publication, ok := s.findPublicationForAbuse("", slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	challenge := s.newCaptcha(slug)
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, abuseFormHTML(publication, challenge, message))
}

func (s *Server) createAbuseReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicationID string `json:"publication_id"`
		Slug          string `json:"slug"`
		ReporterEmail string `json:"reporter_email"`
		Reason        string `json:"reason"`
		Details       string `json:"details"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	publication, ok := s.findPublicationForAbuse(req.PublicationID, req.Slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	abuse, decision, err := s.createAbuseReportData(publication, req.ReporterEmail, req.Reason, req.Details, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"abuse_report": abuse, "decision": decision})
}

func (s *Server) createAbuseReportData(publication Publication, reporterEmail, reason, details string, r *http.Request) (AbuseReport, AbuseDecision, error) {
	reporterEmail = strings.ToLower(strings.TrimSpace(reporterEmail))
	reason = strings.TrimSpace(reason)
	details = strings.TrimSpace(details)
	if reason == "" {
		return AbuseReport{}, AbuseDecision{}, errors.New("reason required")
	}
	decision := s.AbuseAnalyzer.AnalyzeAbuse(AbuseCase{
		Reason:           reason,
		Details:          details,
		PublicationTitle: publication.Title,
		PublicationSlug:  publication.Slug,
		ReporterEmail:    reporterEmail,
	})
	abuse := AbuseReport{
		ID:              NewID("abr"),
		PublicationID:   publication.ID,
		Slug:            publication.Slug,
		ReporterEmail:   reporterEmail,
		ReporterIP:      clientIP(r),
		Reason:          reason,
		Details:         details,
		Status:          "reviewed",
		Severity:        decision.Severity,
		AnalysisSummary: decision.Summary,
		AutoBlocked:     decision.Block,
		CreatedAt:       time.Now(),
		ReviewedAt:      time.Now(),
	}
	if err := s.applyAbuseDecision(abuse, publication, decision); err != nil {
		return AbuseReport{}, AbuseDecision{}, err
	}
	return abuse, decision, nil
}

func (s *Server) listAbuseReports(w http.ResponseWriter, user *User) {
	owned := map[string]bool{}
	var abuseCases []AbuseReport
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if publication.OwnerID == user.ID {
				owned[publication.ID] = true
			}
		}
		for _, abuse := range db.AbuseReports {
			if owned[abuse.PublicationID] {
				abuseCases = append(abuseCases, abuse)
			}
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"abuse_reports": abuseCases})
}

func (s *Server) applyAbuseDecision(abuse AbuseReport, publication Publication, decision AbuseDecision) error {
	now := time.Now()
	return s.Store.WithDB(func(db *DB) error {
		db.AbuseReports = append(db.AbuseReports, abuse)
		var owner User
		for _, user := range db.Users {
			if user.ID == publication.OwnerID {
				owner = user
				break
			}
		}
		if decision.Block {
			for i := range db.Publications {
				if db.Publications[i].ID == publication.ID {
					db.Publications[i].BlockedAt = now
					db.Publications[i].BlockedReason = decision.Summary
					break
				}
			}
			db.Strikes = append(db.Strikes, Strike{
				ID:            NewID("str"),
				UserID:        owner.ID,
				Email:         owner.Email,
				IP:            publication.CreatedIP,
				PublicationID: publication.ID,
				AbuseID:       abuse.ID,
				Reason:        decision.Summary,
				Severity:      decision.Severity,
				CreatedAt:     now,
				ExpiresAt:     now.Add(30 * 24 * time.Hour),
			})
		}
		if decision.Block && (decision.Severity == "critical" || activeStrikeCount(db.Strikes, owner.Email, publication.CreatedIP, now) >= 3) {
			reason := "48 hour abuse ban: " + decision.Summary
			db.Bans = append(db.Bans, Ban{ID: NewID("ban"), UserID: owner.ID, Email: owner.Email, Reason: reason, CreatedAt: now, ExpiresAt: now.Add(48 * time.Hour)})
			if publication.CreatedIP != "" {
				db.Bans = append(db.Bans, Ban{ID: NewID("ban"), IP: publication.CreatedIP, Reason: reason, CreatedAt: now, ExpiresAt: now.Add(48 * time.Hour)})
			}
		}
		return nil
	})
}

func (s *Server) publicationAsset(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/f/")
	parts := strings.SplitN(rest, "/", 2)
	slug := parts[0]
	file := "index.html"
	if len(parts) == 2 && strings.Trim(parts[1], "/") != "" {
		file = parts[1]
	}
	publication, ok := s.findPublicationBySlug(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !publication.ExpiresAt.IsZero() && time.Now().After(publication.ExpiresAt) {
		user := s.currentUser(r)
		s.logPublicationAccess(r, publication, file, user, false, http.StatusGone)
		http.Error(w, "publication expired", http.StatusGone)
		return
	}
	if !publication.BlockedAt.IsZero() {
		s.logPublicationAccess(r, publication, file, nil, false, http.StatusUnavailableForLegalReasons)
		http.Error(w, "publication blocked: "+publication.BlockedReason, http.StatusUnavailableForLegalReasons)
		return
	}
	user := s.currentUser(r)
	if !s.canReadPublication(r, publication) {
		s.logPublicationAccess(r, publication, file, user, false, http.StatusForbidden)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	raw, err := s.Store.ReadPublicationFile(publication.ID, file)
	if err != nil {
		s.logPublicationAccess(r, publication, file, user, false, http.StatusNotFound)
		http.NotFound(w, r)
		return
	}
	ctype := mime.TypeByExtension(filepath.Ext(file))
	if ctype == "" {
		ctype = http.DetectContentType(raw)
	}
	if file == "index.html" && strings.Contains(ctype, "text/html") {
		raw = s.redactPublicationAccessTargets(raw, publication)
		raw = injectCommentWidget(raw, publication.Slug)
	}
	setPrivateRevalidateCache(w)
	w.Header().Set("content-type", ctype)
	etag := weakETag(raw)
	w.Header().Set("etag", etag)
	if !publication.CreatedAt.IsZero() {
		w.Header().Set("last-modified", publication.CreatedAt.UTC().Format(http.TimeFormat))
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("content-disposition", `attachment; filename="`+downloadFilename(publication.Slug, file)+`"`)
	}
	if r.URL.Query().Get("download") != "1" && etagMatches(r.Header.Get("if-none-match"), etag) {
		s.logPublicationAccess(r, publication, file, user, true, http.StatusNotModified)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	s.logPublicationAccess(r, publication, file, user, true, http.StatusOK)
	_, _ = io.Copy(w, bytes.NewReader(raw))
}

func (s *Server) magic(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	hash := HashToken(token)
	if r.Method == http.MethodGet {
		var link MagicLink
		var user User
		var publication Publication
		err := s.Store.WithDB(func(db *DB) error {
			for _, candidate := range db.MagicLinks {
				if candidate.TokenHash == hash && candidate.UsedAt.IsZero() && candidate.ExpiresAt.After(time.Now()) {
					link = candidate
					break
				}
			}
			if link.ID == "" {
				return errors.New("invalid magic link")
			}
			for _, candidate := range db.Users {
				if candidate.ID == link.UserID {
					user = candidate
					break
				}
			}
			if user.ID == "" {
				return errors.New("user not found")
			}
			if link.PublicationID != "" {
				for _, candidate := range db.Publications {
					if candidate.ID == link.PublicationID {
						publication = candidate
						break
					}
				}
			}
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if link.Purpose == "signup" {
			_, _ = io.WriteString(w, confirmMagicHTML(token, user.Email))
			return
		}
		if link.Purpose == "share" {
			_, _ = io.WriteString(w, confirmShareHTML(token, publication.Title))
			return
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var user User
	var publicationSlug string
	err := s.Store.WithDB(func(db *DB) error {
		for i := range db.MagicLinks {
			link := &db.MagicLinks[i]
			if link.TokenHash == hash && link.UsedAt.IsZero() && link.ExpiresAt.After(time.Now()) {
				link.UsedAt = time.Now()
				for i := range db.Users {
					candidate := db.Users[i]
					if candidate.ID == link.UserID {
						if db.Users[i].EmailConfirmedAt == nil {
							now := time.Now()
							db.Users[i].EmailConfirmedAt = &now
							db.Users[i].AutoProvisioned = false
						}
						candidate = db.Users[i]
						user = candidate
						if link.Purpose == "signup" {
							extendSignupAPIKeys(db, user.ID, time.Now())
						}
						break
					}
				}
				if link.PublicationID != "" {
					for _, publication := range db.Publications {
						if publication.ID == link.PublicationID {
							publicationSlug = publication.Slug
						}
					}
				}
				return nil
			}
		}
		return errors.New("invalid magic link")
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	session := Session{ID: NewID("ses"), UserID: user.ID, ExpiresAt: time.Now().Add(30 * 24 * time.Hour), CreatedAt: time.Now()}
	_ = s.Store.WithDB(func(db *DB) error {
		db.Sessions = append(db.Sessions, session)
		return nil
	})
	http.SetCookie(w, SessionCookie(session.ID, s.SessionSecret))
	if publicationSlug != "" {
		http.Redirect(w, r, "/f/"+publicationSlug+"/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/app/", http.StatusFound)
}

func (s *Server) signedAccess(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	hash := HashToken(raw)
	var user User
	var publicationSlug string
	var tokenID string
	err := s.Store.WithDB(func(db *DB) error {
		for i := range db.SignedTokens {
			token := &db.SignedTokens[i]
			if token.TokenHash == hash && token.UsedAt.IsZero() && token.ExpiresAt.After(time.Now()) {
				token.UsedAt = time.Now()
				tokenID = token.ID
				email := token.Email
				for j := range db.Users {
					if db.Users[j].Email == email {
						now := time.Now()
						db.Users[j].EmailConfirmedAt = &now
						db.Users[j].AutoProvisioned = false
						user = db.Users[j]
						break
					}
				}
				if user.ID == "" {
					now := time.Now()
					user = User{ID: NewID("usr"), Email: email, Provider: "signed", EmailConfirmedAt: &now, CreatedAt: now}
					db.Users = append(db.Users, user)
				}
				for _, publication := range db.Publications {
					if publication.ID == token.PublicationID {
						publicationSlug = publication.Slug
						db.Shares = append(db.Shares, Share{ID: NewID("shr"), PublicationID: publication.ID, Email: email, UserID: user.ID, CreatedAt: time.Now()})
						break
					}
				}
				db.SignedProofs = append(db.SignedProofs, SignedAccessProof{
					ID:            NewID("sap"),
					PublicationID: token.PublicationID,
					Email:         email,
					IP:            clientIP(r),
					UserAgent:     r.UserAgent(),
					TokenID:       token.ID,
					CreatedAt:     time.Now(),
				})
				return nil
			}
		}
		return errors.New("invalid signed access token")
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	session := Session{ID: NewID("ses"), UserID: user.ID, ExpiresAt: time.Now().Add(30 * 24 * time.Hour), CreatedAt: time.Now()}
	_ = s.Store.WithDB(func(db *DB) error {
		db.Sessions = append(db.Sessions, session)
		return nil
	})
	_ = tokenID
	http.SetCookie(w, SessionCookie(session.ID, s.SessionSecret))
	http.Redirect(w, r, "/f/"+publicationSlug+"/", http.StatusFound)
}

func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if !publicLoginEnabled {
		http.Error(w, "public login is disabled in this version", http.StatusGone)
		return
	}
	if s.GoogleClient == "" {
		http.Error(w, "google oauth is not configured", http.StatusNotImplemented)
		return
	}
	if s.GoogleSecret == "" {
		http.Redirect(w, r, "/app/", http.StatusFound)
		return
	}
	redirect := s.GoogleRedirect
	if redirect == "" {
		redirect = s.AppURL + "/auth/google/callback"
	}
	q := url.Values{}
	q.Set("client_id", s.GoogleClient)
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("prompt", "select_account")
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+q.Encode(), http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	if !publicLoginEnabled {
		http.Error(w, "public login is disabled in this version", http.StatusGone)
		return
	}
	if s.GoogleClient == "" || s.GoogleSecret == "" {
		http.Error(w, "google oauth is not configured", http.StatusNotImplemented)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}
	redirect := s.GoogleRedirect
	if redirect == "" {
		redirect = s.AppURL + "/auth/google/callback"
	}
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", s.GoogleClient)
	form.Set("client_secret", s.GoogleSecret)
	form.Set("redirect_uri", redirect)
	form.Set("grant_type", "authorization_code")
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", form)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		http.Error(w, "google token exchange failed", http.StatusBadGateway)
		return
	}
	var tokenBody struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	profileReq, _ := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	profileReq.Header.Set("authorization", "Bearer "+tokenBody.AccessToken)
	profileResp, err := http.DefaultClient.Do(profileReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer profileResp.Body.Close()
	if profileResp.StatusCode < 200 || profileResp.StatusCode >= 300 {
		http.Error(w, "google profile fetch failed", http.StatusBadGateway)
		return
	}
	var profile struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(profileResp.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	profile.Email = strings.ToLower(strings.TrimSpace(profile.Email))
	if profile.Email == "" {
		http.Error(w, "google profile missing email", http.StatusBadGateway)
		return
	}
	user := s.upsertOAuthUser(profile.Email, profile.Name, "google")
	session := Session{ID: NewID("ses"), UserID: user.ID, ExpiresAt: time.Now().Add(30 * 24 * time.Hour), CreatedAt: time.Now()}
	_ = s.Store.WithDB(func(db *DB) error {
		db.Sessions = append(db.Sessions, session)
		return nil
	})
	http.SetCookie(w, SessionCookie(session.ID, s.SessionSecret))
	http.Redirect(w, r, "/app/", http.StatusFound)
}

func (s *Server) googleIDToken(w http.ResponseWriter, r *http.Request) {
	if !publicLoginEnabled {
		http.Error(w, "public login is disabled in this version", http.StatusGone)
		return
	}
	if s.GoogleClient == "" {
		http.Error(w, "google oauth is not configured", http.StatusNotImplemented)
		return
	}
	var req struct {
		Credential string `json:"credential"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Credential = strings.TrimSpace(req.Credential)
	if req.Credential == "" {
		http.Error(w, "credential required", http.StatusBadRequest)
		return
	}
	verifyURL := "https://oauth2.googleapis.com/tokeninfo?id_token=" + url.QueryEscape(req.Credential)
	resp, err := http.Get(verifyURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "google token verification failed", http.StatusUnauthorized)
		return
	}
	var token struct {
		Audience      string `json:"aud"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if token.Audience != s.GoogleClient {
		http.Error(w, "google token audience mismatch", http.StatusUnauthorized)
		return
	}
	verified := false
	switch value := token.EmailVerified.(type) {
	case bool:
		verified = value
	case string:
		verified = value == "true"
	}
	token.Email = strings.ToLower(strings.TrimSpace(token.Email))
	if token.Email == "" || !verified {
		http.Error(w, "google profile missing verified email", http.StatusUnauthorized)
		return
	}
	user := s.upsertOAuthUser(token.Email, token.Name, "google")
	session := Session{ID: NewID("ses"), UserID: user.ID, ExpiresAt: time.Now().Add(30 * 24 * time.Hour), CreatedAt: time.Now()}
	_ = s.Store.WithDB(func(db *DB) error {
		db.Sessions = append(db.Sessions, session)
		return nil
	})
	http.SetCookie(w, SessionCookie(session.ID, s.SessionSecret))
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

func (s *Server) createMagicLink(user User, purpose, publicationID string) (string, error) {
	raw := "hml_" + RandomToken(32)
	expiresAt := time.Now().Add(72 * time.Hour)
	if purpose == "signup" {
		expiresAt = time.Now().Add(24 * time.Hour)
	}
	link := MagicLink{ID: NewID("ml"), UserID: user.ID, Email: user.Email, TokenHash: HashToken(raw), Purpose: purpose, PublicationID: publicationID, ExpiresAt: expiresAt, CreatedAt: time.Now()}
	if err := s.Store.AddMagicLink(link); err != nil {
		return "", err
	}
	return s.AppURL + "/auth/magic?token=" + raw, nil
}

func (s *Server) upsertOAuthUser(email, name, provider string) User {
	now := time.Now()
	var user User
	_ = s.Store.WithDB(func(db *DB) error {
		for i := range db.Users {
			if db.Users[i].Email == email {
				if db.Users[i].Name == "" {
					db.Users[i].Name = name
				}
				db.Users[i].Provider = provider
				db.Users[i].EmailConfirmedAt = &now
				db.Users[i].AutoProvisioned = false
				user = db.Users[i]
				return nil
			}
		}
		user = User{ID: NewID("usr"), Email: email, Name: name, Provider: provider, EmailConfirmedAt: &now, CreatedAt: now}
		db.Users = append(db.Users, user)
		return nil
	})
	return user
}

func (s *Server) sharePublication(publication Publication, target, message string) (string, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if !validRecipientTarget(target) {
		return "", errors.New("valid recipient email or @domain required")
	}
	if strings.HasPrefix(target, "@") {
		if err := s.Store.AddShare(Share{ID: NewID("shr"), PublicationID: publication.ID, Email: target, CreatedAt: time.Now()}); err != nil {
			return "", err
		}
		return s.AppURL + "/f/" + publication.Slug + "/", nil
	}
	now := time.Now()
	user, err := s.Store.EnsureMagicUser(target, now)
	if err != nil {
		return "", err
	}
	if err := s.Store.AddShare(Share{ID: NewID("shr"), PublicationID: publication.ID, Email: target, UserID: user.ID, CreatedAt: now}); err != nil {
		return "", err
	}
	link, err := s.createMagicLink(user, "share", publication.ID)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(message + "\n\n" + publication.Title + "\n" + link)
	html := fmt.Sprintf(`<p>%s</p><p><a href="%s">Open file</a></p>`, htmlEscape(message), link)
	_ = s.Mailer.Send(target, "Shared file: "+publication.Title, text, html)
	return link, nil
}

func (s *Server) requireAutomationUser(w http.ResponseWriter, r *http.Request) *User {
	if user := s.currentUser(r); user != nil {
		if !user.EmailConfirmed() {
			http.Error(w, "email confirmation required", http.StatusForbidden)
			return nil
		}
		return user
	}
	auth := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
	if auth == "" {
		http.Error(w, "session or bearer api key required", http.StatusUnauthorized)
		return nil
	}
	user, err := s.Store.UserByAPIKey(HashToken(auth), time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if user == nil {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
	}
	return user
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) *User {
	user := s.currentUser(r)
	if user == nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return nil
	}
	if !user.EmailConfirmed() {
		http.Error(w, "email confirmation required", http.StatusForbidden)
		return nil
	}
	return user
}

func (s *Server) currentUser(r *http.Request) *User {
	sessionID := VerifySessionCookie(r, s.SessionSecret)
	if sessionID == "" {
		return nil
	}
	var user *User
	_ = s.Store.ReadDB(func(db DB) error {
		for _, session := range db.Sessions {
			if session.ID == sessionID && session.ExpiresAt.After(time.Now()) {
				for _, candidate := range db.Users {
					if candidate.ID == session.UserID {
						copy := candidate
						user = &copy
					}
				}
			}
		}
		return nil
	})
	return user
}

func (s *Server) canReadPublication(r *http.Request, publication Publication) bool {
	if publication.Visibility == "public" {
		return true
	}
	user := s.currentUser(r)
	if user == nil {
		return false
	}
	allowed := false
	_ = s.Store.ReadDB(func(db DB) error {
		allowed = publicationCanBeReadByUser(db, publication, *user)
		return nil
	})
	return allowed
}

func (s *Server) logPublicationAccess(r *http.Request, publication Publication, path string, user *User, allowed bool, status int) {
	entry := AccessLog{
		ID:            NewID("acl"),
		PublicationID: publication.ID,
		Slug:          publication.Slug,
		Path:          path,
		IP:            clientIP(r),
		UserAgent:     r.UserAgent(),
		Allowed:       allowed,
		Status:        status,
		CreatedAt:     time.Now(),
	}
	if user != nil {
		entry.UserID = user.ID
		entry.Email = user.Email
	}
	_ = s.Store.AddAccessLog(entry)
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("x-forwarded-for")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := strings.TrimSpace(r.Header.Get("x-real-ip")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) findPublicationBySlug(slug string) (Publication, bool) {
	var found Publication
	ok := false
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if publication.Slug == slug {
				found, ok = publication, true
			}
		}
		return nil
	})
	return found, ok
}

func (s *Server) findPublicationForAbuse(id, slug string) (Publication, bool) {
	var found Publication
	ok := false
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if (id != "" && publication.ID == id) || (slug != "" && publication.Slug == slug) {
				found, ok = publication, true
				return nil
			}
		}
		return nil
	})
	return found, ok
}

func (s *Server) findPublicationOwned(idOrSlug, ownerID string) (Publication, bool) {
	var found Publication
	ok := false
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if publication.OwnerID == ownerID && (publication.ID == idOrSlug || publication.Slug == idOrSlug) {
				found, ok = publication, true
			}
		}
		return nil
	})
	return found, ok
}

func (s *Server) findAccessiblePublication(id, slug string, user User) (Publication, bool) {
	var found Publication
	ok := false
	_ = s.Store.ReadDB(func(db DB) error {
		for _, publication := range db.Publications {
			if (id != "" && publication.ID == id) || (slug != "" && publication.Slug == slug) {
				if publicationCanBeReadByUser(db, publication, user) {
					found, ok = publication, true
				}
				return nil
			}
		}
		return nil
	})
	return found, ok
}

func publicationsSharedWithUser(db DB, user User) []Publication {
	seen := map[string]bool{}
	var publications []Publication
	shared := map[string]bool{}
	for _, share := range db.Shares {
		if share.UserID == user.ID || share.Email == user.Email || domainShareMatches(share.Email, user.Email) {
			shared[share.PublicationID] = true
		}
	}
	for _, publication := range db.Publications {
		if publication.OwnerID == user.ID {
			continue
		}
		if !shared[publication.ID] {
			continue
		}
		if seen[publication.ID] {
			continue
		}
		seen[publication.ID] = true
		publications = append(publications, publication)
	}
	sort.Slice(publications, func(i, j int) bool { return publications[i].CreatedAt.After(publications[j].CreatedAt) })
	return publications
}

func publicationCanBeReadByUser(db DB, publication Publication, user User) bool {
	if publication.Visibility == "public" {
		return true
	}
	if user.ID == "" {
		return false
	}
	if user.ID == publication.OwnerID {
		return true
	}
	if publication.Visibility == "recipients" || publication.Visibility == "signed" || publication.Visibility == "magic" {
		for _, share := range db.Shares {
			if share.PublicationID != publication.ID {
				continue
			}
			if share.UserID == user.ID || share.Email == user.Email || domainShareMatches(share.Email, user.Email) {
				return true
			}
		}
	}
	return false
}

func ownedPublicationSet(publications []Publication, ownerID string) map[string]bool {
	owned := make(map[string]bool)
	for _, publication := range publications {
		if publication.OwnerID == ownerID {
			owned[publication.ID] = true
		}
	}
	return owned
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	setNoStore(w)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func trimAPIVersionPath(path string) string {
	if strings.HasPrefix(path, "/api/v1/") {
		return "/api/" + strings.TrimPrefix(path, "/api/v1/")
	}
	if path == "/api/v1" {
		return "/api"
	}
	return path
}

func validVisibility(value string) bool {
	switch value {
	case "private", "magic", "recipients", "signed", "public":
		return true
	default:
		return false
	}
}

type fastPublishLimits struct {
	MaxFiles                 int
	MaxFileBytes             int64
	MaxRequestBytes          int64
	MaxIPPublishesPerHour    int64
	MaxAgentPublishesPerHour int64
	MaxIPStorageBytes        int64
	MaxAgentStorageBytes     int64
	DefaultTTL               time.Duration
	MaxTTL                   time.Duration
}

func fastPublishLimitsFromEnv() fastPublishLimits {
	return fastPublishLimits{
		MaxFiles:                 envInt("HTMLSHARE_FAST_MAX_FILES", 20),
		MaxFileBytes:             envInt64("HTMLSHARE_FAST_MAX_FILE_BYTES", 2*1024*1024),
		MaxRequestBytes:          envInt64("HTMLSHARE_FAST_MAX_REQUEST_BYTES", 8*1024*1024),
		MaxIPPublishesPerHour:    int64(envInt("HTMLSHARE_FAST_MAX_IP_PUBLISHES_PER_HOUR", 30)),
		MaxAgentPublishesPerHour: int64(envInt("HTMLSHARE_FAST_MAX_AGENT_PUBLISHES_PER_HOUR", 60)),
		MaxIPStorageBytes:        envInt64("HTMLSHARE_FAST_MAX_IP_STORAGE_BYTES", 100*1024*1024),
		MaxAgentStorageBytes:     envInt64("HTMLSHARE_FAST_MAX_AGENT_STORAGE_BYTES", 100*1024*1024),
		DefaultTTL:               time.Duration(envInt("HTMLSHARE_FAST_DEFAULT_TTL_SECONDS", 24*60*60)) * time.Second,
		MaxTTL:                   time.Duration(envInt("HTMLSHARE_FAST_MAX_TTL_SECONDS", 7*24*60*60)) * time.Second,
	}
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envInt64(name string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func validRecipientTarget(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "@") {
		domain := strings.TrimPrefix(value, "@")
		return strings.Contains(domain, ".") && !strings.ContainsAny(domain, " /\\")
	}
	parts := strings.Split(value, "@")
	return len(parts) == 2 && parts[0] != "" && strings.Contains(parts[1], ".") && !strings.ContainsAny(value, " /\\")
}

func normalizeShareTargets(values []string) ([]string, error) {
	if len(values) > 50 {
		return nil, errors.New("too many recipients")
	}
	seen := map[string]bool{}
	var targets []string
	for _, value := range values {
		target := strings.ToLower(strings.TrimSpace(value))
		if target == "" {
			continue
		}
		if !validRecipientTarget(target) {
			return nil, errors.New("valid recipient email or @domain required: " + target)
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	return targets, nil
}

func (s *Server) redactPublicationAccessTargets(raw []byte, publication Publication) []byte {
	if publication.Visibility != "recipients" && publication.Visibility != "signed" {
		return raw
	}
	var targets []string
	_ = s.Store.ReadDB(func(db DB) error {
		for _, share := range db.Shares {
			if share.PublicationID == publication.ID && share.Email != "" {
				targets = append(targets, strings.ToLower(strings.TrimSpace(share.Email)))
			}
		}
		for _, token := range db.SignedTokens {
			if token.PublicationID == publication.ID && token.Email != "" {
				targets = append(targets, strings.ToLower(strings.TrimSpace(token.Email)))
			}
		}
		return nil
	})
	if len(targets) == 0 {
		return raw
	}
	sort.Slice(targets, func(i, j int) bool {
		return len(targets[i]) > len(targets[j])
	})
	body := string(raw)
	for _, target := range targets {
		if target == "" {
			continue
		}
		replacement := "authorized recipient"
		if strings.HasPrefix(target, "@") {
			replacement = "authorized domain"
		}
		body = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(target)).ReplaceAllString(body, replacement)
	}
	if looksLikeAccessNoticeHTML(body) {
		return []byte(accessControlledDocumentHTML(publication.Title))
	}
	return []byte(body)
}

func looksLikeAccessNoticeHTML(body string) bool {
	normalized := strings.ToLower(body)
	return strings.Contains(normalized, "html restringido") ||
		strings.Contains(normalized, "visible solo por authorized recipient") ||
		strings.Contains(normalized, "visible only by authorized recipient") ||
		strings.Contains(normalized, "visible only to authorized recipient") ||
		strings.Contains(normalized, "enlace magico enviado por htmlshare") ||
		strings.Contains(normalized, "magic link sent by htmlshare")
}

func accessControlledDocumentHTML(title string) string {
	if strings.TrimSpace(title) == "" {
		title = "Shared file"
	}
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + htmlEscape(title) + `</title>
  <style>
    :root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2937;background:#f7f2ea}
    body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px}
    main{width:min(100%,760px);background:#fff;border:1px solid #d9d0c3;border-radius:12px;padding:44px;box-shadow:0 18px 50px rgba(31,41,55,.08)}
    h1{margin:0 0 18px;font-size:42px;line-height:1.05}
    p{font-size:18px;line-height:1.6;margin:0;color:#4b5563}
  </style>
</head>
<body>
  <main>
    <h1>Access controlled file</h1>
    <p>This file is protected by htmlshare. Open it from the email link sent to an authorized recipient.</p>
  </main>
</body>
</html>`
}

func domainShareMatches(shareTarget, email string) bool {
	shareTarget = strings.ToLower(strings.TrimSpace(shareTarget))
	email = strings.ToLower(strings.TrimSpace(email))
	return strings.HasPrefix(shareTarget, "@") && strings.HasSuffix(email, shareTarget)
}

func publicUser(user User) map[string]string {
	confirmed := "false"
	if user.EmailConfirmed() {
		confirmed = "true"
	}
	return map[string]string{"id": user.ID, "email": user.Email, "name": user.Name, "provider": user.Provider, "email_confirmed": confirmed}
}

func filterSessions(items []Session, expiredUsers map[string]bool) []Session {
	var kept []Session
	for _, item := range items {
		if !expiredUsers[item.UserID] {
			kept = append(kept, item)
		}
	}
	return kept
}

func filterMagicLinks(items []MagicLink, expiredUsers, expiredPublications map[string]bool) []MagicLink {
	var kept []MagicLink
	for _, item := range items {
		if !expiredUsers[item.UserID] && !expiredPublications[item.PublicationID] {
			kept = append(kept, item)
		}
	}
	return kept
}

func filterAPIKeys(items []APIKey, expiredUsers map[string]bool) []APIKey {
	var kept []APIKey
	now := time.Now()
	for _, item := range items {
		if !expiredUsers[item.UserID] && (item.ExpiresAt.IsZero() || item.ExpiresAt.After(now)) {
			kept = append(kept, item)
		}
	}
	return kept
}

func extendSignupAPIKeys(db *DB, userID string, now time.Time) {
	cutoff := now.Add(25 * time.Hour)
	for i := range db.APIKeys {
		if db.APIKeys[i].UserID == userID && (db.APIKeys[i].ExpiresAt.IsZero() || db.APIKeys[i].ExpiresAt.Before(cutoff)) {
			db.APIKeys[i].ExpiresAt = now.Add(365 * 24 * time.Hour)
		}
	}
}

func filterShares(items []Share, expiredUsers, expiredPublications map[string]bool) []Share {
	var kept []Share
	for _, item := range items {
		if !expiredUsers[item.UserID] && !expiredPublications[item.PublicationID] {
			kept = append(kept, item)
		}
	}
	return kept
}

func filterAccessLogs(items []AccessLog, expiredUsers, expiredPublications map[string]bool) []AccessLog {
	var kept []AccessLog
	for _, item := range items {
		if !expiredUsers[item.UserID] && !expiredPublications[item.PublicationID] {
			kept = append(kept, item)
		}
	}
	return kept
}

func filterActiveBans(items []Ban, now time.Time) []Ban {
	var kept []Ban
	for _, item := range items {
		if item.ExpiresAt.After(now) {
			kept = append(kept, item)
		}
	}
	return kept
}

func filterActiveStrikes(items []Strike, now time.Time) []Strike {
	var kept []Strike
	for _, item := range items {
		if item.ExpiresAt.IsZero() || item.ExpiresAt.After(now) {
			kept = append(kept, item)
		}
	}
	return kept
}

func activeStrikeCount(items []Strike, email, ip string, now time.Time) int {
	count := 0
	for _, item := range items {
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			continue
		}
		if (email != "" && item.Email == email) || (ip != "" && item.IP == ip) {
			count++
		}
	}
	return count
}

func (s *Server) activeBan(ip, email string, now time.Time) (Ban, bool) {
	var found Ban
	ok := false
	_ = s.Store.ReadDB(func(db DB) error {
		for _, ban := range db.Bans {
			if now.After(ban.ExpiresAt) {
				continue
			}
			if (email != "" && ban.Email == email) || (ip != "" && ban.IP == ip) {
				found, ok = ban, true
				return nil
			}
		}
		return nil
	})
	return found, ok
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("referrer-policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("cache-control", "no-store")
}

func setNoCache(w http.ResponseWriter) {
	w.Header().Set("cache-control", "no-cache, max-age=0, must-revalidate")
}

func setPrivateRevalidateCache(w http.ResponseWriter) {
	w.Header().Set("cache-control", "private, no-cache, max-age=0, must-revalidate")
	w.Header().Set("vary", "Cookie, Authorization")
}

func setPublicCache(w http.ResponseWriter, maxAge time.Duration) {
	seconds := int(maxAge.Seconds())
	w.Header().Set("cache-control", fmt.Sprintf("public, max-age=%d, stale-while-revalidate=%d", seconds, seconds))
}

func setImmutableCache(w http.ResponseWriter) {
	w.Header().Set("cache-control", "public, max-age=31536000, immutable")
}

func weakETag(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf(`W/"%x"`, sum[:])
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

func downloadFilename(slug, file string) string {
	ext := filepath.Ext(file)
	if ext == "" {
		ext = ".html"
	}
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, slug)
	name = strings.Trim(name, "-_")
	if name == "" {
		name = "htmlshare"
	}
	return name + ext
}

type captchaChallenge struct {
	Question string
	Token    string
}

func (s *Server) newCaptcha(slug string) captchaChallenge {
	sum := sha256.Sum256([]byte(RandomToken(16) + slug))
	a := int(sum[0]%8) + 2
	b := int(sum[1]%8) + 2
	expires := time.Now().Add(15 * time.Minute).Unix()
	payload := strings.Join([]string{slug, strconv.Itoa(a), strconv.Itoa(b), strconv.FormatInt(expires, 10)}, "|")
	signature := s.signCaptchaPayload(payload)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + signature))
	return captchaChallenge{Question: fmt.Sprintf("%d + %d", a, b), Token: token}
}

func (s *Server) validateCaptcha(slug, answer, token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 5 || parts[0] != slug {
		return false
	}
	payload := strings.Join(parts[:4], "|")
	if !hmac.Equal([]byte(parts[4]), []byte(s.signCaptchaPayload(payload))) {
		return false
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return false
	}
	a, errA := strconv.Atoi(parts[1])
	b, errB := strconv.Atoi(parts[2])
	got, errGot := strconv.Atoi(answer)
	return errA == nil && errB == nil && errGot == nil && got == a+b
}

func (s *Server) signCaptchaPayload(payload string) string {
	secret := s.SessionSecret
	if secret == "" {
		secret = "htmlshare-local-secret"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func confirmMagicHTML(token, email string) string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Confirm htmlshare token</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#242624;color:#fefaf6}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:#f5f2ed;background-image:linear-gradient(rgba(36,38,36,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(36,38,36,.08) 1px,transparent 1px);background-size:72px 72px}
    main{width:min(100%,560px);background:#242624;border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 70px rgba(0,0,0,.18);padding:36px}.brand-page{display:inline-flex;align-items:center;gap:10px;color:#fefaf6;text-decoration:none}.brand-page img{width:58px;height:34px;object-fit:contain}.brand-page b{font-size:18px;letter-spacing:-.03em}.brand-page span{color:#b8bab8;font-weight:400}
    h1{margin:28px 0 10px;font-size:42px;line-height:.96;letter-spacing:-.03em}p{color:#b8bab8;line-height:1.55}.eyebrow{margin:24px 0 0;color:#b8a8d8;font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
    button{width:100%;min-height:52px;margin-top:18px;border:0;border-radius:999px;background:#fefaf6;color:#242624;padding:0 22px;font:800 15px/1 inherit;cursor:pointer}
  </style>
</head>
<body>
  <main>
    <a class="brand-page" href="/"><img src="/logo.png" alt=""><b>html<span>share</span></b></a>
    <p class="eyebrow">Confirm email</p>
    <h1>Activate your agent token.</h1>
    <p>This confirms <strong>` + htmlEscape(email) + `</strong> and extends the temporary agent token from 24 hours to 1 year.</p>
    <form method="post" action="/auth/magic?token=` + url.QueryEscape(token) + `">
      <button type="submit">Confirm and activate</button>
    </form>
  </main>
</body>
</html>`
}

func confirmShareHTML(token, title string) string {
	if title == "" {
		title = "shared file"
	}
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Open shared file · htmlshare</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#242624;color:#fefaf6}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:#f5f2ed;background-image:linear-gradient(rgba(36,38,36,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(36,38,36,.08) 1px,transparent 1px);background-size:72px 72px}
    main{width:min(100%,560px);background:#242624;border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 70px rgba(0,0,0,.18);padding:36px}.brand-page{display:inline-flex;align-items:center;gap:10px;color:#fefaf6;text-decoration:none}.brand-page img{width:58px;height:34px;object-fit:contain}.brand-page b{font-size:18px;letter-spacing:-.03em}.brand-page span{color:#b8bab8;font-weight:400}
    h1{margin:28px 0 10px;font-size:42px;line-height:.96;letter-spacing:-.03em}p{color:#b8bab8;line-height:1.55}.eyebrow{margin:24px 0 0;color:#b8a8d8;font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
    button{width:100%;min-height:52px;margin-top:18px;border:0;border-radius:999px;background:#fefaf6;color:#242624;padding:0 22px;font:800 15px/1 inherit;cursor:pointer}
  </style>
</head>
<body>
  <main>
    <a class="brand-page" href="/"><img src="/logo.png" alt=""><b>html<span>share</span></b></a>
    <p class="eyebrow">Email access</p>
    <h1>Open this shared file.</h1>
    <p>This confirms email access and opens <strong>` + htmlEscape(title) + `</strong>. The token is only consumed when you press the button.</p>
    <form method="post" action="/auth/magic?token=` + url.QueryEscape(token) + `">
      <button type="submit">Open file</button>
    </form>
  </main>
</body>
</html>`
}

func abuseFormHTML(publication Publication, challenge captchaChallenge, message string) string {
	alert := ""
	if message != "" {
		alert = `<div class="alert">` + htmlEscape(message) + `</div>`
	}
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Publication abuse · htmlshare</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#242624;color:#fefaf6}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:#f5f2ed;background-image:linear-gradient(rgba(36,38,36,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(36,38,36,.08) 1px,transparent 1px);background-size:72px 72px}
    main{width:min(100%,720px);background:#242624;border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 70px rgba(0,0,0,.18);padding:36px}.brand-page{display:inline-flex;align-items:center;gap:10px;color:#fefaf6;text-decoration:none}.brand-page img{width:58px;height:34px;object-fit:contain}.brand-page b{font-size:18px;letter-spacing:-.03em}.brand-page span{color:#b8bab8;font-weight:400}
    a{color:#b8a8d8}p{color:#b8bab8;line-height:1.55}h1{margin:8px 0 10px;font-size:42px;line-height:.96;letter-spacing:-.03em}.eyebrow{margin:0;color:#b8a8d8;font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
    form{display:grid;gap:18px;margin-top:28px}label{display:grid;gap:8px;color:#b8bab8;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}input,select,textarea{width:100%;border:1px solid rgba(255,255,255,.14);border-radius:12px;background:#181a18;color:#fefaf6;padding:13px 14px;font:500 15px/1.4 inherit;outline:0;letter-spacing:0;text-transform:none}textarea{min-height:132px;resize:vertical}.row{display:grid;grid-template-columns:1fr 160px;gap:12px}.captcha{padding:16px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:#292b29}.captcha b{display:block;margin-bottom:10px;font-size:22px}.alert{padding:12px 14px;border:1px solid rgba(248,123,115,.38);border-radius:12px;color:#f87b73;background:rgba(248,123,115,.1)}
    button{min-height:48px;border:0;border-radius:999px;background:#fefaf6;color:#242624;padding:0 22px;font:800 15px/1 inherit;cursor:pointer}.secondary{display:inline-flex;margin-top:18px;color:#b8bab8;text-decoration:none}
    @media(max-width:640px){body{padding:0;place-items:stretch}main{min-height:100vh;padding:28px;border:0}.row{grid-template-columns:1fr}h1{font-size:36px}}
  </style>
</head>
<body>
  <main>
    <a class="brand-page" href="/"><img src="/logo.png" alt=""><b>html<span>share</span></b></a>
    <p class="eyebrow">htmlshare · abuse notice</p>
    <h1>Publication abuse</h1>
    <p>We will review this content automatically and may block it when appropriate. This page uses a local captcha to prevent automated submissions.</p>
    <p><strong>` + htmlEscape(publication.Title) + `</strong><br><a href="/f/` + url.QueryEscape(publication.Slug) + `/">/f/` + htmlEscape(publication.Slug) + `/</a></p>
    ` + alert + `
    <form method="post" action="/abuse" autocomplete="on">
      <input type="hidden" name="slug" value="` + htmlEscape(publication.Slug) + `">
      <input type="hidden" name="captcha_token" value="` + htmlEscape(challenge.Token) + `">
      <label>Optional email
        <input type="email" name="reporter_email" placeholder="you@example.com">
      </label>
      <label>Reason
        <select name="reason" required>
          <option value="phishing">Phishing / credential theft</option>
          <option value="malware">Malware</option>
          <option value="spam">Spam</option>
          <option value="harassment">Harassment</option>
          <option value="illegal">Illegal content</option>
          <option value="other">Other</option>
        </select>
      </label>
      <label>Details
        <textarea name="details" required placeholder="Explain the abuse, legal concern, or risk in this content."></textarea>
      </label>
      <div class="captcha">
        <label>Captcha
          <div class="row">
            <b>` + htmlEscape(challenge.Question) + ` =</b>
            <input inputmode="numeric" pattern="[0-9]*" name="captcha_answer" required placeholder="Answer">
          </div>
        </label>
      </div>
      <button type="submit">Submit notice</button>
    </form>
    <a class="secondary" href="/f/` + url.QueryEscape(publication.Slug) + `/">Back to content</a>
  </main>
</body>
</html>`
}

func abuseSubmittedHTML(publication Publication, abuse AbuseReport, decision AbuseDecision) string {
	status := "Received"
	if abuse.AutoBlocked {
		status = "Automatically blocked"
	}
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Abuse notice received · htmlshare</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <style>
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#242624;color:#fefaf6}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:#f5f2ed;background-image:linear-gradient(rgba(36,38,36,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(36,38,36,.08) 1px,transparent 1px);background-size:72px 72px}
    main{width:min(100%,640px);background:#242624;border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 70px rgba(0,0,0,.18);padding:36px}.brand-page{display:inline-flex;align-items:center;gap:10px;color:#fefaf6;text-decoration:none}.brand-page img{width:58px;height:34px;object-fit:contain}.brand-page b{font-size:18px;letter-spacing:-.03em}.brand-page span{color:#b8bab8;font-weight:400}h1{margin:8px 0 10px;font-size:42px;line-height:.96;letter-spacing:-.03em}p{color:#b8bab8;line-height:1.55}.eyebrow{margin:0;color:#b8a8d8;font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}.box{margin-top:24px;padding:16px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:#181a18}a{color:#b8a8d8}
  </style>
</head>
<body>
  <main>
    <a class="brand-page" href="/"><img src="/logo.png" alt=""><b>html<span>share</span></b></a>
    <p class="eyebrow">htmlshare · abuse notice</p>
    <h1>` + htmlEscape(status) + `</h1>
    <p>We have received the abuse notice for <strong>` + htmlEscape(publication.Title) + `</strong>.</p>
    <div class="box">
      <p><strong>Severity:</strong> ` + htmlEscape(decision.Severity) + `</p>
      <p><strong>Decision:</strong> ` + htmlEscape(decision.Summary) + `</p>
      <p><strong>ID:</strong> ` + htmlEscape(abuse.ID) + `</p>
    </div>
    <p><a href="/">Back to htmlshare</a></p>
  </main>
</body>
</html>`
}

func injectCommentWidget(raw []byte, slug string) []byte {
	slugJSON, _ := json.Marshal(slug)
	widget := `<div id="htmlshare-tools-host"></div>
<script>
(function(){
var slug=` + string(slugJSON) + `;
var host=document.getElementById("htmlshare-tools-host");
if(!host || host.shadowRoot){return;}
var root=host.attachShadow({mode:"open"});
root.innerHTML='<style>' +
' :host{all:initial;position:fixed;right:16px;bottom:16px;z-index:2147483647;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#fefaf6}' +
'*,*:before,*:after{box-sizing:border-box}' +
'.launcher{width:50px;height:50px;display:grid;place-items:center;border:1px solid rgba(255,255,255,.18);border-radius:999px;background:#242624;color:#fefaf6;box-shadow:0 14px 44px rgba(0,0,0,.28);cursor:pointer}' +
'.launcher img{width:30px;height:18px;object-fit:contain}' +
'.panel{width:min(320px,calc(100vw - 32px));max-height:min(360px,calc(100vh - 86px));display:none;flex-direction:column;gap:10px;margin-bottom:10px;padding:14px;border:1px solid rgba(255,255,255,.14);border-radius:14px;background:#242624;box-shadow:0 18px 60px rgba(0,0,0,.26)}' +
'.panel.open{display:flex}' +
'.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px}' +
'.brand{display:inline-flex;align-items:center;gap:9px;color:#fefaf6}' +
'.brand-mark{width:46px;height:26px;flex:0 0 auto;object-fit:contain}' +
'.brand-name{display:inline-flex;align-items:baseline;font:800 18px/1 inherit;letter-spacing:-.03em}' +
'.brand-share{color:#b8bab8;font-weight:400}' +
'.icon{width:15px;height:15px;flex:0 0 auto}' +
'button{font:700 13px/1 inherit;border:0;cursor:pointer}' +
'.action,.primary{display:inline-flex;align-items:center;justify-content:center;gap:8px}' +
'.close{width:28px;height:28px;border:1px solid rgba(255,255,255,.14);border-radius:999px;background:transparent;color:#fefaf6}' +
'.actions{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}' +
'.action{min-height:32px;border:1px solid rgba(255,255,255,.18);border-radius:999px;background:transparent;color:#fefaf6;padding:0 8px;font-size:12px}' +
'.action.wide{grid-column:1/-1}' +
'.status{min-height:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#b8bab8;font:500 11px/1.35 ui-sans-serif,system-ui,sans-serif}' +
'.primary{width:100%;min-height:42px;border-radius:999px;background:#fefaf6;color:#242624;padding:0 14px;box-shadow:0 10px 28px rgba(254,250,246,.16)}' +
'@media (max-width:480px){:host{right:10px;bottom:10px}.panel{width:calc(100vw - 20px);padding:12px}}' +
'</style>' +
'<aside class="panel" aria-label="Htmlshare tools">' +
'<div class="top"><div class="brand"><img class="brand-mark" src="/logo.png" alt="" /><span class="brand-name"><span>html</span><span class="brand-share">share</span></span></div><button class="close" id="hs-close" type="button" aria-label="Close">×</button></div>' +
'<button class="primary" id="hs-publish" type="button"><svg class="icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 16V4m0 0 4 4m-4-4-4 4M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Share your file</span></button>' +
'<div class="actions"><button class="action" id="hs-download" type="button"><svg class="icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4v12m0 0 4-4m-4 4-4-4M5 20h14" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Download</span></button><button class="action" id="hs-terms" type="button"><svg class="icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3h7l4 4v14H7zM14 3v5h4M10 12h5m-5 4h5" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Terms</span></button><button class="action" id="hs-read-later" type="button"><svg class="icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 4h12v17l-6-4-6 4z" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Read later</span></button><button class="action" id="hs-abuse-submit" type="button"><svg class="icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 3 20h18L12 3Zm0 6v5m0 3h.01" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Abuse</span></button></div>' +
'<div class="status" id="hs-status"></div>' +
'</aside>' +
'<button class="launcher" id="hs-launcher" type="button" aria-label="Open htmlshare tools"><img src="/logo-white.png" alt="" /></button>';
var panel=root.querySelector(".panel");
root.getElementById("hs-launcher").onclick=function(){panel.classList.toggle("open");};
root.getElementById("hs-close").onclick=function(){panel.classList.remove("open");};
root.getElementById("hs-terms").onclick=function(){window.open("/terms","_blank","noopener");};
root.getElementById("hs-download").onclick=function(){window.location.href="/f/"+encodeURIComponent(slug)+"/?download=1";};
root.getElementById("hs-publish").onclick=function(){window.location.href="/";};
root.getElementById("hs-read-later").onclick=async function(){
  var status=root.getElementById("hs-status");
  status.textContent="Saving...";
  try{
    var res=await fetch("/api/bookmarks",{method:"POST",headers:{"content-type":"application/json"},credentials:"same-origin",body:JSON.stringify({slug:slug,kind:"read_later"})});
    if(res.status===401||res.status===403){status.textContent="Sign in or use signed access first.";return;}
    if(!res.ok){status.textContent="Could not save.";return;}
    status.textContent="Saved for later.";
  }catch(e){status.textContent="Could not save.";}
};
root.getElementById("hs-abuse-submit").onclick=async function(){
  window.location.href="/abuse?slug="+encodeURIComponent(slug);
};
})();
</script>`
	text := string(raw)
	if strings.Contains(strings.ToLower(text), "</body>") {
		idx := strings.LastIndex(strings.ToLower(text), "</body>")
		return []byte(text[:idx] + widget + text[idx:])
	}
	return append(raw, []byte(widget)...)
}
