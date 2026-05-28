package htmlshare

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAutomationSignupKeyAndPublishFlow(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Store:         store,
		AppURL:        "http://example.test",
		SessionSecret: "test-secret",
		Mailer:        Mailer{DataDir: store.DataDir(), From: "test@example.com"},
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	signup := postJSON(t, ts.URL+"/api/ai/signup", "", map[string]string{
		"email": "owner@example.com",
		"name":  "Owner",
		"agent": "codex",
	})
	if signup.StatusCode != http.StatusCreated {
		t.Fatalf("signup status = %d", signup.StatusCode)
	}
	var signupBody map[string]any
	decode(t, signup, &signupBody)
	signupAPIKey, _ := signupBody["api_key"].(string)
	if !strings.HasPrefix(signupAPIKey, "hsk_") {
		t.Fatalf("unexpected signup api key %q", signupAPIKey)
	}
	magicURL := latestOutboxLink(t, store)
	assertUserConfirmed(t, store, "owner@example.com", false)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	magicResp, err := client.Get(magicURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = magicResp.Body.Close()
	if magicResp.StatusCode != http.StatusOK {
		t.Fatalf("confirm page status = %d", magicResp.StatusCode)
	}
	assertUserConfirmed(t, store, "owner@example.com", false)

	confirmResp, err := client.Post(magicURL, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = confirmResp.Body.Close()
	assertUserConfirmed(t, store, "owner@example.com", true)

	keyResp := postJSONWithClient(t, client, ts.URL+"/api/api-keys", "", map[string]string{"name": "test key"})
	if keyResp.StatusCode != http.StatusCreated {
		t.Fatalf("api key status = %d", keyResp.StatusCode)
	}
	var keyBody map[string]string
	decode(t, keyResp, &keyBody)
	apiKey := keyBody["api_key"]
	if !strings.HasPrefix(apiKey, "hsk_") {
		t.Fatalf("unexpected api key %q", apiKey)
	}

	publish := map[string]any{
		"title":      "Automation Publication",
		"visibility": "private",
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>Automation Publication</h1></body></html>",
			"style.css":  "body{font-family:serif}",
		},
	}
	publicationResp := postJSON(t, ts.URL+"/api/publish", apiKey, publish)
	if publicationResp.StatusCode != http.StatusCreated {
		t.Fatalf("publication status = %d", publicationResp.StatusCode)
	}
	var publicationBody map[string]any
	decode(t, publicationResp, &publicationBody)
	if publicationBody["url"] == "" {
		t.Fatal("missing publication url")
	}
	publicationURL, _ := publicationBody["url"].(string)
	viewReq, err := http.NewRequest(http.MethodGet, publicationURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	viewReq.Header.Set("x-forwarded-for", "203.0.113.10")
	viewReq.Header.Set("user-agent", "htmlshare-test")
	viewResp, err := client.Do(viewReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = viewResp.Body.Close()
	if viewResp.StatusCode != http.StatusOK {
		t.Fatalf("view status = %d", viewResp.StatusCode)
	}

	statsResp := postJSONWithClient(t, client, ts.URL+"/api/library/"+publicationBody["id"].(string)+"/stats", "", nil)
	_ = statsResp.Body.Close()
	if statsResp.StatusCode != http.StatusNotFound {
		t.Fatalf("stats POST should not be allowed, got %d", statsResp.StatusCode)
	}
	statsReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/library/"+publicationBody["id"].(string)+"/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	statsResp, err = client.Do(statsReq)
	if err != nil {
		t.Fatal(err)
	}
	var stats map[string]any
	decode(t, statsResp, &stats)
	if stats["visits"].(float64) != 1 {
		t.Fatalf("visits = %v, want 1", stats["visits"])
	}
}

func TestFastPublishDoesNotRequireEmailOrAPIKey(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Store:         store,
		AppURL:        "http://example.test",
		SessionSecret: "test-secret",
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	publishResp := postJSON(t, ts.URL+"/api/publish", "", map[string]any{
		"mode":        "fast",
		"agent_id":    "codex-session-12345",
		"agent_name":  "codex",
		"title":       "Fast AI file",
		"ttl_seconds": 3600,
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>Fast AI file</h1></body></html>",
			"style.css":  "body{font-family:system-ui}",
		},
	})
	if publishResp.StatusCode != http.StatusCreated {
		t.Fatalf("fast publish status = %d", publishResp.StatusCode)
	}
	var body map[string]any
	decode(t, publishResp, &body)
	if body["mode"] != "fast" {
		t.Fatalf("mode = %v, want fast", body["mode"])
	}
	url, _ := body["url"].(string)
	if url == "" {
		t.Fatal("missing fast publication url")
	}
	viewResp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(viewResp.Body)
	_ = viewResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if viewResp.StatusCode != http.StatusOK {
		t.Fatalf("view status = %d", viewResp.StatusCode)
	}
	if !strings.Contains(string(raw), "Fast AI file") {
		t.Fatalf("unexpected body %q", string(raw))
	}
	_ = store.ReadDB(func(db DB) error {
		if len(db.Agents) != 1 {
			t.Fatalf("agents = %d, want 1", len(db.Agents))
		}
		if len(db.Publications) != 1 || db.Publications[0].OwnerID != "" || db.Publications[0].Mode != "fast" {
			t.Fatalf("unexpected publication: %+v", db.Publications)
		}
		return nil
	})
}

func TestAPIV1PublishAlias(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store, AppURL: "http://example.test", SessionSecret: "test-secret"}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	resp := postJSON(t, ts.URL+"/api/v1/publish", "", map[string]any{
		"mode":        "fast",
		"agent_id":    "codex-v1-alias-check",
		"title":       "API v1 Alias",
		"ttl_seconds": 3600,
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>API v1 Alias</h1></body></html>",
		},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("v1 publish status = %d", resp.StatusCode)
	}
	var body map[string]any
	decode(t, resp, &body)
	if body["mode"] != "fast" {
		t.Fatalf("mode = %v, want fast", body["mode"])
	}
}

func TestExpiredAutomaticRegistrationDeletesOwnedContent(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store, AppURL: "http://example.test", SessionSecret: "test-secret"}
	expiredAt := time.Now().Add(-time.Hour)
	user := User{
		ID:                   "usr_expired",
		Email:                "expired@example.com",
		Provider:             "magic",
		AutoProvisioned:      true,
		ConfirmationDeadline: expiredAt,
		CreatedAt:            expiredAt.Add(-24 * time.Hour),
	}
	publication := Publication{ID: "pub_expired", OwnerID: user.ID, Title: "Expired", Slug: "expired", Visibility: "private", Files: []string{"index.html"}, CreatedAt: expiredAt}
	if _, err := store.WritePublicationFile(publication.ID, "index.html", []byte("<h1>expired</h1>")); err != nil {
		t.Fatal(err)
	}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, user)
		db.Publications = append(db.Publications, publication)
		db.APIKeys = append(db.APIKeys, APIKey{ID: "key_expired", UserID: user.ID})
		db.Sessions = append(db.Sessions, Session{ID: "ses_expired", UserID: user.ID})
		db.MagicLinks = append(db.MagicLinks, MagicLink{ID: "ml_expired", UserID: user.ID, PublicationID: publication.ID})
		db.Shares = append(db.Shares, Share{ID: "shr_expired", PublicationID: publication.ID, UserID: user.ID})
		db.AccessLogs = append(db.AccessLogs, AccessLog{ID: "acl_expired", PublicationID: publication.ID, UserID: user.ID})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := server.cleanupExpiredAutomaticRegistrations(time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(store.PublicationDir(publication.ID)); !os.IsNotExist(err) {
		t.Fatalf("expected publication dir to be deleted, got err=%v", err)
	}
	_ = store.ReadDB(func(db DB) error {
		if len(db.Users) != 0 || len(db.Publications) != 0 || len(db.APIKeys) != 0 || len(db.Sessions) != 0 || len(db.MagicLinks) != 0 || len(db.Shares) != 0 || len(db.AccessLogs) != 0 {
			t.Fatalf("expected expired records to be removed: %+v", db)
		}
		return nil
	})
}

func TestAbuseReportBlocksPublicationAndBansCriticalOwner(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	confirmed := now
	owner := User{ID: "usr_owner", Email: "owner@example.com", Provider: "magic", EmailConfirmedAt: &confirmed, CreatedAt: now}
	publication := Publication{ID: "pub_bad", OwnerID: owner.ID, CreatedIP: "198.51.100.44", Title: "Bad Publication", Slug: "bad-publication", Visibility: "public", Files: []string{"index.html"}, CreatedAt: now}
	if _, err := store.WritePublicationFile(publication.ID, "index.html", []byte("<h1>bad</h1>")); err != nil {
		t.Fatal(err)
	}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, owner)
		db.Publications = append(db.Publications, publication)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Store:         store,
		AppURL:        "http://example.test",
		SessionSecret: "test-secret",
		AbuseAnalyzer: HybridAbuseAnalyzer{},
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	abuseResp := postJSON(t, ts.URL+"/api/abuse-reports", "", map[string]string{
		"slug":           publication.Slug,
		"reporter_email": "reader@example.com",
		"reason":         "phishing",
		"details":        "This page is asking for credentials and passwords.",
	})
	if abuseResp.StatusCode != http.StatusCreated {
		t.Fatalf("abuse status = %d", abuseResp.StatusCode)
	}
	_ = abuseResp.Body.Close()

	viewResp, err := http.Get(ts.URL + "/f/" + publication.Slug + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = viewResp.Body.Close()
	if viewResp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("blocked publication status = %d", viewResp.StatusCode)
	}

	signupResp := postJSONWithIP(t, ts.URL+"/api/ai/signup", "198.51.100.44", map[string]string{
		"email": "owner@example.com",
		"agent": "codex",
	})
	_ = signupResp.Body.Close()
	if signupResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("banned signup status = %d", signupResp.StatusCode)
	}

	_ = store.ReadDB(func(db DB) error {
		if len(db.AbuseReports) != 1 {
			t.Fatalf("abuse reports = %d, want 1", len(db.AbuseReports))
		}
		if len(db.Strikes) != 1 {
			t.Fatalf("strikes = %d, want 1", len(db.Strikes))
		}
		if len(db.Bans) != 2 {
			t.Fatalf("bans = %d, want 2", len(db.Bans))
		}
		if db.Bans[0].ExpiresAt.Sub(db.Bans[0].CreatedAt) != 48*time.Hour {
			t.Fatalf("ban duration = %s", db.Bans[0].ExpiresAt.Sub(db.Bans[0].CreatedAt))
		}
		return nil
	})
}

func TestSignedAccessRecordsProofWhileCommentsAreDisabled(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	confirmed := now
	owner := User{ID: "usr_owner", Email: "owner@example.com", Provider: "magic", EmailConfirmedAt: &confirmed, CreatedAt: now}
	publication := Publication{ID: "pub_signed", OwnerID: owner.ID, Title: "Signed Publication", Slug: "signed-publication", Visibility: "recipients", RequireRegistration: true, Files: []string{"index.html"}, CreatedAt: now}
	if _, err := store.WritePublicationFile(publication.ID, "index.html", []byte("<!doctype html><html><body><h1>Signed Publication</h1><p>Legal paragraph</p></body></html>")); err != nil {
		t.Fatal(err)
	}
	ownerSession := Session{ID: "ses_owner", UserID: owner.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, owner)
		db.Publications = append(db.Publications, publication)
		db.Sessions = append(db.Sessions, ownerSession)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Store:         store,
		AppURL:        "http://example.test",
		SessionSecret: "test-secret",
		Mailer:        Mailer{DataDir: store.DataDir(), From: "test@example.com"},
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	ownerJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	ownerClient := &http.Client{Jar: ownerJar}
	ownerClient.Jar.SetCookies(mustURL(t, ts.URL), []*http.Cookie{SessionCookie(ownerSession.ID, server.SessionSecret)})

	signedResp := postJSONWithClient(t, ownerClient, ts.URL+"/api/library/"+publication.ID+"/signed-access", "", map[string]string{
		"email":   "reader@example.com",
		"message": "Please sign access.",
	})
	if signedResp.StatusCode != http.StatusCreated {
		t.Fatalf("signed access status = %d", signedResp.StatusCode)
	}
	var signedBody map[string]string
	decode(t, signedResp, &signedBody)
	signedURL := signedBody["signed_url"]
	if signedURL == "" {
		t.Fatal("missing signed_url")
	}

	readerJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	readerClient := &http.Client{Jar: readerJar}
	signedOpenReq, err := http.NewRequest(http.MethodGet, signedURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedOpenReq.Header.Set("x-forwarded-for", "203.0.113.77")
	signedOpenReq.Header.Set("user-agent", "legal-reader")
	signedOpenResp, err := readerClient.Do(signedOpenReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = signedOpenResp.Body.Close()
	if signedOpenResp.StatusCode != http.StatusOK {
		t.Fatalf("signed open status = %d", signedOpenResp.StatusCode)
	}

	commentsResp, err := readerClient.Get(ts.URL + "/api/public-comments/" + publication.Slug)
	if err != nil {
		t.Fatal(err)
	}
	if commentsResp.StatusCode != http.StatusOK {
		t.Fatalf("comments list status = %d", commentsResp.StatusCode)
	}
	var commentsBody map[string][]Comment
	decode(t, commentsResp, &commentsBody)
	if len(commentsBody["comments"]) != 0 {
		t.Fatalf("comments = %d, want 0", len(commentsBody["comments"]))
	}

	generalResp := postJSONWithClient(t, readerClient, ts.URL+"/api/public-comments/"+publication.Slug, "", map[string]string{
		"body":  "General note",
		"scope": "general",
	})
	if generalResp.StatusCode != http.StatusGone {
		t.Fatalf("general comment status = %d", generalResp.StatusCode)
	}
	_ = generalResp.Body.Close()

	_ = store.ReadDB(func(db DB) error {
		if len(db.SignedProofs) != 1 {
			t.Fatalf("signed proofs = %d, want 1", len(db.SignedProofs))
		}
		if len(db.Comments) != 0 {
			t.Fatalf("comments = %d, want 0", len(db.Comments))
		}
		return nil
	})
}

func assertUserConfirmed(t *testing.T, store *Store, email string, want bool) {
	t.Helper()
	var got bool
	_ = store.ReadDB(func(db DB) error {
		for _, user := range db.Users {
			if user.Email == email {
				got = user.EmailConfirmed()
			}
		}
		return nil
	})
	if got != want {
		t.Fatalf("confirmed(%s) = %v, want %v", email, got, want)
	}
}

func TestCacheHeaders(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Store:         store,
		AppURL:        "http://example.test",
		SessionSecret: "test-secret",
		Mailer:        Mailer{DataDir: store.DataDir(), From: "test@example.com"},
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	apiResp, err := http.Get(ts.URL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	_ = apiResp.Body.Close()
	if got := apiResp.Header.Get("cache-control"); got != "no-store" {
		t.Fatalf("api cache-control = %q", got)
	}

	publishResp := postJSON(t, ts.URL+"/api/v1/publish", "", map[string]any{
		"mode":        "fast",
		"agent_id":    "cache-test-agent",
		"title":       "Cache test",
		"ttl_seconds": 3600,
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>Cache test</h1></body></html>",
		},
	})
	if publishResp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status = %d", publishResp.StatusCode)
	}
	var body map[string]any
	decode(t, publishResp, &body)
	publicURL := body["url"].(string)

	viewResp, err := http.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = viewResp.Body.Close()
	if got := viewResp.Header.Get("cache-control"); got != "private, no-cache, max-age=0, must-revalidate" {
		t.Fatalf("publication cache-control = %q", got)
	}
	etag := viewResp.Header.Get("etag")
	if etag == "" {
		t.Fatal("publication etag is empty")
	}

	req := mustRequest(t, http.MethodGet, publicURL, nil)
	req.Header.Set("if-none-match", etag)
	revalidateResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = revalidateResp.Body.Close()
	if revalidateResp.StatusCode != http.StatusNotModified {
		t.Fatalf("revalidate status = %d, want %d", revalidateResp.StatusCode, http.StatusNotModified)
	}
}

func latestOutboxLink(t *testing.T, store *Store) string {
	t.Helper()
	raw, err := os.ReadFile(store.DataDir() + "/outbox.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("empty outbox")
	}
	var entry map[string]string
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"text", "html"} {
		value := entry[field]
		start := strings.Index(value, "http")
		if start < 0 {
			continue
		}
		end := strings.IndexAny(value[start:], " \n\r\t\"<")
		if end < 0 {
			return value[start:]
		}
		return value[start : start+end]
	}
	t.Fatalf("no link in outbox entry: %+v", entry)
	return ""
}

func postJSON(t *testing.T, url, bearer string, body any) *http.Response {
	t.Helper()
	return postJSONWithClient(t, http.DefaultClient, url, bearer, body)
}

func postJSONWithClient(t *testing.T, client *http.Client, url, bearer string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	if bearer != "" {
		req.Header.Set("authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postJSONWithIP(t *testing.T, url, ip string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-forwarded-for", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func patchJSONWithClient(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustRequest(t *testing.T, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func decode(t *testing.T, resp *http.Response, target any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}
