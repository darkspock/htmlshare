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
	"path/filepath"
	"regexp"
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

func TestRegisteredSignedPublishCreatesInvitationAndRequiresProof(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	confirmed := now
	owner := User{ID: "usr_owner", Email: "owner@example.com", Provider: "magic", EmailConfirmedAt: &confirmed, CreatedAt: now}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, owner)
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
	apiKey, _, err := server.createAPIKey(owner.ID, "test key", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	publishResp := postJSON(t, ts.URL+"/api/publish", apiKey, map[string]any{
		"title":      "Signed Publish",
		"visibility": "signed",
		"share": map[string]any{
			"emails": []string{"reader@example.com"},
		},
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>Signed Publish</h1></body></html>",
		},
	})
	if publishResp.StatusCode != http.StatusCreated {
		t.Fatalf("publish status = %d", publishResp.StatusCode)
	}
	var body map[string]any
	decode(t, publishResp, &body)
	if body["share_count"].(float64) != 1 {
		t.Fatalf("share_count = %v, want 1", body["share_count"])
	}
	var publication Publication
	_ = store.ReadDB(func(db DB) error {
		if len(db.SignedTokens) != 1 {
			t.Fatalf("signed tokens = %d, want 1", len(db.SignedTokens))
		}
		if len(db.SignedProofs) != 0 {
			t.Fatalf("signed proofs = %d, want 0", len(db.SignedProofs))
		}
		publication = db.Publications[0]
		return nil
	})

	readerConfirmed := now
	readerSession := Session{ID: "ses_reader", UserID: "usr_reader", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, User{ID: "usr_reader", Email: "reader@example.com", Provider: "magic", EmailConfirmedAt: &readerConfirmed, CreatedAt: now})
		db.Sessions = append(db.Sessions, readerSession)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	client.Jar.SetCookies(mustURL(t, ts.URL), []*http.Cookie{SessionCookie(readerSession.ID, server.SessionSecret)})
	readResp, err := client.Get(ts.URL + "/f/" + publication.Slug + "/")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(readResp.Body)
	_ = readResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if readResp.StatusCode != http.StatusForbidden {
		t.Fatalf("read before proof status = %d, want %d", readResp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(raw), "Signed access required") || !strings.Contains(string(raw), "Send signed-access link") {
		t.Fatalf("signed gate body = %q", string(raw))
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

func TestFastPublishCanRestrictToEmailRecipients(t *testing.T) {
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

	publishResp := postJSON(t, ts.URL+"/api/v1/publish", "", map[string]any{
		"mode":        "fast",
		"agent_id":    "fast-recipient-session",
		"agent_name":  "codex",
		"title":       "Recipient-only fast file",
		"visibility":  "recipients",
		"ttl_seconds": 3600,
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>Recipient-only fast file</h1><p>Visible only by reader@example.com.</p></body></html>",
		},
		"share": map[string]any{
			"emails":  []string{"reader@example.com"},
			"message": "Please review this file.",
		},
	})
	if publishResp.StatusCode != http.StatusCreated {
		t.Fatalf("fast recipient publish status = %d", publishResp.StatusCode)
	}
	var body map[string]any
	decode(t, publishResp, &body)
	if body["visibility"] != "recipients" {
		t.Fatalf("visibility = %v, want recipients", body["visibility"])
	}
	publicURL := body["url"].(string)
	if body["share_count"] != float64(1) {
		t.Fatalf("share_count = %v, want 1", body["share_count"])
	}

	anonymousResp, err := http.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(anonymousResp.Body)
	_ = anonymousResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if anonymousResp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous status = %d, want %d", anonymousResp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(raw), "Access required") || !strings.Contains(string(raw), "Send access link") {
		t.Fatalf("anonymous gate body = %q", string(raw))
	}

	requestResp, err := http.PostForm(publicURL, url.Values{"email": []string{"reader@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = io.ReadAll(requestResp.Body)
	_ = requestResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if requestResp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "access email is on the way") {
		t.Fatalf("request access status/body = %d %q", requestResp.StatusCode, string(raw))
	}

	magicURL := latestOutboxLink(t, store)
	magicGetResp, err := http.Get(magicURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = io.ReadAll(magicGetResp.Body)
	_ = magicGetResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if magicGetResp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "Open file") {
		t.Fatalf("magic GET status/body = %d %q", magicGetResp.StatusCode, string(raw))
	}

	anonymousAgainResp, err := http.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = anonymousAgainResp.Body.Close()
	if anonymousAgainResp.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous after GET status = %d, want %d", anonymousAgainResp.StatusCode, http.StatusForbidden)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	openResp, err := client.Post(magicURL, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = io.ReadAll(openResp.Body)
	_ = openResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if openResp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "Recipient-only fast file") {
		t.Fatalf("magic POST final status/body = %d %q", openResp.StatusCode, string(raw))
	}
	if strings.Contains(strings.ToLower(string(raw)), "reader@example.com") {
		t.Fatalf("magic POST leaked recipient email in body: %q", string(raw))
	}

	viewResp, err := client.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = io.ReadAll(viewResp.Body)
	_ = viewResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if viewResp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "Recipient-only fast file") {
		t.Fatalf("recipient view status/body = %d %q", viewResp.StatusCode, string(raw))
	}
	if strings.Contains(strings.ToLower(string(raw)), "reader@example.com") {
		t.Fatalf("recipient view leaked recipient email in body: %q", string(raw))
	}
}

func TestRestrictedAccessNoticeHTMLIsNeutralized(t *testing.T) {
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

	publishResp := postJSON(t, ts.URL+"/api/v1/publish", "", map[string]any{
		"mode":        "fast",
		"agent_id":    "access-notice-redaction-session",
		"agent_name":  "codex",
		"title":       "Access notice check",
		"visibility":  "recipients",
		"ttl_seconds": 3600,
		"files": map[string]string{
			"index.html": "<!doctype html><html><body><h1>HTML restringido</h1><p>Esta pagina de prueba esta configurada para ser visible solo por reader@example.com.</p><p>El acceso requiere confirmar el email mediante el enlace magico enviado por htmlshare.</p></body></html>",
		},
		"share": map[string]any{
			"emails": []string{"reader@example.com"},
		},
	})
	if publishResp.StatusCode != http.StatusCreated {
		t.Fatalf("fast recipient publish status = %d", publishResp.StatusCode)
	}
	var body map[string]any
	decode(t, publishResp, &body)
	publicURL := body["url"].(string)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	magicURL := latestOutboxLink(t, store)
	openResp, err := client.Post(magicURL, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, openResp.Body)
	_ = openResp.Body.Close()

	viewResp, err := client.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(viewResp.Body)
	_ = viewResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	page := strings.ToLower(string(raw))
	if viewResp.StatusCode != http.StatusOK || !strings.Contains(page, "access controlled file") {
		t.Fatalf("recipient view status/body = %d %q", viewResp.StatusCode, string(raw))
	}
	for _, forbidden := range []string{"reader@example.com", "html restringido", "visible solo", "enlace magico"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("recipient view leaked access notice %q in body: %q", forbidden, string(raw))
		}
	}
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
	publication := Publication{ID: "pub_signed", OwnerID: owner.ID, Title: "Signed Publication", Slug: "signed-publication", Visibility: "signed", RequireRegistration: true, Files: []string{"index.html"}, CreatedAt: now}
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
	_ = store.ReadDB(func(db DB) error {
		if len(db.Shares) != 1 {
			t.Fatalf("shares after signed send = %d, want 1", len(db.Shares))
		}
		if db.Shares[0].Email != "reader@example.com" {
			t.Fatalf("share email = %q, want reader@example.com", db.Shares[0].Email)
		}
		return nil
	})

	readerJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	readerClient := &http.Client{
		Jar: readerJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
	_ = store.ReadDB(func(db DB) error {
		if len(db.SignedProofs) != 0 {
			t.Fatalf("signed proofs after open = %d, want 0", len(db.SignedProofs))
		}
		if len(db.SignedTokens) != 1 || !db.SignedTokens[0].UsedAt.IsZero() {
			t.Fatalf("signed token should not be consumed by opening the link")
		}
		return nil
	})

	readerConfirmed := time.Now()
	reader := User{ID: "usr_reader", Email: "reader@example.com", Provider: "magic", EmailConfirmedAt: &readerConfirmed, CreatedAt: time.Now()}
	readerSession := Session{ID: "ses_reader", UserID: reader.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, reader)
		db.Sessions = append(db.Sessions, readerSession)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	readerClient.Jar.SetCookies(mustURL(t, ts.URL), []*http.Cookie{SessionCookie(readerSession.ID, server.SessionSecret)})
	unsignedReadResp, err := readerClient.Get(ts.URL + "/f/" + publication.Slug + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = unsignedReadResp.Body.Close()
	if unsignedReadResp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned signed-access read status = %d, want %d", unsignedReadResp.StatusCode, http.StatusForbidden)
	}

	sendCodeResp, err := readerClient.PostForm(signedURL, url.Values{"action": []string{"send_code"}})
	if err != nil {
		t.Fatal(err)
	}
	if sendCodeResp.StatusCode != http.StatusOK {
		t.Fatalf("send code status = %d", sendCodeResp.StatusCode)
	}
	_ = sendCodeResp.Body.Close()
	outbox, err := os.ReadFile(filepath.Join(store.DataDir(), "outbox.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(outbox)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("empty outbox")
	}
	var outboxEntry map[string]string
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &outboxEntry); err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`[0-9]{6}`).FindString(outboxEntry["text"])
	if code == "" {
		t.Fatal("signature code not found in outbox")
	}

	verifyResp, err := readerClient.PostForm(signedURL, url.Values{"action": []string{"verify"}, "code": []string{code}})
	if err != nil {
		t.Fatal(err)
	}
	_ = verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusFound {
		t.Fatalf("verify status = %d", verifyResp.StatusCode)
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
		if len(db.Shares) != 1 {
			t.Fatalf("shares after signed open = %d, want 1", len(db.Shares))
		}
		if len(db.Comments) != 0 {
			t.Fatalf("comments = %d, want 0", len(db.Comments))
		}
		return nil
	})
}

func TestSharingSignedPublicationCreatesSignedInvitation(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	confirmed := now
	owner := User{ID: "usr_owner", Email: "owner@example.com", Provider: "magic", EmailConfirmedAt: &confirmed, CreatedAt: now}
	publication := Publication{ID: "pub_signed_share", OwnerID: owner.ID, Title: "Signed Share", Slug: "signed-share", Visibility: "signed", RequireRegistration: true, Files: []string{"index.html"}, CreatedAt: now}
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

	resp := postJSONWithClient(t, ownerClient, ts.URL+"/api/share", "", map[string]any{
		"id":      publication.ID,
		"emails":  []string{"reader@example.com"},
		"message": "Please review and sign.",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("share status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	_ = store.ReadDB(func(db DB) error {
		if len(db.Shares) != 1 {
			t.Fatalf("shares = %d, want 1", len(db.Shares))
		}
		if len(db.SignedTokens) != 1 {
			t.Fatalf("signed tokens = %d, want 1", len(db.SignedTokens))
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

func TestSessionLogoutExpiresCookieAndSession(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	confirmed := now
	user := User{ID: "usr_logout", Email: "logout@example.com", Provider: "magic", EmailConfirmedAt: &confirmed, CreatedAt: now}
	session := Session{ID: "ses_logout", UserID: user.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := store.WithDB(func(db *DB) error {
		db.Users = append(db.Users, user)
		db.Sessions = append(db.Sessions, session)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: store, AppURL: "http://example.test", SessionSecret: "test-secret"}
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()
	server.AppURL = ts.URL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	client.Jar.SetCookies(mustURL(t, ts.URL), []*http.Cookie{SessionCookie(session.ID, server.SessionSecret)})

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}

	sessionResp, err := client.Get(ts.URL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	decode(t, sessionResp, &body)
	if body["user"] != nil {
		t.Fatalf("session user after logout = %v, want nil", body["user"])
	}
	_ = store.ReadDB(func(db DB) error {
		if !db.Sessions[0].ExpiresAt.Before(time.Now()) {
			t.Fatalf("stored session was not expired")
		}
		return nil
	})
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
