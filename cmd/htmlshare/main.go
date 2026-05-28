package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"htmlshare/internal/htmlshare"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	if os.Getenv("SENTRY_DSN") != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              os.Getenv("SENTRY_DSN"),
			Environment:      env("SENTRY_ENVIRONMENT", "production"),
			Release:          os.Getenv("SENTRY_RELEASE"),
			SendDefaultPII:   false,
			AttachStacktrace: true,
			TracesSampleRate: 0,
			BeforeSend:       scrubSentryEvent,
		}); err != nil {
			log.Printf("sentry init failed: %v", err)
		}
		defer sentry.Flush(2 * time.Second)
	}

	port := env("PORT", "4545")
	appURL := env("APP_URL", "http://localhost:"+port)
	dataDir := env("DATA_DIR", "data")
	store, err := htmlshare.NewStore(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	server := &htmlshare.Server{
		Store:          store,
		AppURL:         appURL,
		AbuseAnalyzer:  htmlshare.NewAbuseAnalyzerFromEnv(),
		SessionSecret:  env("SESSION_SECRET", "dev-session-secret"),
		GoogleClient:   os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleSecret:   os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirect: os.Getenv("GOOGLE_REDIRECT_URL"),
		Mailer: htmlshare.Mailer{
			DataDir:  dataDir,
			APIKey:   os.Getenv("RESEND_API_KEY"),
			From:     env("EMAIL_FROM", "htmlshare <noreply@metricauno.com>"),
			SMTPAddr: os.Getenv("SMTP_ADDR"),
			Brevo: htmlshare.BrevoConfig{
				APIKey: os.Getenv("BREVO_API_KEY"),
				Email:  os.Getenv("BREVO_SENDER_EMAIL"),
				Name:   os.Getenv("BREVO_SENDER_NAME"),
			},
			Mailgun: htmlshare.MailgunConfig{
				APIKey: os.Getenv("MAILGUN_API_KEY"),
				Domain: os.Getenv("MAILGUN_DOMAIN"),
				From:   os.Getenv("MAILGUN_FROM_EMAIL"),
			},
		},
	}
	log.Printf("htmlshare listening on %s", appURL)
	handler := server.Routes()
	if os.Getenv("SENTRY_DSN") != "" {
		handler = sentryhttp.New(sentryhttp.Options{Repanic: true}).Handle(handler)
	}
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func scrubSentryEvent(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if event.Request != nil {
		event.Request.QueryString = ""
		event.Request.Cookies = ""
		for _, header := range []string{"Authorization", "Cookie", "Set-Cookie", "X-Api-Key"} {
			delete(event.Request.Headers, header)
		}
	}
	return event
}

func healthcheck() {
	port := env("PORT", "4545")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Fatalf("healthcheck failed: %s", resp.Status)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
