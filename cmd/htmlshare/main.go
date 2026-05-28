package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"htmlshare/internal/htmlshare"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
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
	log.Fatal(http.ListenAndServe(":"+port, server.Routes()))
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
