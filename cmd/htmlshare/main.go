package main

import (
	"log"
	"net/http"
	"os"

	"htmlshare/internal/htmlshare"
)

func main() {
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
			From:     env("EMAIL_FROM", "htmlshare@example.com"),
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

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
