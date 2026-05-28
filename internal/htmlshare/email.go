package htmlshare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Mailer struct {
	DataDir  string
	APIKey   string
	From     string
	SMTPAddr string
	Brevo    BrevoConfig
	Mailgun  MailgunConfig
}

type BrevoConfig struct {
	APIKey string
	Email  string
	Name   string
}

type MailgunConfig struct {
	APIKey string
	Domain string
	From   string
}

func (m Mailer) Send(to, subject, text, html string) error {
	if m.SMTPAddr != "" {
		return m.sendSMTP(to, subject, text, html)
	}
	if m.Brevo.APIKey != "" && m.Brevo.Email != "" {
		return m.sendBrevo(to, subject, text, html)
	}
	if m.Mailgun.APIKey != "" && m.Mailgun.Domain != "" {
		return m.sendMailgun(to, subject, text, html)
	}
	if m.APIKey == "" {
		return m.writeOutbox(to, subject, text, html)
	}
	body, _ := json.Marshal(map[string]any{
		"from":    m.From,
		"to":      []string{to},
		"subject": subject,
		"text":    text,
		"html":    html,
	})
	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+m.APIKey)
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend returned %s", resp.Status)
	}
	return nil
}

func (m Mailer) sendBrevo(to, subject, text, html string) error {
	name := m.Brevo.Name
	if name == "" {
		name = "htmlshare"
	}
	body, _ := json.Marshal(map[string]any{
		"sender": map[string]string{
			"name":  name,
			"email": m.Brevo.Email,
		},
		"to": []map[string]string{
			{"email": to},
		},
		"subject":     subject,
		"textContent": text,
		"htmlContent": html,
	})
	req, err := http.NewRequest(http.MethodPost, "https://api.brevo.com/v3/smtp/email", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("api-key", m.Brevo.APIKey)
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("brevo returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (m Mailer) sendMailgun(to, subject, text, html string) error {
	from := m.Mailgun.From
	if from == "" {
		from = m.From
	}
	if from == "" {
		from = "htmlshare@" + m.Mailgun.Domain
	}
	form := url.Values{}
	form.Set("from", from)
	form.Set("to", to)
	form.Set("subject", subject)
	form.Set("text", text)
	form.Set("html", html)
	endpoint := "https://api.mailgun.net/v3/" + m.Mailgun.Domain + "/messages"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth("api", m.Mailgun.APIKey)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("mailgun returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (m Mailer) sendSMTP(to, subject, text, html string) error {
	from := m.From
	if from == "" {
		from = "htmlshare@example.com"
	}
	envelopeFrom := from
	if parsed, err := mail.ParseAddress(from); err == nil {
		envelopeFrom = parsed.Address
	}
	message := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: text/html; charset="utf-8"`,
		"",
		html,
		"",
		"<!-- text fallback: " + text + " -->",
	}, "\r\n")
	return smtp.SendMail(m.SMTPAddr, nil, envelopeFrom, []string{to}, []byte(message))
}

func (m Mailer) writeOutbox(to, subject, text, html string) error {
	path := filepath.Join(m.DataDir, "outbox.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	entry, _ := json.Marshal(map[string]string{
		"to": to, "subject": subject, "text": text, "html": html, "created_at": time.Now().Format(time.RFC3339),
	})
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(entry, '\n'))
	return err
}
