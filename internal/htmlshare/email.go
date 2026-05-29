package htmlshare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
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

type TransactionalEmail struct {
	AppURL         string
	Title          string
	Preheader      string
	Intro          string
	Body           string
	ActionLabel    string
	ActionURL      string
	HighlightLabel string
	HighlightValue string
	Details        []string
	FooterContext  string
}

func RenderTransactionalEmail(email TransactionalEmail) (string, string) {
	appURL := strings.TrimRight(email.AppURL, "/")
	if appURL == "" {
		appURL = "https://share.metricauno.com"
	}
	title := strings.TrimSpace(email.Title)
	if title == "" {
		title = "htmlshare notification"
	}
	preheader := strings.TrimSpace(email.Preheader)
	if preheader == "" {
		preheader = title
	}
	context := strings.TrimSpace(email.FooterContext)
	if context == "" {
		context = "a requested htmlshare action"
	}
	var textParts []string
	textParts = append(textParts, title)
	if strings.TrimSpace(email.Intro) != "" {
		textParts = append(textParts, "\n"+strings.TrimSpace(email.Intro))
	}
	if strings.TrimSpace(email.Body) != "" {
		textParts = append(textParts, strings.TrimSpace(email.Body))
	}
	if strings.TrimSpace(email.HighlightValue) != "" {
		label := strings.TrimSpace(email.HighlightLabel)
		if label == "" {
			label = "Code"
		}
		textParts = append(textParts, label+": "+strings.TrimSpace(email.HighlightValue))
	}
	if strings.TrimSpace(email.ActionURL) != "" {
		label := strings.TrimSpace(email.ActionLabel)
		if label == "" {
			label = "Open htmlshare"
		}
		textParts = append(textParts, label+": "+strings.TrimSpace(email.ActionURL))
	}
	for _, detail := range email.Details {
		if strings.TrimSpace(detail) != "" {
			textParts = append(textParts, "- "+strings.TrimSpace(detail))
		}
	}
	textParts = append(textParts,
		"\nTransactional email for "+context+".",
		"htmlshare is operated by Metrica Uno.",
		"Legal: https://metrica.uno/privacy/ | https://metrica.uno/terms/ | https://metrica.uno/cookies/",
		"Report abuse: "+appURL+"/abuse",
	)
	text := strings.Join(textParts, "\n\n")

	intro := paragraph(email.Intro)
	body := paragraph(email.Body)
	highlight := ""
	if strings.TrimSpace(email.HighlightValue) != "" {
		label := strings.TrimSpace(email.HighlightLabel)
		if label == "" {
			label = "Code"
		}
		highlight = `<tr><td style="padding:0 32px 22px;"><div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#7a7c7a;font-weight:700;margin-bottom:8px;">` + htmlEscape(label) + `</div><div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:24px;letter-spacing:.06em;background:#f5f2ed;border:1px solid #e0ddd7;border-radius:10px;padding:18px 20px;color:#242624;">` + htmlEscape(email.HighlightValue) + `</div></td></tr>`
	}
	action := ""
	if strings.TrimSpace(email.ActionURL) != "" {
		label := strings.TrimSpace(email.ActionLabel)
		if label == "" {
			label = "Open htmlshare"
		}
		action = `<tr><td style="padding:2px 32px 30px;"><a href="` + htmlEscape(email.ActionURL) + `" style="display:inline-block;background:#242624;color:#fefaf6;text-decoration:none;border-radius:999px;padding:14px 22px;font-size:15px;font-weight:800;">` + htmlEscape(label) + `</a></td></tr>`
	}
	details := ""
	for _, detail := range email.Details {
		if strings.TrimSpace(detail) != "" {
			details += `<li style="margin:0 0 8px;color:#4d4f4d;">` + htmlEscape(detail) + `</li>`
		}
	}
	if details != "" {
		details = `<tr><td style="padding:0 32px 26px;"><ul style="margin:0;padding-left:20px;">` + details + `</ul></td></tr>`
	}
	html := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + htmlEscape(title) + `</title>
</head>
<body style="margin:0;padding:0;background:#f5f2ed;font-family:Manrope,Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#242624;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">` + htmlEscape(preheader) + `</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f2ed;padding:28px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;background:#ffffff;border:1px solid #e0ddd7;border-radius:18px;overflow:hidden;">
          <tr>
            <td style="padding:30px 32px 14px;">
              <a href="` + htmlEscape(appURL) + `" style="display:inline-flex;align-items:center;text-decoration:none;color:#242624;">
                <img src="` + htmlEscape(appURL) + `/logo.png" width="120" alt="htmlshare" style="display:block;width:120px;height:auto;border:0;">
              </a>
            </td>
          </tr>
          <tr><td style="padding:0 32px 10px;"><h1 style="margin:0;font-size:30px;line-height:1.08;letter-spacing:-.03em;color:#242624;">` + htmlEscape(title) + `</h1></td></tr>
          ` + intro + body + highlight + action + details + `
          <tr>
            <td style="padding:22px 32px 30px;background:#f8f6f2;border-top:1px solid #e8e4de;color:#7a7c7a;font-size:12px;line-height:1.55;">
              <p style="margin:0 0 10px;">Transactional email for ` + htmlEscape(context) + `. It was sent because someone requested this htmlshare action.</p>
              <p style="margin:0 0 10px;">htmlshare is operated by <a href="https://metricauno.com" style="color:#3f5f82;text-decoration:underline;">Metrica Uno</a>.</p>
              <p style="margin:0;"><a href="https://metrica.uno/privacy/" style="color:#7a7c7a;">Privacy</a> · <a href="https://metrica.uno/terms/" style="color:#7a7c7a;">Terms</a> · <a href="https://metrica.uno/cookies/" style="color:#7a7c7a;">Cookies</a> · <a href="` + htmlEscape(appURL) + `/abuse" style="color:#7a7c7a;">Report abuse</a></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
	return text, html
}

func paragraph(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return `<tr><td style="padding:0 32px 18px;"><p style="margin:0;color:#4d4f4d;font-size:16px;line-height:1.55;">` + htmlEscape(value) + `</p></td></tr>`
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
		"tags":        []string{"htmlshare", "transactional"},
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
		from = "htmlshare <noreply@metricauno.com>"
	}
	envelopeFrom := from
	if parsed, err := mail.ParseAddress(from); err == nil {
		envelopeFrom = parsed.Address
	}
	message := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="htmlshare-alt"`,
		"",
		"--htmlshare-alt",
		`Content-Type: text/plain; charset="utf-8"`,
		"Content-Transfer-Encoding: 8bit",
		"",
		text,
		"",
		"--htmlshare-alt",
		`Content-Type: text/html; charset="utf-8"`,
		"Content-Transfer-Encoding: 8bit",
		"",
		html,
		"",
		"--htmlshare-alt--",
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
