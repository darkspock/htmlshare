package htmlshare

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func NewID(prefix string) string {
	return prefix + "_" + RandomToken(12)
}

func RandomToken(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func Sign(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func SessionCookie(sessionID, secret string) *http.Cookie {
	value := sessionID + "." + Sign(sessionID, secret)
	return &http.Cookie{
		Name:     "hs_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	}
}

func ExpiredSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     "hs_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
	}
}

func VerifySessionCookie(r *http.Request, secret string) string {
	cookie, err := r.Cookie("hs_session")
	if err != nil {
		return ""
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return ""
	}
	if hmac.Equal([]byte(parts[1]), []byte(Sign(parts[0], secret))) {
		return parts[0]
	}
	return ""
}

func Slugify(title string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(title) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "file"
	}
	return fmt.Sprintf("%s-%s", slug, RandomToken(4))
}
