package htmlshare

import "time"

type User struct {
	ID                   string     `json:"id"`
	Email                string     `json:"email"`
	Name                 string     `json:"name"`
	Provider             string     `json:"provider"`
	PasswordHash         string     `json:"password_hash,omitempty"`
	AutoProvisioned      bool       `json:"auto_provisioned"`
	ConfirmationDeadline time.Time  `json:"confirmation_deadline,omitempty"`
	EmailConfirmedAt     *time.Time `json:"email_confirmed_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

func (u User) EmailConfirmed() bool {
	return u.EmailConfirmedAt != nil || u.Provider == "google"
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type MagicLink struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Email         string    `json:"email"`
	TokenHash     string    `json:"token_hash"`
	Purpose       string    `json:"purpose"`
	PublicationID string    `json:"publication_id,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	UsedAt        time.Time `json:"used_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type APIKey struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	TokenPrefix string    `json:"token_prefix"`
	TokenHash   string    `json:"token_hash"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
}

type Publication struct {
	ID                  string    `json:"id"`
	OwnerID             string    `json:"owner_id"`
	CreatedIP           string    `json:"created_ip,omitempty"`
	Title               string    `json:"title"`
	Slug                string    `json:"slug"`
	Visibility          string    `json:"visibility"`
	RequireRegistration bool      `json:"require_registration"`
	Files               []string  `json:"files"`
	BlockedAt           time.Time `json:"blocked_at,omitempty"`
	BlockedReason       string    `json:"blocked_reason,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

type Share struct {
	ID            string    `json:"id"`
	PublicationID string    `json:"publication_id"`
	Email         string    `json:"email"`
	UserID        string    `json:"user_id,omitempty"`
	TokenHash     string    `json:"token_hash,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type AccessLog struct {
	ID            string    `json:"id"`
	PublicationID string    `json:"publication_id"`
	Slug          string    `json:"slug"`
	Path          string    `json:"path"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	UserID        string    `json:"user_id,omitempty"`
	Email         string    `json:"email,omitempty"`
	Allowed       bool      `json:"allowed"`
	Status        int       `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

type AbuseReport struct {
	ID              string    `json:"id"`
	PublicationID   string    `json:"publication_id"`
	Slug            string    `json:"slug"`
	ReporterEmail   string    `json:"reporter_email,omitempty"`
	ReporterIP      string    `json:"reporter_ip"`
	Reason          string    `json:"reason"`
	Details         string    `json:"details,omitempty"`
	Status          string    `json:"status"`
	Severity        string    `json:"severity"`
	AnalysisSummary string    `json:"analysis_summary,omitempty"`
	AutoBlocked     bool      `json:"auto_blocked"`
	CreatedAt       time.Time `json:"created_at"`
	ReviewedAt      time.Time `json:"reviewed_at,omitempty"`
}

type Strike struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id,omitempty"`
	Email         string    `json:"email,omitempty"`
	IP            string    `json:"ip,omitempty"`
	PublicationID string    `json:"publication_id,omitempty"`
	AbuseID       string    `json:"abuse_id,omitempty"`
	Reason        string    `json:"reason"`
	Severity      string    `json:"severity"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Ban struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id,omitempty"`
	Email     string    `json:"email,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Comment struct {
	ID             string    `json:"id"`
	PublicationID  string    `json:"publication_id"`
	ParentID       string    `json:"parent_id,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	Email          string    `json:"email,omitempty"`
	IP             string    `json:"ip"`
	Body           string    `json:"body"`
	Scope          string    `json:"scope"`
	AnchorText     string    `json:"anchor_text,omitempty"`
	AnchorSelector string    `json:"anchor_selector,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ArchivedAt     time.Time `json:"archived_at,omitempty"`
	DeletedAt      time.Time `json:"deleted_at,omitempty"`
}

type SignedAccessToken struct {
	ID            string    `json:"id"`
	PublicationID string    `json:"publication_id"`
	Email         string    `json:"email"`
	TokenHash     string    `json:"token_hash"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	UsedAt        time.Time `json:"used_at,omitempty"`
}

type SignedAccessProof struct {
	ID            string    `json:"id"`
	PublicationID string    `json:"publication_id"`
	Email         string    `json:"email"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	TokenID       string    `json:"token_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type DB struct {
	Users        []User              `json:"users"`
	Sessions     []Session           `json:"sessions"`
	MagicLinks   []MagicLink         `json:"magic_links"`
	APIKeys      []APIKey            `json:"api_keys"`
	Publications []Publication       `json:"publications"`
	Shares       []Share             `json:"shares"`
	AccessLogs   []AccessLog         `json:"access_logs"`
	AbuseReports []AbuseReport       `json:"abuse_reports"`
	Strikes      []Strike            `json:"strikes"`
	Bans         []Ban               `json:"bans"`
	Comments     []Comment           `json:"comments"`
	SignedTokens []SignedAccessToken `json:"signed_tokens"`
	SignedProofs []SignedAccessProof `json:"signed_proofs"`
}
