package htmlshare

import (
	"context"
	"database/sql"
	"embed"
	_ "embed"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"htmlshare/internal/htmlshare/state"
)

//go:embed sql/schema.sql
var postgresSchema string

//go:embed sql/migrations/*.sql
var postgresMigrations embed.FS

func ensurePostgresSchema(db *sql.DB) error {
	if _, err := db.Exec(postgresSchema); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	return applyPostgresMigrations(db)
}

func applyPostgresMigrations(db *sql.DB) error {
	files, err := fs.Glob(postgresMigrations, "sql/migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, name := range files {
		version := filepath.Base(name)
		var applied bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		raw, err := postgresMigrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(raw)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) loadPostgres() error {
	ctx := context.Background()
	q := state.New(s.pg)
	var next DB

	users, err := q.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, item := range users {
		next.Users = append(next.Users, User{
			ID:                   item.ID,
			Email:                item.Email,
			Name:                 item.Name,
			Provider:             item.Provider,
			PasswordHash:         item.PasswordHash.String,
			AutoProvisioned:      item.AutoProvisioned,
			ConfirmationDeadline: nullTimeValue(item.ConfirmationDeadline),
			EmailConfirmedAt:     nullTimePtr(item.EmailConfirmedAt),
			CreatedAt:            item.CreatedAt,
		})
	}

	sessions, err := q.ListSessions(ctx)
	if err != nil {
		return err
	}
	for _, item := range sessions {
		next.Sessions = append(next.Sessions, Session{ID: item.ID, UserID: item.UserID, ExpiresAt: item.ExpiresAt, CreatedAt: item.CreatedAt})
	}

	links, err := q.ListMagicLinks(ctx)
	if err != nil {
		return err
	}
	for _, item := range links {
		next.MagicLinks = append(next.MagicLinks, MagicLink{
			ID:            item.ID,
			UserID:        item.UserID,
			Email:         item.Email,
			TokenHash:     item.TokenHash,
			Purpose:       item.Purpose,
			PublicationID: item.PublicationID.String,
			ExpiresAt:     item.ExpiresAt,
			UsedAt:        nullTimeValue(item.UsedAt),
			CreatedAt:     item.CreatedAt,
		})
	}

	keys, err := q.ListAPIKeys(ctx)
	if err != nil {
		return err
	}
	for _, item := range keys {
		next.APIKeys = append(next.APIKeys, APIKey{
			ID:          item.ID,
			UserID:      item.UserID,
			Name:        item.Name,
			TokenPrefix: item.TokenPrefix,
			TokenHash:   item.TokenHash,
			CreatedAt:   item.CreatedAt,
			ExpiresAt:   nullTimeValue(item.ExpiresAt),
			LastUsedAt:  nullTimeValue(item.LastUsedAt),
		})
	}

	agents, err := q.ListAgents(ctx)
	if err != nil {
		return err
	}
	for _, item := range agents {
		next.Agents = append(next.Agents, Agent{
			ID:             item.ID,
			ExternalIDHash: item.ExternalIDHash,
			Name:           item.Name,
			FirstIP:        item.FirstIp,
			LastIP:         item.LastIp,
			StorageBytes:   item.StorageBytes,
			BlockedAt:      nullTimeValue(item.BlockedAt),
			BlockedReason:  item.BlockedReason.String,
			CreatedAt:      item.CreatedAt,
			LastSeenAt:     item.LastSeenAt,
		})
	}

	publications, err := q.ListPublications(ctx)
	if err != nil {
		return err
	}
	for _, item := range publications {
		next.Publications = append(next.Publications, Publication{
			ID:                  item.ID,
			OwnerID:             item.OwnerID.String,
			AgentID:             item.AgentID.String,
			Mode:                item.Mode,
			CreatedIP:           item.CreatedIp.String,
			Title:               item.Title,
			Slug:                item.Slug,
			Visibility:          item.Visibility,
			RequireRegistration: item.RequireRegistration,
			Files:               item.Files,
			SizeBytes:           item.SizeBytes,
			BlockedAt:           nullTimeValue(item.BlockedAt),
			BlockedReason:       item.BlockedReason.String,
			ExpiresAt:           nullTimeValue(item.ExpiresAt),
			CreatedAt:           item.CreatedAt,
		})
	}

	shares, err := q.ListShares(ctx)
	if err != nil {
		return err
	}
	for _, item := range shares {
		next.Shares = append(next.Shares, Share{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, UserID: item.UserID.String, TokenHash: item.TokenHash.String, CreatedAt: item.CreatedAt})
	}

	logs, err := q.ListAccessLogs(ctx)
	if err != nil {
		return err
	}
	for _, item := range logs {
		next.AccessLogs = append(next.AccessLogs, AccessLog{
			ID:            item.ID,
			PublicationID: item.PublicationID,
			Slug:          item.Slug,
			Path:          item.Path,
			IP:            item.Ip,
			UserAgent:     item.UserAgent,
			UserID:        item.UserID.String,
			Email:         item.Email.String,
			Allowed:       item.Allowed,
			Status:        int(item.Status),
			CreatedAt:     item.CreatedAt,
		})
	}

	abuseReports, err := q.ListAbuseReports(ctx)
	if err != nil {
		return err
	}
	for _, item := range abuseReports {
		next.AbuseReports = append(next.AbuseReports, AbuseReport{
			ID:              item.ID,
			PublicationID:   item.PublicationID,
			Slug:            item.Slug,
			ReporterEmail:   item.ReporterEmail.String,
			ReporterIP:      item.ReporterIp,
			Reason:          item.Reason,
			Details:         item.Details.String,
			Status:          item.Status,
			Severity:        item.Severity,
			AnalysisSummary: item.AnalysisSummary.String,
			AutoBlocked:     item.AutoBlocked,
			CreatedAt:       item.CreatedAt,
			ReviewedAt:      nullTimeValue(item.ReviewedAt),
		})
	}

	strikes, err := q.ListStrikes(ctx)
	if err != nil {
		return err
	}
	for _, item := range strikes {
		next.Strikes = append(next.Strikes, Strike{
			ID:            item.ID,
			UserID:        item.UserID.String,
			Email:         item.Email.String,
			IP:            item.Ip.String,
			PublicationID: item.PublicationID.String,
			AbuseID:       item.AbuseID.String,
			Reason:        item.Reason,
			Severity:      item.Severity,
			CreatedAt:     item.CreatedAt,
			ExpiresAt:     item.ExpiresAt,
		})
	}

	bans, err := q.ListBans(ctx)
	if err != nil {
		return err
	}
	for _, item := range bans {
		next.Bans = append(next.Bans, Ban{ID: item.ID, UserID: item.UserID.String, Email: item.Email.String, IP: item.Ip.String, Reason: item.Reason, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt})
	}

	comments, err := q.ListComments(ctx)
	if err != nil {
		return err
	}
	for _, item := range comments {
		next.Comments = append(next.Comments, Comment{
			ID:             item.ID,
			PublicationID:  item.PublicationID,
			ParentID:       item.ParentID.String,
			UserID:         item.UserID.String,
			Email:          item.Email.String,
			IP:             item.Ip,
			Body:           item.Body,
			Scope:          item.Scope,
			AnchorText:     item.AnchorText.String,
			AnchorSelector: item.AnchorSelector.String,
			CreatedAt:      item.CreatedAt,
			ArchivedAt:     nullTimeValue(item.ArchivedAt),
			DeletedAt:      nullTimeValue(item.DeletedAt),
		})
	}

	tokens, err := q.ListSignedAccessTokens(ctx)
	if err != nil {
		return err
	}
	for _, item := range tokens {
		next.SignedTokens = append(next.SignedTokens, SignedAccessToken{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, TokenHash: item.TokenHash, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt, UsedAt: nullTimeValue(item.UsedAt)})
	}

	proofs, err := q.ListSignedAccessProofs(ctx)
	if err != nil {
		return err
	}
	for _, item := range proofs {
		next.SignedProofs = append(next.SignedProofs, SignedAccessProof{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, IP: item.Ip, UserAgent: item.UserAgent, TokenID: item.TokenID, CreatedAt: item.CreatedAt})
	}

	s.db = next
	return nil
}

func (s *Store) savePostgres() error {
	ctx := context.Background()
	tx, err := s.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := state.New(tx)
	if err := q.ClearAll(ctx); err != nil {
		return err
	}
	for _, item := range s.db.Users {
		if err := q.InsertUser(ctx, state.InsertUserParams{
			ID:                   item.ID,
			Email:                item.Email,
			Name:                 item.Name,
			Provider:             item.Provider,
			PasswordHash:         nullString(item.PasswordHash),
			AutoProvisioned:      item.AutoProvisioned,
			ConfirmationDeadline: nullTime(item.ConfirmationDeadline),
			EmailConfirmedAt:     nullTimeFromPtr(item.EmailConfirmedAt),
			CreatedAt:            item.CreatedAt,
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Sessions {
		if err := q.InsertSession(ctx, state.InsertSessionParams{ID: item.ID, UserID: item.UserID, ExpiresAt: item.ExpiresAt, CreatedAt: item.CreatedAt}); err != nil {
			return err
		}
	}
	for _, item := range s.db.MagicLinks {
		if err := q.InsertMagicLink(ctx, state.InsertMagicLinkParams{
			ID:            item.ID,
			UserID:        item.UserID,
			Email:         item.Email,
			TokenHash:     item.TokenHash,
			Purpose:       item.Purpose,
			PublicationID: nullString(item.PublicationID),
			ExpiresAt:     item.ExpiresAt,
			UsedAt:        nullTime(item.UsedAt),
			CreatedAt:     item.CreatedAt,
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.APIKeys {
		if err := q.InsertAPIKey(ctx, state.InsertAPIKeyParams{
			ID:          item.ID,
			UserID:      item.UserID,
			Name:        item.Name,
			TokenPrefix: item.TokenPrefix,
			TokenHash:   item.TokenHash,
			CreatedAt:   item.CreatedAt,
			ExpiresAt:   nullTime(item.ExpiresAt),
			LastUsedAt:  nullTime(item.LastUsedAt),
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Agents {
		if _, err := q.UpsertAgent(ctx, state.UpsertAgentParams{
			ID:             item.ID,
			ExternalIDHash: item.ExternalIDHash,
			Name:           item.Name,
			FirstIp:        item.FirstIP,
			LastIp:         item.LastIP,
			StorageBytes:   item.StorageBytes,
			BlockedAt:      nullTime(item.BlockedAt),
			BlockedReason:  nullString(item.BlockedReason),
			CreatedAt:      item.CreatedAt,
			LastSeenAt:     item.LastSeenAt,
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Publications {
		mode := item.Mode
		if mode == "" {
			mode = "registered"
		}
		if err := q.InsertPublication(ctx, state.InsertPublicationParams{
			ID:                  item.ID,
			OwnerID:             nullString(item.OwnerID),
			AgentID:             nullString(item.AgentID),
			Mode:                mode,
			CreatedIp:           nullString(item.CreatedIP),
			Title:               item.Title,
			Slug:                item.Slug,
			Visibility:          item.Visibility,
			RequireRegistration: item.RequireRegistration,
			Files:               item.Files,
			SizeBytes:           item.SizeBytes,
			BlockedAt:           nullTime(item.BlockedAt),
			BlockedReason:       nullString(item.BlockedReason),
			ExpiresAt:           nullTime(item.ExpiresAt),
			CreatedAt:           item.CreatedAt,
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Shares {
		if err := q.InsertShare(ctx, state.InsertShareParams{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, UserID: nullString(item.UserID), TokenHash: nullString(item.TokenHash), CreatedAt: item.CreatedAt}); err != nil {
			return err
		}
	}
	for _, item := range s.db.AccessLogs {
		if err := q.InsertAccessLog(ctx, state.InsertAccessLogParams{ID: item.ID, PublicationID: item.PublicationID, Slug: item.Slug, Path: item.Path, Ip: item.IP, UserAgent: item.UserAgent, UserID: nullString(item.UserID), Email: nullString(item.Email), Allowed: item.Allowed, Status: int32(item.Status), CreatedAt: item.CreatedAt}); err != nil {
			return err
		}
	}
	for _, item := range s.db.AbuseReports {
		if err := q.InsertAbuseReport(ctx, state.InsertAbuseReportParams{ID: item.ID, PublicationID: item.PublicationID, Slug: item.Slug, ReporterEmail: nullString(item.ReporterEmail), ReporterIp: item.ReporterIP, Reason: item.Reason, Details: nullString(item.Details), Status: item.Status, Severity: item.Severity, AnalysisSummary: nullString(item.AnalysisSummary), AutoBlocked: item.AutoBlocked, CreatedAt: item.CreatedAt, ReviewedAt: nullTime(item.ReviewedAt)}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Strikes {
		if err := q.InsertStrike(ctx, state.InsertStrikeParams{ID: item.ID, UserID: nullString(item.UserID), Email: nullString(item.Email), Ip: nullString(item.IP), PublicationID: nullString(item.PublicationID), AbuseID: nullString(item.AbuseID), Reason: item.Reason, Severity: item.Severity, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Bans {
		if err := q.InsertBan(ctx, state.InsertBanParams{ID: item.ID, UserID: nullString(item.UserID), Email: nullString(item.Email), Ip: nullString(item.IP), Reason: item.Reason, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Comments {
		if err := q.InsertComment(ctx, state.InsertCommentParams{ID: item.ID, PublicationID: item.PublicationID, ParentID: nullString(item.ParentID), UserID: nullString(item.UserID), Email: nullString(item.Email), Ip: item.IP, Body: item.Body, Scope: item.Scope, AnchorText: nullString(item.AnchorText), AnchorSelector: nullString(item.AnchorSelector), CreatedAt: item.CreatedAt, ArchivedAt: nullTime(item.ArchivedAt), DeletedAt: nullTime(item.DeletedAt)}); err != nil {
			return err
		}
	}
	for _, item := range s.db.SignedTokens {
		if err := q.InsertSignedAccessToken(ctx, state.InsertSignedAccessTokenParams{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, TokenHash: item.TokenHash, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt, UsedAt: nullTime(item.UsedAt)}); err != nil {
			return err
		}
	}
	for _, item := range s.db.SignedProofs {
		if err := q.InsertSignedAccessProof(ctx, state.InsertSignedAccessProofParams{ID: item.ID, PublicationID: item.PublicationID, Email: item.Email, Ip: item.IP, UserAgent: item.UserAgent, TokenID: item.TokenID, CreatedAt: item.CreatedAt}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) migrateLegacyPostgresState() error {
	var exists bool
	if err := s.pg.QueryRow(`SELECT to_regclass('public.htmlshare_state') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var raw []byte
	err := s.pg.QueryRow(`SELECT payload FROM htmlshare_state WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = s.pg.Exec(`DROP TABLE htmlshare_state`)
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		_, _ = s.pg.Exec(`DROP TABLE htmlshare_state`)
		return nil
	}
	var migrated DB
	if err := unmarshalLegacyState(raw, &migrated); err != nil {
		return err
	}
	s.db = migrated
	if err := s.savePostgres(); err != nil {
		return err
	}
	_, err = s.pg.Exec(`DROP TABLE htmlshare_state`)
	return err
}

func (s *Store) migrateLegacyPublicationIDs() error {
	rows, err := s.pg.Query(`SELECT id FROM publications WHERE id LIKE 'rep\_%' ESCAPE '\' OR id LIKE 'rpt\_%' ESCAPE '\' ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type idPair struct {
		oldID string
		newID string
	}
	var pairs []idPair
	for rows.Next() {
		var oldID string
		if err := rows.Scan(&oldID); err != nil {
			return err
		}
		newID := strings.TrimPrefix(strings.TrimPrefix(oldID, "rep_"), "rpt_")
		if newID == "" || newID == oldID {
			continue
		}
		pairs = append(pairs, idPair{oldID: oldID, newID: "pub_" + newID})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(pairs) == 0 {
		return nil
	}

	tx, err := s.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, pair := range pairs {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM publications WHERE id = $1)`, pair.newID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		var slug string
		if err := tx.QueryRow(`SELECT slug FROM publications WHERE id = $1`, pair.oldID).Scan(&slug); err != nil {
			return err
		}
		legacySlug := slug + "__legacy_id_migration"
		if _, err := tx.Exec(`UPDATE publications SET slug = $2 WHERE id = $1`, pair.oldID, legacySlug); err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO publications (id, owner_id, created_ip, title, slug, visibility, require_registration, files, blocked_at, blocked_reason, expires_at, created_at)
			SELECT $2, owner_id, created_ip, title, $3, visibility, require_registration, files, blocked_at, blocked_reason, expires_at, created_at
			FROM publications
			WHERE id = $1
		`, pair.oldID, pair.newID, slug); err != nil {
			return err
		}
		for _, table := range []string{"magic_links", "shares", "access_logs", "abuse_reports", "strikes", "comments", "signed_access_tokens", "signed_access_proofs"} {
			if _, err := tx.Exec(`UPDATE `+table+` SET publication_id = $2 WHERE publication_id = $1`, pair.oldID, pair.newID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM publications WHERE id = $1`, pair.oldID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	for _, pair := range pairs {
		if err := s.movePublicationStorage(pair.oldID, pair.newID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) movePublicationStorage(oldID, newID string) error {
	oldPrefix := "publications/" + oldID + "/"
	newPrefix := "publications/" + newID + "/"
	if s.s3 != nil {
		return s.s3.MovePrefix(oldPrefix, newPrefix)
	}
	oldPath := filepath.Join(s.dir, "publications", oldID)
	newPath := filepath.Join(s.dir, "publications", newID)
	if _, err := os.Stat(oldPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := os.Stat(newPath); errors.Is(err, os.ErrNotExist) {
		return os.Rename(oldPath, newPath)
	}
	entries, err := os.ReadDir(oldPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.Rename(filepath.Join(oldPath, entry.Name()), filepath.Join(newPath, entry.Name())); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return os.RemoveAll(oldPath)
}

func unmarshalLegacyState(raw []byte, target *DB) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	if legacy, ok := root["reports"]; ok {
		if _, hasPublications := root["publications"]; !hasPublications {
			root["publications"] = legacy
		}
		delete(root, "reports")
	}
	for _, key := range []string{"magic_links", "shares", "access_logs", "abuse_reports", "strikes", "comments", "signed_tokens", "signed_proofs"} {
		renamed, err := renameReportID(root[key])
		if err != nil {
			return err
		}
		if renamed != nil {
			root[key] = renamed
		}
	}
	next, err := json.Marshal(root)
	if err != nil {
		return err
	}
	return json.Unmarshal(next, target)
}

func renameReportID(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	for _, item := range items {
		if value, ok := item["report_id"]; ok {
			if _, hasPublication := item["publication_id"]; !hasPublication {
				item["publication_id"] = value
			}
			delete(item, "report_id")
		}
	}
	return json.Marshal(items)
}

func (s *Store) migrateLegacyPublicationStorage() error {
	if s.s3 != nil {
		return s.s3.MovePrefix("reports/", "publications/")
	}
	oldPath := filepath.Join(s.dir, "reports")
	newPath := filepath.Join(s.dir, "publications")
	if _, err := os.Stat(oldPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if _, err := os.Stat(newPath); errors.Is(err, os.ErrNotExist) {
		return os.Rename(oldPath, newPath)
	}
	entries, err := os.ReadDir(oldPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.Rename(filepath.Join(oldPath, entry.Name()), filepath.Join(newPath, entry.Name())); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return os.RemoveAll(oldPath)
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: strings.TrimSpace(value) != ""}
}

func nullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}

func nullTimeFromPtr(value *time.Time) sql.NullTime {
	if value == nil || value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func nullTimeValue(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	next := value.Time
	return &next
}
