-- name: ClearAll :exec
TRUNCATE signed_access_proofs, signed_access_tokens, comments, bans, strikes, abuse_reports, access_logs, shares, publications, api_keys, magic_links, sessions, users;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at, id;

-- name: InsertUser :exec
INSERT INTO users (id, email, name, provider, password_hash, auto_provisioned, confirmation_deadline, email_confirmed_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListSessions :many
SELECT * FROM sessions ORDER BY created_at, id;

-- name: InsertSession :exec
INSERT INTO sessions (id, user_id, expires_at, created_at)
VALUES ($1, $2, $3, $4);

-- name: ListMagicLinks :many
SELECT * FROM magic_links ORDER BY created_at, id;

-- name: InsertMagicLink :exec
INSERT INTO magic_links (id, user_id, email, token_hash, purpose, publication_id, expires_at, used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListAPIKeys :many
SELECT * FROM api_keys ORDER BY created_at, id;

-- name: InsertAPIKey :exec
INSERT INTO api_keys (id, user_id, name, token_prefix, token_hash, created_at, expires_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListPublications :many
SELECT * FROM publications ORDER BY created_at, id;

-- name: InsertPublication :exec
INSERT INTO publications (id, owner_id, created_ip, title, slug, visibility, require_registration, files, blocked_at, blocked_reason, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: ListShares :many
SELECT * FROM shares ORDER BY created_at, id;

-- name: InsertShare :exec
INSERT INTO shares (id, publication_id, email, user_id, token_hash, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAccessLogs :many
SELECT * FROM access_logs ORDER BY created_at, id;

-- name: InsertAccessLog :exec
INSERT INTO access_logs (id, publication_id, slug, path, ip, user_agent, user_id, email, allowed, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: ListAbuseReports :many
SELECT * FROM abuse_reports ORDER BY created_at, id;

-- name: InsertAbuseReport :exec
INSERT INTO abuse_reports (id, publication_id, slug, reporter_email, reporter_ip, reason, details, status, severity, analysis_summary, auto_blocked, created_at, reviewed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: ListStrikes :many
SELECT * FROM strikes ORDER BY created_at, id;

-- name: InsertStrike :exec
INSERT INTO strikes (id, user_id, email, ip, publication_id, abuse_id, reason, severity, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListBans :many
SELECT * FROM bans ORDER BY created_at, id;

-- name: InsertBan :exec
INSERT INTO bans (id, user_id, email, ip, reason, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListComments :many
SELECT * FROM comments ORDER BY created_at, id;

-- name: InsertComment :exec
INSERT INTO comments (id, publication_id, parent_id, user_id, email, ip, body, scope, anchor_text, anchor_selector, created_at, archived_at, deleted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: ListSignedAccessTokens :many
SELECT * FROM signed_access_tokens ORDER BY created_at, id;

-- name: InsertSignedAccessToken :exec
INSERT INTO signed_access_tokens (id, publication_id, email, token_hash, created_at, expires_at, used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListSignedAccessProofs :many
SELECT * FROM signed_access_proofs ORDER BY created_at, id;

-- name: InsertSignedAccessProof :exec
INSERT INTO signed_access_proofs (id, publication_id, email, ip, user_agent, token_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);
