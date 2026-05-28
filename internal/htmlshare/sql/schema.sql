CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  name text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  password_hash text,
  auto_provisioned boolean NOT NULL DEFAULT false,
  confirmation_deadline timestamptz,
  email_confirmed_at timestamptz,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email text NOT NULL,
  token_hash text NOT NULL,
  purpose text NOT NULL,
  publication_id text,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  token_prefix text NOT NULL,
  token_hash text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz,
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS agents (
  id text PRIMARY KEY,
  external_id_hash text NOT NULL UNIQUE,
  name text NOT NULL DEFAULT '',
  first_ip text NOT NULL DEFAULT '',
  last_ip text NOT NULL DEFAULT '',
  storage_bytes bigint NOT NULL DEFAULT 0,
  blocked_at timestamptz,
  blocked_reason text,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS publications (
  id text PRIMARY KEY,
  owner_id text REFERENCES users(id) ON DELETE CASCADE,
  agent_id text REFERENCES agents(id) ON DELETE SET NULL,
  mode text NOT NULL DEFAULT 'registered',
  created_ip text,
  title text NOT NULL,
  slug text NOT NULL UNIQUE,
  visibility text NOT NULL,
  require_registration boolean NOT NULL DEFAULT false,
  files text[] NOT NULL DEFAULT '{}',
  size_bytes bigint NOT NULL DEFAULT 0,
  blocked_at timestamptz,
  blocked_reason text,
  expires_at timestamptz,
  created_at timestamptz NOT NULL
);

ALTER TABLE publications ALTER COLUMN owner_id DROP NOT NULL;
ALTER TABLE publications ADD COLUMN IF NOT EXISTS agent_id text REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE publications ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'registered';
ALTER TABLE publications ADD COLUMN IF NOT EXISTS size_bytes bigint NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS shares (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  email text NOT NULL,
  user_id text REFERENCES users(id) ON DELETE SET NULL,
  token_hash text,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  slug text NOT NULL,
  path text NOT NULL,
  ip text NOT NULL,
  user_agent text NOT NULL,
  user_id text REFERENCES users(id) ON DELETE SET NULL,
  email text,
  allowed boolean NOT NULL,
  status integer NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS abuse_reports (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  slug text NOT NULL,
  reporter_email text,
  reporter_ip text NOT NULL,
  reason text NOT NULL,
  details text,
  status text NOT NULL,
  severity text NOT NULL,
  analysis_summary text,
  auto_blocked boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL,
  reviewed_at timestamptz
);

CREATE TABLE IF NOT EXISTS strikes (
  id text PRIMARY KEY,
  user_id text REFERENCES users(id) ON DELETE CASCADE,
  email text,
  ip text,
  publication_id text REFERENCES publications(id) ON DELETE CASCADE,
  abuse_id text REFERENCES abuse_reports(id) ON DELETE CASCADE,
  reason text NOT NULL,
  severity text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
  id text PRIMARY KEY,
  user_id text REFERENCES users(id) ON DELETE CASCADE,
  email text,
  ip text,
  reason text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  parent_id text REFERENCES comments(id) ON DELETE CASCADE,
  user_id text REFERENCES users(id) ON DELETE SET NULL,
  email text,
  ip text NOT NULL,
  body text NOT NULL,
  scope text NOT NULL,
  anchor_text text,
  anchor_selector text,
  created_at timestamptz NOT NULL,
  archived_at timestamptz,
  deleted_at timestamptz
);

CREATE TABLE IF NOT EXISTS signed_access_tokens (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  email text NOT NULL,
  token_hash text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);

CREATE TABLE IF NOT EXISTS signed_access_proofs (
  id text PRIMARY KEY,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  email text NOT NULL,
  ip text NOT NULL,
  user_agent text NOT NULL,
  token_id text NOT NULL REFERENCES signed_access_tokens(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS bookmarks (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  kind text NOT NULL DEFAULT 'read_later',
  created_at timestamptz NOT NULL,
  UNIQUE (user_id, publication_id, kind)
);
