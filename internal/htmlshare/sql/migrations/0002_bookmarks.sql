CREATE TABLE IF NOT EXISTS bookmarks (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  publication_id text NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
  kind text NOT NULL DEFAULT 'read_later',
  created_at timestamptz NOT NULL,
  UNIQUE (user_id, publication_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_publication_id ON bookmarks(publication_id);
