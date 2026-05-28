package htmlshare

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	mu   sync.Mutex
	dir  string
	file string
	db   DB
	pg   *sql.DB
	s3   *S3Client
}

func NewStore(dir string) (*Store, error) {
	if dir == "" {
		dir = "data"
	}
	store := &Store{dir: dir, file: filepath.Join(dir, "db.json"), s3: NewS3ClientFromEnv()}
	if err := os.MkdirAll(filepath.Join(dir, "publications"), 0o755); err != nil {
		return nil, err
	}
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		if err := store.openPostgres(databaseURL); err != nil {
			return nil, err
		}
		return store, nil
	}
	raw, err := os.ReadFile(store.file)
	if err == nil {
		if err := unmarshalLegacyState(raw, &store.db); err != nil {
			return nil, err
		}
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
		return store, store.migrateLegacyPublicationStorage()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return store, store.saveLocked()
}

func (s *Store) openPostgres(databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}
	if err := ensurePostgresSchema(db); err != nil {
		return err
	}
	s.pg = db
	if err := s.migrateLegacyPostgresState(); err != nil {
		return err
	}
	if err := s.migrateLegacyPublicationIDs(); err != nil {
		return err
	}
	if err := s.loadPostgres(); err != nil {
		return err
	}
	return s.migrateLegacyPublicationStorage()
}

func (s *Store) DataDir() string {
	return s.dir
}

func (s *Store) WithDB(fn func(*DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.db); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) ReadDB(fn func(DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.db)
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return err
	}
	if s.pg != nil {
		return s.savePostgres()
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.file, raw, 0o600)
}

func (s *Store) PublicationDir(publicationID string) string {
	return filepath.Join(s.dir, "publications", publicationID)
}

func (s *Store) DeletePublicationDir(publicationID string) error {
	if s.s3 != nil {
		return s.s3.DeletePrefix("publications/" + publicationID + "/")
	}
	return os.RemoveAll(s.PublicationDir(publicationID))
}

func (s *Store) WritePublicationFile(publicationID, name string, content []byte) (string, error) {
	clean, err := cleanPublicationPath(name)
	if err != nil {
		return "", err
	}
	if s.s3 != nil {
		return clean, s.s3.PutObject("publications/"+publicationID+"/"+clean, content)
	}
	target := filepath.Join(s.PublicationDir(publicationID), clean)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	return clean, os.WriteFile(target, content, 0o644)
}

func (s *Store) ReadPublicationFile(publicationID, name string) ([]byte, error) {
	clean, err := cleanPublicationPath(name)
	if err != nil {
		return nil, err
	}
	if s.s3 != nil {
		return s.s3.GetObject("publications/" + publicationID + "/" + clean)
	}
	path, err := s.PublicationFile(publicationID, clean)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func (s *Store) PublicationFile(publicationID, name string) (string, error) {
	clean, err := cleanPublicationPath(name)
	if err != nil {
		return "", err
	}
	base := s.PublicationDir(publicationID)
	target := filepath.Clean(filepath.Join(base, clean))
	if target != base && !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		return "", errors.New("unsafe publication path")
	}
	return target, nil
}

func cleanPublicationPath(name string) (string, error) {
	name = strings.TrimLeft(strings.ReplaceAll(name, "\\", "/"), "/")
	if name == "" {
		name = "index.html"
	}
	clean := filepath.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "..") || strings.Contains(clean, string(os.PathSeparator)+".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe publication path")
	}
	return clean, nil
}
