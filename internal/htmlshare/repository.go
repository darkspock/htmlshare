package htmlshare

import (
	"context"
	"database/sql"
	"time"

	"htmlshare/internal/htmlshare/state"
)

type FastUsage struct {
	IPCount      int64
	AgentCount   int64
	IPStorage    int64
	AgentStorage int64
}

func (s *Store) UserByAPIKey(tokenHash string, now time.Time) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		q := state.New(s.pg)
		key, err := q.GetAPIKeyByHash(context.Background(), tokenHash)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		expiresAt := nullTimeValue(key.ExpiresAt)
		if !expiresAt.IsZero() && now.After(expiresAt) {
			return nil, nil
		}
		userRow, err := q.GetUserByID(context.Background(), key.UserID)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if err := q.UpdateAPIKeyLastUsed(context.Background(), state.UpdateAPIKeyLastUsedParams{ID: key.ID, LastUsedAt: nullTime(now)}); err != nil {
			return nil, err
		}
		user := userFromState(userRow)
		for i := range s.db.APIKeys {
			if s.db.APIKeys[i].ID == key.ID {
				s.db.APIKeys[i].LastUsedAt = now
				break
			}
		}
		return &user, nil
	}
	for i := range s.db.APIKeys {
		if s.db.APIKeys[i].TokenHash != tokenHash {
			continue
		}
		if !s.db.APIKeys[i].ExpiresAt.IsZero() && now.After(s.db.APIKeys[i].ExpiresAt) {
			return nil, nil
		}
		s.db.APIKeys[i].LastUsedAt = now
		for _, candidate := range s.db.Users {
			if candidate.ID == s.db.APIKeys[i].UserID {
				copy := candidate
				return &copy, s.saveLocked()
			}
		}
	}
	return nil, nil
}

func (s *Store) EnsureAgent(externalIDHash, name, ip string, now time.Time) (Agent, error) {
	agent := Agent{
		ID:             NewID("agt"),
		ExternalIDHash: externalIDHash,
		Name:           name,
		FirstIP:        ip,
		LastIP:         ip,
		CreatedAt:      now,
		LastSeenAt:     now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		item, err := state.New(s.pg).UpsertAgent(context.Background(), state.UpsertAgentParams{
			ID:             agent.ID,
			ExternalIDHash: agent.ExternalIDHash,
			Name:           agent.Name,
			FirstIp:        agent.FirstIP,
			LastIp:         agent.LastIP,
			CreatedAt:      agent.CreatedAt,
			LastSeenAt:     agent.LastSeenAt,
		})
		if err != nil {
			return Agent{}, err
		}
		agent = agentFromState(item)
	}
	for i := range s.db.Agents {
		if s.db.Agents[i].ExternalIDHash == externalIDHash {
			s.db.Agents[i].Name = chooseNonEmpty(name, s.db.Agents[i].Name)
			s.db.Agents[i].LastIP = ip
			s.db.Agents[i].LastSeenAt = now
			if s.pg != nil {
				return s.db.Agents[i], nil
			}
			return s.db.Agents[i], s.saveLocked()
		}
	}
	s.db.Agents = append(s.db.Agents, agent)
	if s.pg != nil {
		return agent, nil
	}
	return agent, s.saveLocked()
}

func (s *Store) FastUsage(agentID, ip string, since, now time.Time) (FastUsage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		q := state.New(s.pg)
		ipCount, err := q.CountFastPublicationsByIPSince(context.Background(), state.CountFastPublicationsByIPSinceParams{CreatedIp: nullString(ip), CreatedAt: since})
		if err != nil {
			return FastUsage{}, err
		}
		agentCount, err := q.CountFastPublicationsByAgentSince(context.Background(), state.CountFastPublicationsByAgentSinceParams{AgentID: nullString(agentID), CreatedAt: since})
		if err != nil {
			return FastUsage{}, err
		}
		ipStorage, err := q.SumFastStorageByIP(context.Background(), state.SumFastStorageByIPParams{CreatedIp: nullString(ip), ExpiresAt: nullTime(now)})
		if err != nil {
			return FastUsage{}, err
		}
		agentStorage, err := q.SumFastStorageByAgent(context.Background(), state.SumFastStorageByAgentParams{AgentID: nullString(agentID), ExpiresAt: nullTime(now)})
		if err != nil {
			return FastUsage{}, err
		}
		return FastUsage{IPCount: ipCount, AgentCount: agentCount, IPStorage: ipStorage, AgentStorage: agentStorage}, nil
	}
	var usage FastUsage
	for _, publication := range s.db.Publications {
		if publication.Mode != "fast" {
			continue
		}
		if publication.CreatedAt.After(since) || publication.CreatedAt.Equal(since) {
			if publication.CreatedIP == ip {
				usage.IPCount++
			}
			if publication.AgentID == agentID {
				usage.AgentCount++
			}
		}
		if publication.ExpiresAt.IsZero() || publication.ExpiresAt.After(now) {
			if publication.CreatedIP == ip {
				usage.IPStorage += publication.SizeBytes
			}
			if publication.AgentID == agentID {
				usage.AgentStorage += publication.SizeBytes
			}
		}
	}
	return usage, nil
}

func (s *Store) AddPublication(publication Publication) error {
	if publication.Mode == "" {
		publication.Mode = "registered"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		tx, err := s.pg.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		q := state.New(tx)
		if err := q.InsertPublication(context.Background(), state.InsertPublicationParams{
			ID:                  publication.ID,
			OwnerID:             nullString(publication.OwnerID),
			AgentID:             nullString(publication.AgentID),
			Mode:                publication.Mode,
			CreatedIp:           nullString(publication.CreatedIP),
			Title:               publication.Title,
			Slug:                publication.Slug,
			Visibility:          publication.Visibility,
			RequireRegistration: publication.RequireRegistration,
			Files:               publication.Files,
			SizeBytes:           publication.SizeBytes,
			BlockedAt:           nullTime(publication.BlockedAt),
			BlockedReason:       nullString(publication.BlockedReason),
			ExpiresAt:           nullTime(publication.ExpiresAt),
			CreatedAt:           publication.CreatedAt,
		}); err != nil {
			return err
		}
		if publication.AgentID != "" && publication.SizeBytes > 0 {
			if err := q.IncrementAgentStorage(context.Background(), state.IncrementAgentStorageParams{
				ID:           publication.AgentID,
				StorageBytes: publication.SizeBytes,
				LastSeenAt:   publication.CreatedAt,
			}); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	s.db.Publications = append(s.db.Publications, publication)
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) EnsureMagicUser(email string, now time.Time) (User, error) {
	user := User{}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		q := state.New(s.pg)
		item, err := q.GetUserByEmail(context.Background(), email)
		if err == nil {
			user = userFromState(item)
		} else if err == sql.ErrNoRows {
			user = User{
				ID:                   NewID("usr"),
				Email:                email,
				Provider:             "magic",
				AutoProvisioned:      true,
				ConfirmationDeadline: now.Add(24 * time.Hour),
				CreatedAt:            now,
			}
			if err := q.InsertUser(context.Background(), state.InsertUserParams{
				ID:                   user.ID,
				Email:                user.Email,
				Name:                 user.Name,
				Provider:             user.Provider,
				PasswordHash:         nullString(user.PasswordHash),
				AutoProvisioned:      user.AutoProvisioned,
				ConfirmationDeadline: nullTime(user.ConfirmationDeadline),
				EmailConfirmedAt:     nullTimeFromPtr(user.EmailConfirmedAt),
				CreatedAt:            user.CreatedAt,
			}); err != nil {
				return User{}, err
			}
		} else {
			return User{}, err
		}
	} else {
		for _, candidate := range s.db.Users {
			if candidate.Email == email {
				user = candidate
				break
			}
		}
		if user.ID == "" {
			user = User{
				ID:                   NewID("usr"),
				Email:                email,
				Provider:             "magic",
				AutoProvisioned:      true,
				ConfirmationDeadline: now.Add(24 * time.Hour),
				CreatedAt:            now,
			}
			s.db.Users = append(s.db.Users, user)
			return user, s.saveLocked()
		}
		return user, nil
	}
	for _, candidate := range s.db.Users {
		if candidate.ID == user.ID {
			return user, nil
		}
	}
	s.db.Users = append(s.db.Users, user)
	return user, nil
}

func (s *Store) AddShare(share Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		if err := state.New(s.pg).InsertShare(context.Background(), state.InsertShareParams{
			ID:            share.ID,
			PublicationID: share.PublicationID,
			Email:         share.Email,
			UserID:        nullString(share.UserID),
			TokenHash:     nullString(share.TokenHash),
			CreatedAt:     share.CreatedAt,
		}); err != nil {
			return err
		}
	}
	s.db.Shares = append(s.db.Shares, share)
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) AddMagicLink(link MagicLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		if err := state.New(s.pg).InsertMagicLink(context.Background(), state.InsertMagicLinkParams{
			ID:            link.ID,
			UserID:        link.UserID,
			Email:         link.Email,
			TokenHash:     link.TokenHash,
			Purpose:       link.Purpose,
			PublicationID: nullString(link.PublicationID),
			ExpiresAt:     link.ExpiresAt,
			UsedAt:        nullTime(link.UsedAt),
			CreatedAt:     link.CreatedAt,
		}); err != nil {
			return err
		}
	}
	s.db.MagicLinks = append(s.db.MagicLinks, link)
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) AddAccessLog(entry AccessLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		if err := state.New(s.pg).InsertAccessLog(context.Background(), state.InsertAccessLogParams{
			ID:            entry.ID,
			PublicationID: entry.PublicationID,
			Slug:          entry.Slug,
			Path:          entry.Path,
			Ip:            entry.IP,
			UserAgent:     entry.UserAgent,
			UserID:        nullString(entry.UserID),
			Email:         nullString(entry.Email),
			Allowed:       entry.Allowed,
			Status:        int32(entry.Status),
			CreatedAt:     entry.CreatedAt,
		}); err != nil {
			return err
		}
	}
	s.db.AccessLogs = append(s.db.AccessLogs, entry)
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) UpsertBookmark(bookmark Bookmark) error {
	if bookmark.Kind == "" {
		bookmark.Kind = "read_later"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		if err := state.New(s.pg).UpsertBookmark(context.Background(), state.UpsertBookmarkParams{
			ID:            bookmark.ID,
			UserID:        bookmark.UserID,
			PublicationID: bookmark.PublicationID,
			Kind:          bookmark.Kind,
			CreatedAt:     bookmark.CreatedAt,
		}); err != nil {
			return err
		}
	}
	for _, item := range s.db.Bookmarks {
		if item.UserID == bookmark.UserID && item.PublicationID == bookmark.PublicationID && item.Kind == bookmark.Kind {
			return nil
		}
	}
	s.db.Bookmarks = append(s.db.Bookmarks, bookmark)
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) DeleteBookmark(userID, publicationID, kind string) error {
	if kind == "" {
		kind = "read_later"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg != nil {
		if err := state.New(s.pg).DeleteBookmark(context.Background(), state.DeleteBookmarkParams{UserID: userID, PublicationID: publicationID, Kind: kind}); err != nil {
			return err
		}
	}
	var bookmarks []Bookmark
	for _, item := range s.db.Bookmarks {
		if item.UserID == userID && item.PublicationID == publicationID && item.Kind == kind {
			continue
		}
		bookmarks = append(bookmarks, item)
	}
	s.db.Bookmarks = bookmarks
	if s.pg != nil {
		return nil
	}
	return s.saveLocked()
}

func userFromState(item state.User) User {
	return User{
		ID:                   item.ID,
		Email:                item.Email,
		Name:                 item.Name,
		Provider:             item.Provider,
		PasswordHash:         item.PasswordHash.String,
		AutoProvisioned:      item.AutoProvisioned,
		ConfirmationDeadline: nullTimeValue(item.ConfirmationDeadline),
		EmailConfirmedAt:     nullTimePtr(item.EmailConfirmedAt),
		CreatedAt:            item.CreatedAt,
	}
}

func agentFromState(item state.Agent) Agent {
	return Agent{
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
	}
}

func chooseNonEmpty(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}
