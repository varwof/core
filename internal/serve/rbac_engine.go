// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package serve

import (
	"errors"
	"log/slog"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/engine"
)

// The account/token read and write path prefers the resident memory engine's
// user/token indexes (memory is authoritative when enabled) and falls back to
// the DB on a miss so out-of-band writes (e.g. a CLI against the same store)
// stay visible. Writes keep memory and the backend in step: the backend op runs
// first (it owns identity generation and write serialization), then the
// affected resident row is refreshed/removed in memory.

func (s *Server) getUserByUsername(username string) (*db.RBACUser, error) {
	if e := s.getEngine(); e != nil {
		u, err := e.GetUserByUsername(username)
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine user lookup failed, falling back to DB", "username", username, "error", err)
		}
	}
	return s.getDB().GetUserByUsername(username)
}

func (s *Server) getToken(token string) (*db.TokenInfo, error) {
	if e := s.getEngine(); e != nil {
		info, err := e.GetToken(token)
		if err == nil {
			return info, nil
		}
		if !errors.Is(err, engine.ErrNotFound) {
			slog.Warn("serve: engine token lookup failed, falling back to DB", "error", err)
		}
	}
	return s.getDB().GetToken(token)
}

func (s *Server) createUser(username, passwordHash, salt, role string) error {
	if err := s.getDB().CreateUser(username, passwordHash, salt, role); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		u, err := s.getDB().GetUserByUsername(username)
		if err != nil {
			return err
		}
		e.PutUser(u)
	}
	return nil
}

func (s *Server) deleteUser(id int) error {
	if err := s.getDB().DeleteUser(id); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		e.DeleteUserByID(id)
		e.DeleteTokensByUserID(id)
	}
	return nil
}

func (s *Server) updateUserPassword(id int, passwordHash, salt string) error {
	if err := s.getDB().UpdateUserPassword(id, passwordHash, salt); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		e.DeleteTokensByUserID(id) // db.UpdateUserPassword clears the user's tokens
		if u, err := e.GetUserByID(id); err == nil {
			u2 := *u
			u2.PasswordHash = passwordHash
			u2.Salt = salt
			e.PutUser(&u2)
		}
	}
	return nil
}

func (s *Server) updateUserOperatorCert(id int, pem string) error {
	if err := s.getDB().UpdateUserOperatorCert(id, pem); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		if u, err := e.GetUserByID(id); err == nil {
			u2 := *u
			u2.OperatorCertPEM = pem
			e.PutUser(&u2)
		}
	}
	return nil
}

func (s *Server) createAPIToken(userID int, description, expiresAt string) (*db.RBACToken, error) {
	tok, err := s.getDB().CreateAPIToken(userID, description, expiresAt)
	if err != nil {
		return nil, err
	}
	if e := s.getEngine(); e != nil {
		e.PutTokenHash(db.TokenHashRow{
			ID:        tok.ID,
			TokenHash: db.TokenHash(tok.Token),
			UserID:    tok.UserID,
			ExpiresAt: tok.ExpiresAt,
		})
	}
	return tok, nil
}

func (s *Server) deleteTokenByHash(hash string) error {
	if err := s.getDB().DeleteTokenByHash(hash); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		e.DeleteTokenByHash(hash)
	}
	return nil
}

func (s *Server) deleteTokenByID(id int) error {
	if err := s.getDB().DeleteToken(id); err != nil {
		return err
	}
	if e := s.getEngine(); e != nil {
		e.DeleteTokenByID(id)
	}
	return nil
}