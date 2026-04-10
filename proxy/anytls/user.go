package anytls

import (
	"context"
	"crypto/sha256"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if u == nil || u.Account == nil {
		return errors.New("anytls: invalid user")
	}
	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("anytls: invalid account type")
	}

	sum := sha256.Sum256([]byte(acc.Password))

	s.userMu.Lock()
	defer s.userMu.Unlock()

	if prev, ok := s.usersByEmail[u.Email]; ok {
		prevAcc, ok := prev.Account.(*MemoryAccount)
		if ok {
			prevSum := sha256.Sum256([]byte(prevAcc.Password))
			if prevSum != sum {
				delete(s.users, prevSum)
			}
		}
	}
	s.users[sum] = u
	s.usersByEmail[u.Email] = u
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("anytls: empty email")
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()

	if user, ok := s.usersByEmail[email]; ok {
		delete(s.usersByEmail, email)
		acc, ok := user.Account.(*MemoryAccount)
		if ok {
			sum := sha256.Sum256([]byte(acc.Password))
			delete(s.users, sum)
		}
	}
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	s.userMu.RLock()
	defer s.userMu.RUnlock()

	return s.usersByEmail[email]
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	s.userMu.RLock()
	defer s.userMu.RUnlock()

	users := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	s.userMu.RLock()
	defer s.userMu.RUnlock()

	return int64(len(s.users))
}
