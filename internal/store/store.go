package store

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"grok-oauth-api/internal/oauth"
)

var (
	ErrNoRefreshToken = errors.New("no refresh token available")
	ErrNoAccessToken  = errors.New("no access token available")
)

type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (t *TokenData) IsExpired(skew time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return true
	}
	return time.Until(t.ExpiresAt) <= skew
}

type Store struct {
	path    string
	mu      sync.RWMutex
	data    TokenData
	group   singleflight.Group
	oauth   *oauth.Client
}

func New(path string, oauthClient *oauth.Client) *Store {
	return &Store{
		path:  path,
		oauth: oauthClient,
	}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var data TokenData
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	s.data = data
	return nil
}

func (s *Store) Save(data TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data = data
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0600)
}

func (s *Store) Get() TokenData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Store) SetAccessToken(access string, expiresAt time.Time) error {
	return s.Save(TokenData{
		AccessToken: access,
		ExpiresAt:   expiresAt,
	})
}

func (s *Store) SetTokens(tokens *oauth.TokenResponse) error {
	return s.Save(TokenData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt(),
	})
}

func (s *Store) EnsureValid() (string, error) {
	data := s.Get()

	needsRefresh := data.AccessToken == "" ||
		data.IsExpired(oauth.RefreshSkew) ||
		oauth.AccessTokenIsExpiring(data.AccessToken, oauth.RefreshSkew)

	if !needsRefresh {
		return data.AccessToken, nil
	}

	result, err, _ := s.group.Do("refresh", func() (interface{}, error) {
		current := s.Get()
		if current.RefreshToken == "" {
			return "", ErrNoRefreshToken
		}

		tokens, err := s.oauth.RefreshAccessToken(current.RefreshToken)
		if err != nil {
			return "", err
		}

		refreshToken := tokens.RefreshToken
		if refreshToken == "" {
			refreshToken = current.RefreshToken
		}

		newData := TokenData{
			AccessToken:  tokens.AccessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    tokens.ExpiresAt(),
		}
		if saveErr := s.Save(newData); saveErr != nil {
			// best-effort persistence; in-memory token is still valid this turn
		}
		return tokens.AccessToken, nil
	})

	if err != nil {
		return "", err
	}
	return result.(string), nil
}
