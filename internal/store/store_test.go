package store

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"grok-oauth-api/internal/oauth"
)

func TestStoreLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")

	oauthClient := oauth.NewClient("", "", "", "", "", "", "")
	s := New(path, oauthClient)

	data := TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := s.Save(data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	s2 := New(path, oauthClient)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	got := s2.Get()
	if got.AccessToken != data.AccessToken || got.RefreshToken != data.RefreshToken {
		t.Errorf("loaded data mismatch: got %+v", got)
	}
}

func TestEnsureValidSingleFlight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")

	refreshCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		refreshCount++
		mu.Unlock()
		json.NewEncoder(w).Encode(oauth.TokenResponse{
			AccessToken:  "new-access",
			RefreshToken: "new-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	oauthClient := oauth.NewClient("", "", server.URL, server.URL, "", "", "")
	s := New(path, oauthClient)
	_ = s.Save(TokenData{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour),
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.EnsureValid()
		}()
	}
	wg.Wait()

	mu.Lock()
	if refreshCount != 1 {
		t.Errorf("refresh called %d times, want 1", refreshCount)
	}
	mu.Unlock()

	got := s.Get()
	if got.AccessToken != "new-access" {
		t.Errorf("access token = %q, want new-access", got.AccessToken)
	}
}

func TestEnsureValidNoRefreshToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")

	oauthClient := oauth.NewClient("", "", "", "", "", "", "")
	s := New(path, oauthClient)

	_, err := s.EnsureValid()
	if err != ErrNoRefreshToken {
		t.Errorf("expected ErrNoRefreshToken, got %v", err)
	}
}

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		expires  time.Time
		skew     time.Duration
		expected bool
	}{
		{"fresh", time.Now().Add(time.Hour), time.Minute, false},
		{"within skew", time.Now().Add(30 * time.Second), time.Minute, true},
		{"expired", time.Now().Add(-time.Hour), time.Minute, true},
		{"zero", time.Time{}, time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := TokenData{ExpiresAt: tt.expires}
			if got := d.IsExpired(tt.skew); got != tt.expected {
				t.Errorf("IsExpired = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	oauthClient := oauth.NewClient("", "", "", "", "", "", "")
	s := New(path, oauthClient)
	if err := s.Load(); err != nil {
		t.Errorf("Load on missing file should not error, got %v", err)
	}
}

func TestSavePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")

	oauthClient := oauth.NewClient("", "", "", "", "", "", "")
	s := New(path, oauthClient)
	_ = s.Save(TokenData{AccessToken: "secret"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("auth.json is world/group readable: %o", info.Mode().Perm())
	}
}
