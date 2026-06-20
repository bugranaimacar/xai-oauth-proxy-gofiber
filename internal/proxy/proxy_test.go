package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"encoding/json"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"grok-oauth-api/internal/config"
	"grok-oauth-api/internal/oauth"
	"grok-oauth-api/internal/store"
)

func TestProxyForwardsRequest(t *testing.T) {
	accessToken := makeJWT(time.Now().Add(time.Hour))
	refreshCalled := false

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				t.Errorf("missing bearer token in upstream request")
			}
			if auth != "Bearer "+accessToken {
				t.Errorf("upstream got wrong token: %s", auth)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"resp"}`))
			return
		}
		if r.URL.Path == "/oauth2/token" {
			refreshCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oauth.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: "refresh2",
				ExpiresIn:    3600,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Port:          "8080",
		ProxyAPIKey:   "proxy-key",
		XAIAPIBase:    upstream.URL,
		XAITokenURL:   upstream.URL + "/oauth2/token",
		XAIClientID:   "client",
		UserAgent:     "test",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	oauthClient := oauth.NewClient(cfg.XAIClientID, "", cfg.XAITokenURL, "", "", "", "")
	s := store.New(path, oauthClient)
	_ = s.Save(store.TokenData{
		AccessToken:  makeJWT(time.Now().Add(-time.Hour)),
		RefreshToken: "refresh1",
		ExpiresAt:    time.Now().Add(-time.Hour),
	})

	app := fiber.New()
	app.All("/v1/*", New(cfg, s))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"grok"}`))
	req.Header.Set("Authorization", "Bearer proxy-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"id":"resp"`) {
		t.Errorf("unexpected body: %s", body)
	}
	if !refreshCalled {
		t.Error("refresh endpoint was not called")
	}
}

func TestProxyStreamsResponse(t *testing.T) {
	accessToken := makeJWT(time.Now().Add(time.Hour))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"chunk\":1}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ProxyAPIKey: "proxy-key",
		XAIAPIBase:  upstream.URL,
		UserAgent:   "test",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	oauthClient := oauth.NewClient("client", "", "", "", "", "", "")
	s := store.New(path, oauthClient)
	_ = s.Save(store.TokenData{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	app := fiber.New()
	app.All("/v1/*", New(cfg, s))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"grok","stream":true}`))
	req.Header.Set("Authorization", "Bearer proxy-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `data: {"chunk":1}`) {
		t.Errorf("unexpected stream body: %s", body)
	}
}

func TestProxyRejectsInvalidKey(t *testing.T) {
	cfg := &config.Config{
		Port:        "8080",
		ProxyAPIKey: "proxy-key",
		XAIAPIBase:  "http://localhost",
	}

	app := fiber.New()
	app.All("/v1/*", New(cfg, nil))

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func makeJWT(exp time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"exp": exp.Unix()})
	s, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	return s
}
