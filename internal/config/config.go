package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	DefaultClientID      = "b1a00492-073a-47ea-816f-4c329264a828"
	DefaultAuthorizeURL  = "https://auth.x.ai/oauth2/authorize"
	DefaultTokenURL      = "https://auth.x.ai/oauth2/token"
	DefaultDeviceAuthURL = "https://auth.x.ai/oauth2/device/code"
	DefaultAPIBase       = "https://api.x.ai"
	DefaultRedirectURI   = "http://127.0.0.1:56121/callback"
	DefaultScope         = "openid profile email offline_access grok-cli:access api:access"
	DefaultTokenPath     = "./auth.json"
	DefaultPort          = "8080"
	DefaultUserAgent     = "grok-oauth-proxy/0.1.0"
	RefreshSkew          = 2 * time.Minute
)

type Config struct {
	Port          string
	ProxyAPIKey   string
	XAIClientID   string
	XAIAuthorize  string
	XAITokenURL   string
	XAIDeviceURL  string
	XAIAPIBase    string
	XAIRedirectURI string
	XAIScope      string
	TokenPath     string
	UserAgent     string
}

func Load() (*Config, error) {
	apiKey := os.Getenv("PROXY_API_KEY")
	if apiKey == "" {
		apiKey = "local-dev-key"
	}

	cfg := &Config{
		Port:           getEnv("PORT", DefaultPort),
		ProxyAPIKey:    apiKey,
		XAIClientID:    getEnv("XAI_CLIENT_ID", DefaultClientID),
		XAIAuthorize:   getEnv("XAI_AUTHORIZE_URL", DefaultAuthorizeURL),
		XAITokenURL:    getEnv("XAI_TOKEN_URL", DefaultTokenURL),
		XAIDeviceURL:   getEnv("XAI_DEVICE_URL", DefaultDeviceAuthURL),
		XAIAPIBase:     getEnv("XAI_API_BASE", DefaultAPIBase),
		XAIRedirectURI: getEnv("XAI_REDIRECT_URI", DefaultRedirectURI),
		XAIScope:       getEnv("XAI_SCOPE", DefaultScope),
		TokenPath:      getEnv("TOKEN_PATH", DefaultTokenPath),
		UserAgent:      getEnv("USER_AGENT", DefaultUserAgent),
	}

	if _, err := strconv.Atoi(cfg.Port); err != nil {
		return nil, fmt.Errorf("invalid PORT %q: %w", cfg.Port, err)
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
