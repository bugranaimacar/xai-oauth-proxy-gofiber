package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"grok-oauth-api/internal/config"
	"grok-oauth-api/internal/oauth"
	"grok-oauth-api/internal/proxy"
	"grok-oauth-api/internal/store"
)

type Server struct {
	app           *fiber.App
	cfg           *config.Config
	oauthClient   *oauth.Client
	tokenStore    *store.Store
	callbackServer *oauth.CallbackServer
}

func New(cfg *config.Config) *Server {
	oauthClient := oauth.NewClient(
		cfg.XAIClientID,
		cfg.XAIAuthorize,
		cfg.XAITokenURL,
		cfg.XAIDeviceURL,
		cfg.XAIRedirectURI,
		cfg.XAIScope,
		cfg.UserAgent,
	)
	tokenStore := store.New(cfg.TokenPath, oauthClient)
	_ = tokenStore.Load()

	app := fiber.New()

	s := &Server{
		app:            app,
		cfg:            cfg,
		oauthClient:    oauthClient,
		tokenStore:     tokenStore,
		callbackServer: oauth.NewCallbackServer(),
	}

	app.Get("/health", s.health)
	app.Get("/oauth/start", s.oauthStart)
	app.Get("/oauth/callback", s.oauthCallback)
	app.Post("/oauth/device", s.oauthDeviceStart)
	app.Post("/oauth/device/poll", s.oauthDevicePoll)
	app.All("/v1/*", proxy.New(cfg, tokenStore))

	return s
}

func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

func (s *Server) Shutdown(ctx context.Context) error {
	_ = s.callbackServer.Stop()
	return s.app.ShutdownWithContext(ctx)
}

func (s *Server) health(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok", "provider": "xai"})
}

func (s *Server) oauthStart(c fiber.Ctx) error {
	auto := c.Query("auto") == "true"

	redirectURI, err := s.callbackServer.Start()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	state, err := oauth.GenerateState()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	nonce, err := oauth.GenerateState()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	authURL := s.oauthClient.BuildAuthorizeURL(pkce, state, nonce)

	if auto {
		if err := oauth.OpenBrowser(authURL); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   "failed to open browser",
				"auth_url": authURL,
			})
		}

		tokens, cbErr := s.callbackServer.WaitForCallback(pkce, state)
		if cbErr != nil {
			return c.Status(http.StatusGatewayTimeout).JSON(fiber.Map{"error": cbErr.Error()})
		}
		if err := s.tokenStore.SetTokens(tokens); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		c.Set("Content-Type", "text/html")
		return c.Status(http.StatusOK).SendString(OAuthSuccessHTML)
	}

	go func() {
		tokens, cbErr := s.callbackServer.WaitForCallback(pkce, state)
		if cbErr != nil {
			return
		}
		_ = s.tokenStore.SetTokens(tokens)
	}()

	return c.JSON(fiber.Map{
		"auth_url":     authURL,
		"redirect_uri": redirectURI,
		"state":        state,
	})
}

func (s *Server) oauthCallback(c fiber.Ctx) error {
	// The loopback callback server handles the actual OAuth response internally.
	// This Fiber handler is only reached if the callback is routed through Fiber,
	// which is not the expected flow. Return a hint.
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{
		"error": "callback should be handled by the loopback server on 127.0.0.1:56121",
	})
}

const OAuthSuccessHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xAI Authorization Successful</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
  color: #f1ecec;
}
.card {
  text-align: center;
  padding: 3rem 2.5rem;
  background: rgba(19, 16, 16, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 1.25rem;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  max-width: 420px;
  width: 90%;
  backdrop-filter: blur(8px);
}
.icon {
  width: 72px;
  height: 72px;
  margin: 0 auto 1.5rem;
  background: linear-gradient(135deg, #22c55e, #16a34a);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2.25rem;
}
h1 { font-size: 1.75rem; margin-bottom: 0.75rem; }
p { color: #b7b1b1; line-height: 1.6; margin-bottom: 0.5rem; }
.token-pill {
  display: inline-block;
  margin-top: 1rem;
  padding: 0.5rem 1rem;
  background: rgba(34, 197, 94, 0.12);
  color: #4ade80;
  border-radius: 9999px;
  font-size: 0.875rem;
  font-weight: 500;
}
.footer {
  margin-top: 2rem;
  font-size: 0.75rem;
  color: #6b6b6b;
}
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#10003;</div>
  <h1>Authorization Successful</h1>
  <p>Your xAI Grok account is now connected.</p>
  <p>Tokens have been saved and the proxy is ready to use.</p>
  <div class="token-pill">Connected</div>
  <div class="footer">grok-oauth-proxy</div>
</div>
</body>
</html>`

func (s *Server) oauthDeviceStart(c fiber.Ctx) error {
	device, err := s.oauthClient.RequestDeviceCode()
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(device)
}

type devicePollRequest struct {
	DeviceCode string `json:"device_code"`
}

func (s *Server) oauthDevicePoll(c fiber.Ctx) error {
	var req devicePollRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if req.DeviceCode == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "device_code is required"})
	}

	device := &oauth.DeviceCodeResponse{DeviceCode: req.DeviceCode}
	tokens, err := s.oauthClient.PollDeviceCodeToken(device)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return c.Status(http.StatusRequestTimeout).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.tokenStore.SetTokens(tokens); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	c.Set("Content-Type", "text/html")
	return c.Status(http.StatusOK).SendString(OAuthSuccessHTML)
}
