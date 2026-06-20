package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"grok-oauth-api/internal/config"
	"grok-oauth-api/internal/store"
)

func New(cfg *config.Config, tokenStore *store.Store) fiber.Handler {
	upstream, err := url.Parse(cfg.XAIAPIBase)
	if err != nil {
		panic(fmt.Sprintf("invalid XAI_API_BASE: %v", err))
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid proxy API key"})
		}
		key := strings.TrimPrefix(authHeader, "Bearer ")
		if key != cfg.ProxyAPIKey {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid proxy API key"})
		}

		accessToken, err := tokenStore.EnsureValid()
		if err != nil {
			return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
				"error":  "failed to ensure valid xAI access token",
				"detail": err.Error(),
			})
		}

		targetURL := upstream.JoinPath(c.Path())
		if c.Request().URI().QueryString() != nil {
			targetURL.RawQuery = string(c.Request().URI().QueryString())
		}

		body := c.Request().Body()
		req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL.String(), io.NopCloser(strings.NewReader(string(body))))
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		c.Request().Header.VisitAll(func(key, value []byte) {
			k := string(key)
			if strings.EqualFold(k, "host") || strings.EqualFold(k, "authorization") {
				return
			}
			req.Header.Add(k, string(value))
		})

		req.Header.Set("Authorization", "Bearer "+accessToken)
		if cfg.UserAgent != "" {
			req.Header.Set("User-Agent", cfg.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}
		defer resp.Body.Close()

		c.Status(resp.StatusCode)
		for k, vv := range resp.Header {
			for _, v := range vv {
				c.Set(k, v)
			}
		}

		_, err = io.Copy(c.Response().BodyWriter(), resp.Body)
		return err
	}
}
