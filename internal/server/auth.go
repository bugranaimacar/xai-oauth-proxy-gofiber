package server

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"
	"grok-oauth-api/internal/config"
)

// requireProxyAPIKey ensures OAuth setup endpoints use the same key as /v1/*.
func requireProxyAPIKey(cfg *config.Config) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing or invalid proxy API key",
			})
		}
		key := strings.TrimPrefix(authHeader, "Bearer ")
		if key != cfg.ProxyAPIKey {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid proxy API key",
			})
		}
		return c.Next()
	}
}