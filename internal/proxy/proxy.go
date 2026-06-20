package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"grok-oauth-api/internal/config"
	"grok-oauth-api/internal/store"
)

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func New(cfg *config.Config, tokenStore *store.Store) fiber.Handler {
	upstream, err := url.Parse(cfg.XAIAPIBase)
	if err != nil {
		panic(fmt.Sprintf("invalid XAI_API_BASE: %v", err))
	}

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
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
		bodyRewritten := false
		if shouldRewriteModel(c.Path(), c.Get("Content-Type")) {
			if rewritten, ok := rewriteModel(body, cfg.ModelMap); ok {
				body = rewritten
				bodyRewritten = true
			}
		}

		req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL.String(), io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		if bodyRewritten || len(body) > 0 {
			req.ContentLength = int64(len(body))
		}

		c.Request().Header.VisitAll(func(key, value []byte) {
			k := strings.ToLower(string(key))
			switch k {
			case "host", "authorization", "content-length":
				return
			}
			req.Header.Add(string(key), string(value))
		})

		req.Header.Set("Authorization", "Bearer "+accessToken)
		if cfg.UserAgent != "" {
			req.Header.Set("User-Agent", cfg.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}

		if isModelsPath(c.Path()) && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return writeModelsResponse(c, resp, cfg.ModelMap)
		}

		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/event-stream") {
			copyResponseHeaders(c, resp.Header)
			c.Status(resp.StatusCode)
			// SendStream closes the upstream body before fasthttp reads it.
			// Copy inside SendStreamWriter so the body stays open until done.
			return c.SendStreamWriter(func(w *bufio.Writer) {
				defer resp.Body.Close()
				_, _ = io.Copy(w, resp.Body)
			})
		}

		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}

		copyResponseHeaders(c, resp.Header)
		c.Status(resp.StatusCode)
		return c.Send(respBody)
	}
}

func copyResponseHeaders(c fiber.Ctx, headers http.Header) {
	for k, vv := range headers {
		if _, skip := hopByHopHeaders[strings.ToLower(k)]; skip {
			continue
		}
		for _, v := range vv {
			c.Set(k, v)
		}
	}
}

func isModelsPath(path string) bool {
	return strings.HasSuffix(path, "/models")
}

func writeModelsResponse(c fiber.Ctx, resp *http.Response, modelMap map[string]string) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	rewritten, err := injectModelAliases(body, modelMap)
	if err != nil {
		copyResponseHeaders(c, resp.Header)
		c.Status(resp.StatusCode)
		return c.Send(body)
	}

	copyResponseHeaders(c, resp.Header)
	c.Status(resp.StatusCode)
	c.Set("Content-Type", "application/json")
	return c.Send(rewritten)
}

func injectModelAliases(body []byte, modelMap map[string]string) ([]byte, error) {
	if len(modelMap) == 0 {
		return body, nil
	}

	var payload struct {
		Object string           `json:"object"`
		Data   []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, err
	}

	existing := make(map[string]struct{}, len(payload.Data))
	for _, item := range payload.Data {
		if id, ok := item["id"].(string); ok {
			existing[id] = struct{}{}
		}
	}

	for alias := range modelMap {
		if _, ok := existing[alias]; ok {
			continue
		}
		payload.Data = append(payload.Data, map[string]any{
			"id":       alias,
			"object":   "model",
			"owned_by": "grok-oauth-proxy",
		})
	}

	return json.Marshal(payload)
}
