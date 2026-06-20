package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"grok-oauth-api/internal/oauth"
)

const oauthSessionTTL = 15 * time.Minute

type oauthSession struct {
	SessionID  string
	DeviceCode string
	UserCode   string
	PKCE       *oauth.PKCE
	State      string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func normalizeUserCode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.ToUpper(code)
}

func (s *Server) putOAuthSession(sess *oauthSession) {
	s.oauthSessions.Store(sess.SessionID, sess)
	if sess.UserCode != "" {
		s.userCodeIndex.Store(normalizeUserCode(sess.UserCode), sess.SessionID)
	}
}

func (s *Server) getOAuthSession(sessionID string) (*oauthSession, bool) {
	v, ok := s.oauthSessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	sess := v.(*oauthSession)
	if time.Now().After(sess.ExpiresAt) {
		s.deleteOAuthSession(sess)
		return nil, false
	}
	return sess, true
}

func (s *Server) getOAuthSessionByUserCode(userCode string) (*oauthSession, bool) {
	id, ok := s.userCodeIndex.Load(normalizeUserCode(userCode))
	if !ok {
		return nil, false
	}
	return s.getOAuthSession(id.(string))
}

func (s *Server) deleteOAuthSession(sess *oauthSession) {
	s.oauthSessions.Delete(sess.SessionID)
	if sess.UserCode != "" {
		s.userCodeIndex.Delete(normalizeUserCode(sess.UserCode))
	}
}

func parseOAuthCallbackURL(raw string) (code, state string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("callback_url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	code = strings.TrimSpace(q.Get("code"))
	state = strings.TrimSpace(q.Get("state"))
	if errParam := q.Get("error"); errParam != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = errParam
		}
		return "", "", errors.New(desc)
	}
	if code == "" {
		return "", "", errors.New("callback_url is missing code query parameter")
	}
	return code, state, nil
}

type remoteCompleteRequest struct {
	SessionID   string `json:"session_id"`
	UserCode    string `json:"user_code"`
	CallbackURL string `json:"callback_url"`
	Code        string `json:"code"`
	State       string `json:"state"`
}

func (s *Server) oauthRemoteStart(c fiber.Ctx) error {
	device, err := s.oauthClient.RequestDeviceCode()
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	sessionID, err := newSessionID()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	expiresIn := device.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int(oauth.DeviceDefaultExpires / time.Second)
	}

	sess := &oauthSession{
		SessionID:  sessionID,
		DeviceCode: device.DeviceCode,
		UserCode:   device.UserCode,
		ExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		CreatedAt:  time.Now(),
	}
	s.putOAuthSession(sess)

	return c.JSON(fiber.Map{
		"session_id":                sessionID,
		"user_code":                 device.UserCode,
		"device_code":               device.DeviceCode,
		"verification_uri":          device.VerificationURI,
		"verification_uri_complete": device.VerificationURIComplete,
		"expires_in":                expiresIn,
		"interval":                  device.Interval,
		"instructions": []string{
			"Open verification_uri in a browser and sign in to xAI.",
			"Copy the code shown (Enter this code to finish signing in) into user_code.",
			"POST /oauth/remote/complete with JSON {\"session_id\":\"...\",\"user_code\":\"...\"} or {\"user_code\":\"...\"} only.",
		},
	})
}

func (s *Server) oauthRemoteComplete(c fiber.Ctx) error {
	var req remoteCompleteRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Device flow: user pasted the Grok Build / device user code.
	if strings.TrimSpace(req.UserCode) != "" {
		return s.completeDeviceUserCode(c, req)
	}

	// Authorization code flow: user pasted redirect URL or code+state from browser.
	return s.completeAuthorizationCode(c, req)
}

func (s *Server) completeDeviceUserCode(c fiber.Ctx, req remoteCompleteRequest) error {
	var sess *oauthSession
	var ok bool

	if strings.TrimSpace(req.SessionID) != "" {
		sess, ok = s.getOAuthSession(req.SessionID)
		if !ok {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "unknown or expired session_id — call POST /oauth/remote again",
			})
		}
		normalized := normalizeUserCode(req.UserCode)
		if normalizeUserCode(sess.UserCode) != normalized {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "user_code does not match this session",
			})
		}
	} else {
		sess, ok = s.getOAuthSessionByUserCode(req.UserCode)
		if !ok {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error": "no active session for this user_code — call POST /oauth/remote first",
			})
		}
	}

	device := &oauth.DeviceCodeResponse{
		DeviceCode: sess.DeviceCode,
		ExpiresIn:  int(time.Until(sess.ExpiresAt).Seconds()),
	}
	tokens, err := s.oauthClient.PollDeviceCodeToken(device)
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.tokenStore.SetTokens(tokens); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	s.deleteOAuthSession(sess)

	return c.JSON(fiber.Map{
		"status":     "connected",
		"token_path": s.cfg.TokenPath,
		"message":    "OAuth completed; tokens saved",
	})
}

func (s *Server) completeAuthorizationCode(c fiber.Ctx, req remoteCompleteRequest) error {
	code := strings.TrimSpace(req.Code)
	state := strings.TrimSpace(req.State)

	if req.CallbackURL != "" {
		var err error
		code, state, err = parseOAuthCallbackURL(req.CallbackURL)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	if code == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "provide user_code (device flow), or callback_url, or code+state+session_id (browser flow)",
		})
	}

	if strings.TrimSpace(req.SessionID) == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "session_id is required when submitting callback_url or code (from GET /oauth/start)",
		})
	}

	sess, ok := s.getOAuthSession(req.SessionID)
	if !ok {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "unknown or expired session_id — call GET /oauth/start again",
		})
	}
	if sess.PKCE == nil || sess.State == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "session is not a browser OAuth session — use /oauth/remote for device codes",
		})
	}
	if state != "" && state != sess.State {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "state does not match session"})
	}

	tokens, err := s.oauthClient.ExchangeCodeForTokens(code, sess.PKCE)
	if err != nil {
		return c.Status(http.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	if err := s.tokenStore.SetTokens(tokens); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	s.deleteOAuthSession(sess)

	return c.JSON(fiber.Map{
		"status":     "connected",
		"token_path": s.cfg.TokenPath,
		"message":    "OAuth completed; tokens saved",
	})
}

// oauthComplete is an alias for remote complete (manual callback URL / user code).
func (s *Server) oauthComplete(c fiber.Ctx) error {
	return s.oauthRemoteComplete(c)
}