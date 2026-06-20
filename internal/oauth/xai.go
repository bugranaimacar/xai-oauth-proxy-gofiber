package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/context"
)

const (
	DefaultClientID        = "b1a00492-073a-47ea-816f-4c329264a828"
	DefaultAuthorizeURL    = "https://auth.x.ai/oauth2/authorize"
	DefaultTokenURL        = "https://auth.x.ai/oauth2/token"
	DefaultDeviceAuthURL   = "https://auth.x.ai/oauth2/device/code"
	DefaultRedirectURI     = "http://127.0.0.1:56121/callback"
	DefaultScope           = "openid profile email offline_access grok-cli:access api:access"
	RefreshSkew            = 2 * time.Minute
	DeviceDefaultInterval  = 5 * time.Second
	DeviceMinInterval      = 1 * time.Second
	DeviceSlowDownIncrement = 5 * time.Second
	DeviceDefaultExpires   = 5 * time.Minute
	PollingSafetyMargin    = 3 * time.Second
	DeviceCodeGrantType    = "urn:ietf:params:oauth:grant-type:device_code"
	CallbackTimeout        = 5 * time.Minute
)

var (
	CORSAllowedOrigins = map[string]struct{}{
		"https://accounts.x.ai": {},
		"https://auth.x.ai":     {},
	}
)

type PKCE struct {
	Verifier  string
	Challenge string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (tr TokenResponse) ExpiresAt() time.Time {
	if tr.ExpiresIn <= 0 {
		return time.Now().Add(time.Hour)
	}
	return time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

type DeviceTokenError struct {
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (e *DeviceTokenError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorType, e.ErrorDescription)
	}
	return e.ErrorType
}

type Client struct {
	ClientID      string
	AuthorizeURL  string
	TokenURL      string
	DeviceAuthURL string
	RedirectURI   string
	Scope         string
	UserAgent     string
	HTTPClient    *http.Client
}

func NewClient(clientID, authorizeURL, tokenURL, deviceAuthURL, redirectURI, scope, userAgent string) *Client {
	if clientID == "" {
		clientID = DefaultClientID
	}
	if authorizeURL == "" {
		authorizeURL = DefaultAuthorizeURL
	}
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if deviceAuthURL == "" {
		deviceAuthURL = DefaultDeviceAuthURL
	}
	if redirectURI == "" {
		redirectURI = DefaultRedirectURI
	}
	if scope == "" {
		scope = DefaultScope
	}
	return &Client{
		ClientID:      clientID,
		AuthorizeURL:  authorizeURL,
		TokenURL:      tokenURL,
		DeviceAuthURL: deviceAuthURL,
		RedirectURI:   redirectURI,
		Scope:         scope,
		UserAgent:     userAgent,
		HTTPClient:    http.DefaultClient,
	}
}

func (c *Client) authHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Accept", "application/json")
	if c.UserAgent != "" {
		h.Set("User-Agent", c.UserAgent)
	}
	return h
}

func GenerateRandomString(length int) (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b), nil
}

func GeneratePKCE() (*PKCE, error) {
	verifier, err := GenerateRandomString(64)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return &PKCE{Verifier: verifier, Challenge: challenge}, nil
}

func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func EscapeHTML(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
	)
	return replacer.Replace(value)
}

func (c *Client) BuildAuthorizeURL(pkce *PKCE, state, nonce string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.ClientID)
	params.Set("redirect_uri", c.RedirectURI)
	params.Set("scope", c.Scope)
	params.Set("code_challenge", pkce.Challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("plan", "generic")
	params.Set("referrer", "grok-oauth-proxy")
	return c.AuthorizeURL + "?" + params.Encode()
}

func (c *Client) ExchangeCodeForTokens(code string, pkce *PKCE) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.RedirectURI)
	data.Set("client_id", c.ClientID)
	data.Set("code_verifier", pkce.Verifier)

	req, err := http.NewRequest(http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.authHeaders()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xAI token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

func (c *Client) RefreshAccessToken(refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.ClientID)

	req, err := http.NewRequest(http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.authHeaders()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xAI token refresh failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

func (c *Client) RequestDeviceCode() (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", c.ClientID)
	data.Set("scope", c.Scope)

	req, err := http.NewRequest(http.MethodPost, c.DeviceAuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.authHeaders()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xAI device code request failed (%d): %s", resp.StatusCode, string(body))
	}

	var device DeviceCodeResponse
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, err
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" {
		return nil, errors.New("xAI device code response is missing device_code / user_code / verification_uri")
	}
	return &device, nil
}

func positiveSecondsToMs(value int, defaultMs time.Duration) time.Duration {
	if value > 0 {
		return time.Duration(value) * time.Second
	}
	return defaultMs
}

func (c *Client) PollDeviceCodeToken(device *DeviceCodeResponse) (*TokenResponse, error) {
	expiresInMs := positiveSecondsToMs(device.ExpiresIn, DeviceDefaultExpires)
	deadline := time.Now().Add(expiresInMs)
	intervalMs := positiveSecondsToMs(device.Interval, DeviceDefaultInterval)
	if intervalMs < DeviceMinInterval {
		intervalMs = DeviceMinInterval
	}

	for time.Now().Before(deadline) {
		data := url.Values{}
		data.Set("grant_type", DeviceCodeGrantType)
		data.Set("client_id", c.ClientID)
		data.Set("device_code", device.DeviceCode)

		req, err := http.NewRequest(http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header = c.authHeaders()

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			var tokens TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
				resp.Body.Close()
				return nil, err
			}
			resp.Body.Close()
			return &tokens, nil
		}

		var errBody DeviceTokenError
		decodeErr := json.NewDecoder(resp.Body).Decode(&errBody)
		resp.Body.Close()
		if decodeErr != nil {
			errBody.ErrorType = "unknown"
			errBody.ErrorDescription = resp.Status
		}

		remaining := time.Until(deadline)
		switch errBody.ErrorType {
		case "authorization_pending":
			sleep := min(intervalMs+PollingSafetyMargin, remaining)
			time.Sleep(sleep)
			continue
		case "slow_down":
			intervalMs += DeviceSlowDownIncrement
			sleep := min(intervalMs+PollingSafetyMargin, remaining)
			time.Sleep(sleep)
			continue
		case "access_denied", "authorization_denied":
			return nil, errors.New("xAI device authorization was denied")
		case "expired_token":
			return nil, errors.New("xAI device code expired - please re-run login")
		default:
			return nil, fmt.Errorf("xAI device token exchange failed (%d): %w", resp.StatusCode, &errBody)
		}
	}

	return nil, errors.New("xAI device authorization timed out")
}

func AccessTokenIsExpiring(token string, skew time.Duration) bool {
	if token == "" {
		return false
	}
	parsed, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	return time.Unix(int64(exp), 0).Before(time.Now().Add(skew))
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

type CallbackServer struct {
	server     *http.Server
	pending    *pendingOAuth
	mu         sync.Mutex
	redirectURI string
}

type pendingOAuth struct {
	pkce   *PKCE
	state  string
	result chan callbackResult
}

type callbackResult struct {
	tokens *TokenResponse
	err    error
}

func NewCallbackServer() *CallbackServer {
	return &CallbackServer{}
}

func (cs *CallbackServer) Start() (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.server != nil {
		return DefaultRedirectURI, nil
	}

	u, err := url.Parse(DefaultRedirectURI)
	if err != nil {
		return "", err
	}

	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, cs.handleCallback)
	mux.HandleFunc("/cancel", cs.handleCancel)

	cs.server = &http.Server{
		Addr:    u.Host,
		Handler: mux,
	}
	cs.redirectURI = DefaultRedirectURI

	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		cs.server = nil
		return "", err
	}

	go func() {
		if err := cs.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// log-only: accept-time failures should not crash the process
		}
	}()

	return cs.redirectURI, nil
}

func (cs *CallbackServer) Stop() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cs.server.Shutdown(ctx)
	cs.server = nil
	return err
}

func (cs *CallbackServer) WaitForCallback(pkce *PKCE, state string) (*TokenResponse, error) {
	cs.mu.Lock()
	if cs.pending != nil {
		cs.pending.result <- callbackResult{err: errors.New("superseded by a newer xAI authorize request")}
	}
	pending := &pendingOAuth{
		pkce:   pkce,
		state:  state,
		result: make(chan callbackResult, 1),
	}
	cs.pending = pending
	cs.mu.Unlock()

	timer := time.NewTimer(CallbackTimeout)
	defer timer.Stop()

	select {
	case res := <-pending.result:
		cs.mu.Lock()
		if cs.pending == pending {
			cs.pending = nil
		}
		cs.mu.Unlock()
		return res.tokens, res.err
	case <-timer.C:
		cs.mu.Lock()
		if cs.pending == pending {
			cs.pending = nil
		}
		cs.mu.Unlock()
		return nil, errors.New("OAuth callback timeout - authorization took too long")
	}
}

func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if _, ok := CORSAllowedOrigins[origin]; ok {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Vary", "Origin")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	authError := q.Get("error")
	errorDescription := q.Get("error_description")

	if authError != "" {
		msg := errorDescription
		if msg == "" {
			msg = authError
		}
		cs.fail(w, msg)
		return
	}

	if code == "" {
		cs.fail(w, "Missing authorization code")
		return
	}

	cs.mu.Lock()
	pending := cs.pending
	if pending == nil || pending.state != state {
		cs.mu.Unlock()
		cs.fail(w, "Invalid state - potential CSRF attack")
		return
	}
	cs.pending = nil
	cs.mu.Unlock()

	go func() {
		tokens, err := cs.client().ExchangeCodeForTokens(code, pending.pkce)
		pending.result <- callbackResult{tokens: tokens, err: err}
	}()

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(HTMLSuccess))
}

func (cs *CallbackServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	cs.mu.Lock()
	pending := cs.pending
	if pending != nil {
		cs.pending = nil
		pending.result <- callbackResult{err: errors.New("Login cancelled")}
	}
	cs.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Login cancelled"))
}

func (cs *CallbackServer) fail(w http.ResponseWriter, msg string) {
	cs.mu.Lock()
	pending := cs.pending
	if pending != nil {
		cs.pending = nil
		pending.result <- callbackResult{err: errors.New(msg)}
	}
	cs.mu.Unlock()

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(fmt.Sprintf(HTMLError, EscapeHTML(msg))))
}

func (cs *CallbackServer) client() *Client {
	return NewClient("", "", "", "", "", "", "")
}

const HTMLSuccess = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>xAI Authorization Successful</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #131010; color: #f1ecec; }
.container { text-align: center; padding: 2rem; }
h1 { color: #f1ecec; margin-bottom: 1rem; }
p { color: #b7b1b1; }
</style>
</head>
<body>
<div class="container">
<h1>Authorization Successful</h1>
<p>You can close this window and return to the proxy.</p>
</div>
<script>setTimeout(() => window.close(), 2000)</script>
</body>
</html>`

const HTMLError = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>xAI Authorization Failed</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #131010; color: #f1ecec; }
.container { text-align: center; padding: 2rem; }
h1 { color: #fc533a; margin-bottom: 1rem; }
p { color: #b7b1b1; }
.error { color: #ff917b; font-family: monospace; margin-top: 1rem; padding: 1rem; background: #3c140d; border-radius: 0.5rem; }
</style>
</head>
<body>
<div class="container">
<h1>Authorization Failed</h1>
<p>An error occurred during authorization.</p>
<div class="error">%s</div>
</div>
</body>
</html>`
