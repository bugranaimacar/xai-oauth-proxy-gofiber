package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	urlpkg "net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGeneratePKCE(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}
	if len(pkce.Verifier) != 64 {
		t.Errorf("verifier length = %d, want 64", len(pkce.Verifier))
	}
	hash := sha256.Sum256([]byte(pkce.Verifier))
	want := base64.RawURLEncoding.EncodeToString(hash[:])
	if pkce.Challenge != want {
		t.Errorf("challenge mismatch: got %s, want %s", pkce.Challenge, want)
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	c := NewClient("client-id", "https://auth.x.ai/oauth2/authorize", "", "", DefaultRedirectURI, DefaultScope, "")
	pkce, _ := GeneratePKCE()
	state := "state"
	nonce := "nonce"
	url := c.BuildAuthorizeURL(pkce, state, nonce)

	required := []string{
		"response_type=code",
		"client_id=client-id",
		"redirect_uri=" + urlpkg.QueryEscape(DefaultRedirectURI),
		"code_challenge=" + pkce.Challenge,
		"code_challenge_method=S256",
		"state=state",
		"nonce=nonce",
		"plan=generic",
		"referrer=grok-oauth-proxy",
	}
	for _, want := range required {
		if !strings.Contains(url, want) {
			t.Errorf("authorize URL missing %q", want)
		}
	}
}

func TestEscapeHTML(t *testing.T) {
	got := EscapeHTML(`<script>alert("xss")</script>`)
	want := `&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;`
	if got != want {
		t.Errorf("EscapeHTML = %q, want %q", got, want)
	}
}

func TestAccessTokenIsExpiring(t *testing.T) {
	now := time.Now()
	expSoon := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"exp": now.Add(30 * time.Second).Unix(),
	})
	tokenSoon, _ := expSoon.SignedString(jwt.UnsafeAllowNoneSignatureType)

	expLater := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"exp": now.Add(time.Hour).Unix(),
	})
	tokenLater, _ := expLater.SignedString(jwt.UnsafeAllowNoneSignatureType)

	if !AccessTokenIsExpiring(tokenSoon, time.Minute) {
		t.Error("expected token expiring soon to need refresh")
	}
	if AccessTokenIsExpiring(tokenLater, time.Minute) {
		t.Error("expected token expiring later to not need refresh")
	}
	if AccessTokenIsExpiring("not-a-jwt", time.Minute) {
		t.Error("expected non-JWT token to not report expiring")
	}
}

func TestPositiveSecondsToMs(t *testing.T) {
	if positiveSecondsToMs(0, DeviceDefaultInterval) != DeviceDefaultInterval {
		t.Error("zero should fall back to default")
	}
	if positiveSecondsToMs(-5, DeviceDefaultInterval) != DeviceDefaultInterval {
		t.Error("negative should fall back to default")
	}
	if positiveSecondsToMs(10, DeviceDefaultInterval) != 10*time.Second {
		t.Error("positive value should be converted")
	}
}
