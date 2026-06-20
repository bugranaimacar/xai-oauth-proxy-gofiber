package server

import "testing"

func TestParseOAuthCallbackURL(t *testing.T) {
	code, state, err := parseOAuthCallbackURL("http://127.0.0.1:56121/callback?code=abc123&state=xyz")
	if err != nil {
		t.Fatal(err)
	}
	if code != "abc123" || state != "xyz" {
		t.Fatalf("got code=%q state=%q", code, state)
	}
}

func TestNormalizeUserCode(t *testing.T) {
	if got := normalizeUserCode("ab cd-ef"); got != "ABCDEF" {
		t.Fatalf("got %q", got)
	}
}