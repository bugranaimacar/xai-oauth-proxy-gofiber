package proxy

import (
	"strings"
	"testing"
)

func TestRewriteModel(t *testing.T) {
	modelMap := map[string]string{
		"composer-bugra": "composer-2.5",
	}

	body := []byte(`{"model":"composer-bugra","messages":[{"role":"user","content":"hi"}]}`)
	rewritten, ok := rewriteModel(body, modelMap)
	if !ok {
		t.Fatal("expected model rewrite")
	}
	if !strings.Contains(string(rewritten), `"model":"composer-2.5"`) {
		t.Fatalf("unexpected body: %s", rewritten)
	}
}

func TestRewriteModelNoMatch(t *testing.T) {
	modelMap := map[string]string{
		"composer-bugra": "composer-2.5",
	}

	body := []byte(`{"model":"grok-3-latest","messages":[]}`)
	rewritten, ok := rewriteModel(body, modelMap)
	if ok {
		t.Fatalf("expected no rewrite, got %s", rewritten)
	}
}

func TestShouldRewriteModel(t *testing.T) {
	if !shouldRewriteModel("/v1/chat/completions", "application/json") {
		t.Error("expected chat completions path to rewrite")
	}
	if shouldRewriteModel("/v1/models", "application/json") {
		t.Error("expected models path to skip rewrite")
	}
}

func TestInjectModelAliases(t *testing.T) {
	body := []byte(`{"object":"list","data":[{"id":"composer-2.5","object":"model"}]}`)
	rewritten, err := injectModelAliases(body, map[string]string{
		"composer-bugra": "composer-2.5",
	})
	if err != nil {
		t.Fatalf("injectModelAliases failed: %v", err)
	}
	if !strings.Contains(string(rewritten), `"id":"composer-bugra"`) {
		t.Fatalf("alias not injected: %s", rewritten)
	}
}
