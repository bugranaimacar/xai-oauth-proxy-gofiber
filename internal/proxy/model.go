package proxy

import (
	"encoding/json"
	"strings"
)

func rewriteModel(body []byte, modelMap map[string]string) ([]byte, bool) {
	if len(body) == 0 || len(modelMap) == 0 {
		return body, false
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, false
	}

	modelRaw, ok := payload["model"]
	if !ok {
		return body, false
	}

	var model string
	if err := json.Unmarshal(modelRaw, &model); err != nil {
		return body, false
	}

	target, ok := modelMap[model]
	if !ok {
		return body, false
	}

	payload["model"], _ = json.Marshal(target)
	rewritten, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return rewritten, true
}

func shouldRewriteModel(path string, contentType string) bool {
	if !strings.Contains(contentType, "application/json") {
		return false
	}
	return strings.HasSuffix(path, "/chat/completions") ||
		strings.HasSuffix(path, "/completions") ||
		strings.HasSuffix(path, "/responses")
}
