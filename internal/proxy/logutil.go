package proxy

import (
	"encoding/json"
	"strings"
)

func extractRequestMeta(body []byte) (model string, stream bool) {
	if len(body) == 0 {
		return "", false
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	if modelRaw, ok := payload["model"]; ok {
		_ = json.Unmarshal(modelRaw, &model)
	}
	if streamRaw, ok := payload["stream"]; ok {
		_ = json.Unmarshal(streamRaw, &stream)
	}
	return model, stream
}

func truncateForLog(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
