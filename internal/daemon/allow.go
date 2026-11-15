package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func settingsPath(cwd string) string { return filepath.Join(cwd, ".claude", "settings.local.json") }

func readAllow(cwd string) ([]string, error) {
	var doc map[string]any
	data, err := os.ReadFile(settingsPath(cwd))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	perms, _ := doc["permissions"].(map[string]any)
	list, _ := perms["allow"].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// WriteAllowRule adds Bash(<command>) to the project's .claude/settings.local.json permissions.allow (spike S2:
// applies to the running session immediately). Other keys are kept as they are.
func WriteAllowRule(cwd, command string) error {
	doc := map[string]any{}
	if data, err := os.ReadFile(settingsPath(cwd)); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
	}
	perms, _ := doc["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
	}
	list, _ := perms["allow"].([]any)
	rule := "Bash(" + command + ")"
	for _, v := range list {
		if v == rule {
			return nil
		}
	}
	perms["allow"] = append(list, rule)
	doc["permissions"] = perms
	if err := os.MkdirAll(filepath.Dir(settingsPath(cwd)), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath(cwd), append(data, '\n'), 0o644)
}
