package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAllowRuleKeepsOtherKeysAndDedupes(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".claude"), 0o755)
	orig := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"other-tool"}]}]},"permissions":{"allow":["Bash(ls)"],"deny":["Bash(rm -rf /)"]}}`
	_ = os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte(orig), 0o644)
	if err := WriteAllowRule(dir, "git push"); err != nil {
		t.Fatal(err)
	}
	if err := WriteAllowRule(dir, "git push"); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	data, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.local.json"))
	_ = json.Unmarshal(data, &got)
	perms := got["permissions"].(map[string]any)
	if len(perms["allow"].([]any)) != 2 || len(perms["deny"].([]any)) != 1 || got["hooks"] == nil {
		t.Fatalf("%s", data)
	}
}

func TestWriteAllowRuleCreatesFile(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAllowRule(dir, "npm test"); err != nil {
		t.Fatal(err)
	}
	rules, _ := readAllow(dir)
	if len(rules) != 1 || rules[0] != "Bash(npm test)" {
		t.Fatal(rules)
	}
}
