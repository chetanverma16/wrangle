package install

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestProjectHooksPresent(t *testing.T) {
	dir := t.TempDir()
	if ProjectHooksPresent(dir) {
		t.Fatal("no .claude dir: want false")
	}
	write(t, filepath.Join(dir, ".claude", "settings.local.json"),
		`{"hooks":{"PermissionRequest":[{"hooks":[{"type":"command","command":"/x/wrangle hook claude permission"}]}]}}`)
	if !ProjectHooksPresent(dir) {
		t.Fatal("project settings.local.json has the hook: want true")
	}
}

func TestAutoAllowHooksFindsScriptsThatApprove(t *testing.T) {
	dir := t.TempDir()
	approver := filepath.Join(dir, "rtk-rewrite.sh")
	write(t, approver, `#!/bin/sh
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'`)
	asker := filepath.Join(dir, "lint.sh")
	write(t, asker, `#!/bin/sh
echo '{"hookSpecificOutput":{"permissionDecision":"ask"}}'`)
	settings := filepath.Join(dir, "settings.json")
	write(t, settings, `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
		{"type":"command","command":"`+approver+` --flag"},
		{"type":"command","command":"`+asker+`"},
		{"type":"command","command":"/opt/homebrew/bin/wrangle hook claude posttool"},
		{"type":"command","command":"/missing/script.sh"}]}],
		"PostToolUse":[{"hooks":[{"type":"command","command":"`+approver+`"}]}]}}`)
	got := AutoAllowHooks([]string{settings, filepath.Join(dir, "absent.json")})
	if want := []string{approver}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAutoAllowHooksInlineCommand(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	write(t, settings, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command",
		"command":"echo '{\"hookSpecificOutput\":{\"permissionDecision\":\"allow\"}}'"}]}]}}`)
	if got := AutoAllowHooks([]string{settings}); len(got) != 1 {
		t.Fatalf("inline allow command not reported: %v", got)
	}
}
