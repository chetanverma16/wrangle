package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProjectHooksPresent reports whether dir's own Claude Code settings (.claude/settings.json or settings.local.json)
// send approvals to Wrangle. Project hooks work only in that project, but they work.
func ProjectHooksPresent(dir string) bool {
	for _, name := range []string{"settings.json", "settings.local.json"} {
		if data, err := os.ReadFile(filepath.Join(dir, ".claude", name)); err == nil && strings.Contains(string(data), " hook claude permission") {
			return true
		}
	}
	return false
}

// ClaudeSettingsFiles are the settings Claude Code reads for a session started in dir: the user's, then the project's.
func ClaudeSettingsFiles(p Paths, dir string) []string {
	return []string{p.ClaudeSettings, filepath.Join(dir, ".claude", "settings.json"), filepath.Join(dir, ".claude", "settings.local.json")}
}

var allowRe = regexp.MustCompile(`permissionDecision\\?"?\s*:\s*\\?"?allow`)

const maxScript = 1 << 20

// AutoAllowHooks lists the other PreToolUse hooks in files that can approve a tool call themselves (their command, or
// the script it runs, sets permissionDecision to "allow"). Claude Code doesn't ask about calls a hook already allowed,
// so no PermissionRequest fires and those calls never reach the phone. Read only; nothing is run.
func AutoAllowHooks(files []string) []string {
	var found []string
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			Hooks map[string][]struct {
				Hooks []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"hooks"`
		}
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		for _, g := range doc.Hooks["PreToolUse"] {
			for _, h := range g.Hooks {
				c := strings.TrimSpace(h.Command)
				if c == "" || hookRe.MatchString(c) || seen[c] || !approves(c) {
					continue
				}
				seen[c] = true
				found = append(found, label(c))
			}
		}
	}
	return found
}

// approves: the command line itself, or the script file it starts, contains a permissionDecision of allow.
func approves(command string) bool {
	if allowRe.MatchString(command) {
		return true
	}
	path := expandHome(strings.Fields(command)[0])
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxScript {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && allowRe.Match(data)
}

// label is the script path when the command starts one, else the command (trimmed for display).
func label(command string) string {
	first := strings.Fields(command)[0]
	if _, err := os.Stat(expandHome(first)); err == nil {
		return first
	}
	if len(command) > 60 {
		return command[:57] + "..."
	}
	return command
}

func expandHome(p string) string {
	p = strings.Trim(p, `"'`)
	home := userHome()
	for _, pre := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(p, pre) {
			return filepath.Join(home, p[len(pre):])
		}
	}
	return p
}
