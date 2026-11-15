package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// planClaude computes the new settings document; it writes nothing. A nil result means no change.
func planClaude(p Paths, bin string) (*pendingWrite, error) {
	doc, existed, err := readDoc(p.ClaudeSettings)
	if err != nil {
		return nil, err
	}
	changed := false
	changed = ensureHook(doc, "PermissionRequest", "", bin+" hook claude permission", 150) || changed
	changed = ensureHook(doc, "Stop", "", bin+" hook claude stop", 0) || changed
	changed = ensureHook(doc, "Notification", "", bin+" hook claude notification", 0) || changed
	changed = ensureHook(doc, "PostToolUse", "", bin+" hook claude posttool", 0) || changed

	w := &pendingWrite{path: p.ClaudeSettings, doc: doc, existed: existed}
	sl, _ := doc["statusLine"].(map[string]any)
	cur, _ := sl["command"].(string)
	if m := statuslineRe.FindStringSubmatch(cur); m != nil {
		// Already ours (maybe under an older bin path): rewrite only the bin, keep the --then part.
		want := bin + " statusline"
		if m[1] != "" {
			want += " --then " + m[1]
		}
		if want != cur {
			sl["command"] = want
			changed = true
		}
	} else {
		saved, _ := json.Marshal(map[string]any{"statusLine": doc["statusLine"]})
		w.pre = func() error {
			if err := os.MkdirAll(p.Backup, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(p.Backup, "claude-statusline.json"), saved, 0o600)
		}
		cmd := bin + " statusline"
		if cur != "" {
			cmd += " --then " + shellQuote(cur)
		}
		next := map[string]any{"type": "command", "command": cmd}
		if pad, ok := sl["padding"]; ok {
			next["padding"] = pad
		}
		doc["statusLine"] = next
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return w, nil
}

func planUninstallClaude(p Paths) (*pendingWrite, error) {
	doc, existed, err := readDoc(p.ClaudeSettings)
	if err != nil || !existed {
		return nil, err
	}
	changed := removeHooks(doc)
	if sl, _ := doc["statusLine"].(map[string]any); sl != nil {
		c, _ := sl["command"].(string)
		if m := statuslineRe.FindStringSubmatch(c); m != nil {
			raw := strings.TrimSpace(m[1])
			switch {
			case raw != "":
				// Prefer the exact inverse of shellQuote; a hand-edited (unquoted) command is already a shell command.
				if orig, ok := shellUnquote(raw); ok {
					raw = orig
				}
				sl["command"] = raw // keeps type, padding and any other keys
			default:
				var saved map[string]any
				if data, err := os.ReadFile(filepath.Join(p.Backup, "claude-statusline.json")); strings.Contains(m[0], "--then") && err == nil &&
					json.Unmarshal(data, &saved) == nil && saved["statusLine"] != nil {
					doc["statusLine"] = saved["statusLine"]
				} else {
					delete(doc, "statusLine")
				}
			}
			changed = true
		}
	}
	if !changed {
		return nil, nil
	}
	return &pendingWrite{path: p.ClaudeSettings, doc: doc, existed: true}, nil
}
