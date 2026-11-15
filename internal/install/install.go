// Package install merges Wrangle's hooks into Claude Code and Codex config without touching anything else.
package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Paths struct {
	ClaudeSettings, CodexHooks, Backup, ServiceDir string
	WrangleHome                                    string // logs live here
	GOOS                                           string
	CodexHome                                      string // $CODEX_HOME at install time, passed to the service ("" = unset)
}

type Report struct {
	Changed          []string
	CodexTrustNeeded bool
}

// userHome is $HOME, so a HOME override (dev setups, tests) moves every agent and service path. If HOME is unset it
// falls back to the account's home directory, never to paths relative to the working directory.
func userHome() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "/"
}

// DefaultPaths are the agents' settings and the service directory under the user's home (see userHome); CODEX_HOME,
// when set, moves Codex's.
func DefaultPaths(wrangleHome string) Paths {
	home := userHome()
	codex := os.Getenv("CODEX_HOME")
	if codex == "" {
		codex = filepath.Join(home, ".codex")
	}
	svc := filepath.Join(home, ".config", "systemd", "user")
	if runtime.GOOS == "darwin" {
		svc = filepath.Join(home, "Library", "LaunchAgents")
	}
	return Paths{ClaudeSettings: filepath.Join(home, ".claude", "settings.json"), CodexHooks: filepath.Join(codex, "hooks.json"),
		Backup: filepath.Join(wrangleHome, "backup"), ServiceDir: svc, WrangleHome: wrangleHome, GOOS: runtime.GOOS,
		CodexHome: os.Getenv("CODEX_HOME")}
}

// stableCandidates is a var so tests can point it at temp files.
var stableCandidates = func() []string {
	home := userHome()
	return []string{"/opt/homebrew/bin/wrangle", "/usr/local/bin/wrangle", filepath.Join(home, ".local", "bin", "wrangle")}
}

// StableBin returns the first stable install path that is the very same file as the running executable.
func StableBin(executable string) string {
	self, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return executable
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return executable
	}
	for _, p := range stableCandidates() {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if info, err := os.Stat(real); err == nil && os.SameFile(info, selfInfo) {
			return p
		}
	}
	return executable
}

func Install(p Paths, bin string, now time.Time) (Report, error) {
	var r Report
	// Plan everything first so a broken file means nothing is written.
	claude, err := planClaude(p, bin)
	if err != nil {
		return r, fmt.Errorf("claude settings: %w", err)
	}
	var codex *pendingWrite
	if p.CodexHooks != "" {
		if codex, err = planCodex(p, bin); err != nil {
			return r, fmt.Errorf("codex hooks: %w", err)
		}
	}
	if err := claude.commit(p.Backup, now); err != nil {
		return r, err
	}
	if claude != nil {
		r.Changed = append(r.Changed, p.ClaudeSettings)
	}
	if codex != nil {
		if err := codex.commit(p.Backup, now); err != nil {
			return r, err
		}
		r.Changed = append(r.Changed, p.CodexHooks)
		r.CodexTrustNeeded = true
	}
	if p.ServiceDir != "" {
		path, err := writeService(p, bin)
		if err != nil {
			return r, err
		}
		r.Changed = append(r.Changed, path)
	}
	return r, nil
}

// Uninstall removes every Wrangle entry (any bin path) and restores the original status line.
func Uninstall(p Paths, bin string, now time.Time) error {
	claude, err := planUninstallClaude(p)
	if err != nil {
		return err
	}
	var codex *pendingWrite
	if p.CodexHooks != "" {
		if codex, err = planUninstallCodex(p); err != nil {
			return err
		}
	}
	if err := claude.commit(p.Backup, now); err != nil {
		return err
	}
	if err := codex.commit(p.Backup, now); err != nil {
		return err
	}
	return removeService(p)
}

// --- shared JSON helpers -------------------------------------------------------------------------------------

func readDoc(path string) (map[string]any, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	doc := map[string]any{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return doc, true, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, true, err
	}
	return doc, true, nil
}

// pendingWrite is a fully computed new document, written only once every file has been planned.
type pendingWrite struct {
	path    string
	doc     map[string]any
	existed bool
	pre     func() error // runs just before the write (e.g. saving the old status line)
}

// commit is a no-op on a nil receiver (nothing changed).
func (w *pendingWrite) commit(backupDir string, now time.Time) error {
	if w == nil {
		return nil
	}
	if w.pre != nil {
		if err := w.pre(); err != nil {
			return err
		}
	}
	return writeDoc(w.path, w.doc, w.existed, backupDir, now)
}

// writeDoc keeps the file's mode (new files are 0600) and writes through symlinks to the real target.
func writeDoc(path string, doc map[string]any, existed bool, backupDir string, now time.Time) error {
	target, mode := path, os.FileMode(0o600)
	if existed {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		target = real
		info, err := os.Stat(real)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
		if err := os.MkdirAll(backupDir, 0o700); err != nil {
			return err
		}
		orig, err := os.ReadFile(real)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(backupDir, fmt.Sprintf("%s.%d", filepath.Base(path), now.Unix())), orig, 0o600); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".wrangle-*") // created 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(append(data, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var (
	hookRe       = regexp.MustCompile(`^(?:\S*/)?wrangle hook (claude|codex) (permission|stop|notification|posttool)$`)
	statuslineRe = regexp.MustCompile(`(?s)^(?:\S*/)?wrangle statusline(?: --then (.*))?$`)
)

// ensureHook makes hooks[event] hold exactly one Wrangle entry, with command (whatever bin path an older install used
// is rewritten in place; extra Wrangle entries are dropped). Returns whether anything changed.
func ensureHook(doc map[string]any, event, matcher, command string, timeout int) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	groups, _ := hooks[event].([]any)
	changed, found := false, false
	var keptGroups []any
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			keptGroups = append(keptGroups, g)
			continue
		}
		inner, _ := gm["hooks"].([]any)
		var kept []any
		for _, h := range inner {
			m, ok := h.(map[string]any)
			c, _ := m["command"].(string)
			if !ok || !hookRe.MatchString(c) {
				kept = append(kept, h)
				continue
			}
			if found {
				changed = true // duplicate
				continue
			}
			found = true
			if c != command {
				m["command"] = command
				changed = true
			}
			kept = append(kept, m)
		}
		if len(kept) > 0 || len(inner) == 0 {
			gm["hooks"] = kept
			keptGroups = append(keptGroups, gm)
		}
	}
	if !found {
		entry := map[string]any{"type": "command", "command": command}
		if timeout > 0 {
			entry["timeout"] = timeout
		}
		group := map[string]any{"hooks": []any{entry}}
		if matcher != "" {
			group["matcher"] = matcher
		}
		keptGroups = append(keptGroups, group)
		changed = true
	}
	hooks[event] = keptGroups
	return changed
}

// removeHooks drops every Wrangle hook whatever its path; empty groups and events are removed.
func removeHooks(doc map[string]any) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	changed := false
	for event, raw := range hooks {
		groups, _ := raw.([]any)
		var keptGroups []any
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			inner, _ := gm["hooks"].([]any)
			var kept []any
			for _, h := range inner {
				if m, ok := h.(map[string]any); ok {
					if c, _ := m["command"].(string); hookRe.MatchString(c) {
						changed = true
						continue
					}
				}
				kept = append(kept, h)
			}
			if len(kept) > 0 {
				gm["hooks"] = kept
				keptGroups = append(keptGroups, gm)
			}
		}
		if len(keptGroups) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = keptGroups
		}
	}
	if hooks != nil && len(hooks) == 0 {
		delete(doc, "hooks")
	}
	return changed
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// shellUnquote exactly inverts shellQuote.
func shellUnquote(s string) (string, bool) {
	var out strings.Builder
	for {
		if !strings.HasPrefix(s, "'") {
			return "", false
		}
		end := strings.Index(s[1:], "'")
		if end < 0 {
			return "", false
		}
		out.WriteString(s[1 : 1+end])
		s = s[2+end:]
		if s == "" {
			return out.String(), true
		}
		if !strings.HasPrefix(s, `\'`) {
			return "", false
		}
		out.WriteByte('\'')
		s = s[2:]
	}
}

// HooksPresent reports whether Claude Code already sends approvals to Wrangle.
func HooksPresent(p Paths) bool {
	data, err := os.ReadFile(p.ClaudeSettings)
	return err == nil && strings.Contains(string(data), " hook claude permission")
}

// WriteService writes the launchd agent (or systemd unit) only; Install still writes hooks and service together.
func WriteService(p Paths, bin string) (string, error) { return writeService(p, bin) }
