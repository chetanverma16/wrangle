package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bin = "/opt/homebrew/bin/wrangle"

func paths(t *testing.T) Paths {
	root := t.TempDir()
	return Paths{ClaudeSettings: filepath.Join(root, ".claude", "settings.json"), CodexHooks: filepath.Join(root, ".codex", "hooks.json"),
		Backup: filepath.Join(root, ".wrangle", "backup"), ServiceDir: filepath.Join(root, "svc"), WrangleHome: filepath.Join(root, ".wrangle"), GOOS: "darwin"}
}

func write(t *testing.T, path, s string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	var m map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func commands(m map[string]any, event string) []string {
	var out []string
	hooks, _ := m["hooks"].(map[string]any)
	groups, _ := hooks[event].([]any)
	for _, g := range groups {
		inner, _ := g.(map[string]any)["hooks"].([]any)
		for _, h := range inner {
			out = append(out, h.(map[string]any)["command"].(string))
		}
	}
	return out
}

const foreign = `{"model":"opus","hooks":{"Stop":[{"hooks":[{"type":"command","command":"/Users/dev/.orca/hook.sh"}]}],
 "PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guard.py"}]}]},
 "statusLine":{"type":"command","command":"~/bin/my-status"},"permissions":{"allow":["Bash(ls)"]}}`

func TestClaudeInstallKeepsForeignHooks(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	if _, err := Install(p, bin, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p.ClaudeSettings)
	if m["model"] != "opus" || m["permissions"] == nil {
		t.Fatal("unrelated keys must stay")
	}
	if got := commands(m, "Stop"); len(got) != 2 || got[0] != "/Users/dev/.orca/hook.sh" || got[1] != bin+" hook claude stop" {
		t.Fatalf("Stop %v", got)
	}
	if got := commands(m, "PreToolUse"); len(got) != 1 {
		t.Fatalf("PreToolUse must be untouched: %v", got)
	}
	if got := commands(m, "PermissionRequest"); len(got) != 1 || got[0] != bin+" hook claude permission" {
		t.Fatalf("PermissionRequest %v", got)
	}
	if got := commands(m, "Notification"); len(got) != 1 {
		t.Fatalf("Notification %v", got)
	}
	perm := m["hooks"].(map[string]any)["PermissionRequest"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if perm["timeout"].(float64) != 150 {
		t.Fatalf("claude permission hook timeout must be 150, got %v", perm["timeout"])
	}
	sl := m["statusLine"].(map[string]any)["command"].(string)
	if sl != bin+" statusline --then '~/bin/my-status'" {
		t.Fatalf("statusLine %q", sl)
	}
	if _, err := os.Stat(filepath.Join(p.Backup, "settings.json.100")); err != nil {
		t.Fatal("backup missing")
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	_, _ = Install(p, bin, time.Unix(100, 0))
	_, _ = Install(p, bin, time.Unix(200, 0))
	m := readJSON(t, p.ClaudeSettings)
	if got := commands(m, "Stop"); len(got) != 2 {
		t.Fatalf("second install duplicated: %v", got)
	}
	if sl := m["statusLine"].(map[string]any)["command"].(string); strings.Count(sl, "statusline") != 1 {
		t.Fatalf("statusLine wrapped twice: %q", sl)
	}
	c := readJSON(t, p.CodexHooks)
	if got := commands(c, "PermissionRequest"); len(got) != 1 {
		t.Fatalf("codex duplicated: %v", got)
	}
}

func TestUninstallRestoresOriginal(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	write(t, p.CodexHooks, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"superset-notify"}]}]}}`)
	_, _ = Install(p, bin, time.Unix(100, 0))
	if err := Uninstall(p, bin, time.Unix(300, 0)); err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	_ = json.Unmarshal([]byte(foreign), &want)
	got = readJSON(t, p.ClaudeSettings)
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	if string(w) != string(g) {
		t.Fatalf("uninstall must restore the original\nwant %s\n got %s", w, g)
	}
	if got := commands(readJSON(t, p.CodexHooks), "Stop"); len(got) != 1 || got[0] != "superset-notify" {
		t.Fatalf("codex %v", got)
	}
}

func TestCodexHooksUseShortTimeoutAndReportTrust(t *testing.T) {
	p := paths(t)
	r, err := Install(p, bin, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !r.CodexTrustNeeded {
		t.Fatal("first install must tell the user to trust the hooks in Codex")
	}
	c := readJSON(t, p.CodexHooks)
	h := c["hooks"].(map[string]any)["PermissionRequest"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if h["command"] != bin+" hook codex permission" || h["timeout"].(float64) != 60 {
		t.Fatalf("%v", h)
	}
	if got := commands(c, "Stop"); len(got) != 1 || got[0] != bin+" hook codex stop" {
		t.Fatalf("%v", got)
	}
}

func TestNoStatusLineBeforeGivesPlainCommand(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{}`)
	_, _ = Install(p, bin, time.Unix(1, 0))
	if sl := readJSON(t, p.ClaudeSettings)["statusLine"].(map[string]any)["command"]; sl != bin+" statusline" {
		t.Fatalf("%v", sl)
	}
	_ = Uninstall(p, bin, time.Unix(2, 0))
	if _, ok := readJSON(t, p.ClaudeSettings)["statusLine"]; ok {
		t.Fatal("statusLine we added must be removed")
	}
}

func TestServiceFilesPerOS(t *testing.T) {
	p := paths(t)
	_, _ = Install(p, bin, time.Unix(1, 0))
	plist, err := os.ReadFile(filepath.Join(p.ServiceDir, "com.stackframe.wrangle.plist"))
	if err != nil || !strings.Contains(string(plist), "<string>serve</string>") {
		t.Fatalf("launchd plist: %v %s", err, plist)
	}
	p.GOOS = "linux"
	_, _ = Install(p, bin, time.Unix(2, 0))
	unit, err := os.ReadFile(filepath.Join(p.ServiceDir, "wrangle.service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart="+bin+" serve") {
		t.Fatalf("systemd unit: %v %s", err, unit)
	}
}

func TestStableBinPrefersHomebrew(t *testing.T) {
	if got := StableBin("/opt/homebrew/Cellar/wrangle/0.1.0/bin/wrangle"); !strings.HasSuffix(got, "wrangle") {
		t.Fatal(got)
	}
}

func TestMalformedSettingsIsAnErrorAndUntouched(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{not json`)
	if _, err := Install(p, bin, time.Unix(1, 0)); err == nil {
		t.Fatal("want an error for a broken settings file")
	}
	if data, _ := os.ReadFile(p.ClaudeSettings); string(data) != `{not json` {
		t.Fatal("broken file must not be overwritten")
	}
}

func mode(t *testing.T, path string) os.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestModesArePreserved(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	_ = os.Chmod(p.ClaudeSettings, 0o600)
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, p.ClaudeSettings); m != 0o600 {
		t.Fatalf("settings mode after install %v", m)
	}
	if m := mode(t, p.CodexHooks); m != 0o600 {
		t.Fatalf("new file must be 0600, got %v", m)
	}
	if err := Uninstall(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, p.ClaudeSettings); m != 0o600 {
		t.Fatalf("settings mode after uninstall %v", m)
	}
}

func TestSymlinkedSettingsStayLinks(t *testing.T) {
	p := paths(t)
	real := filepath.Join(filepath.Dir(p.ClaudeSettings), "dotfiles", "settings.json")
	write(t, real, foreign)
	if err := os.MkdirAll(filepath.Dir(p.ClaudeSettings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p.ClaudeSettings); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(p.ClaudeSettings); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink must remain")
	}
	if got := commands(readJSON(t, real), "Stop"); len(got) != 2 {
		t.Fatalf("target not updated: %v", got)
	}
}

func TestBinMigrationDoesNotDuplicateOrLoseOriginal(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	write(t, p.CodexHooks, `{}`)
	binB := "/usr/local/bin/wrangle"
	_, _ = Install(p, bin, time.Unix(1, 0))
	if _, err := Install(p, binB, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p.ClaudeSettings)
	for _, ev := range []string{"PermissionRequest", "Notification"} {
		if got := commands(m, ev); len(got) != 1 || !strings.HasPrefix(got[0], binB+" hook claude ") {
			t.Fatalf("%s %v", ev, got)
		}
	}
	if got := commands(m, "Stop"); len(got) != 2 || got[1] != binB+" hook claude stop" {
		t.Fatalf("Stop %v", got)
	}
	if sl := m["statusLine"].(map[string]any)["command"]; sl != binB+" statusline --then '~/bin/my-status'" {
		t.Fatalf("%v", sl)
	}
	if got := commands(readJSON(t, p.CodexHooks), "PermissionRequest"); len(got) != 1 || got[0] != binB+" hook codex permission" {
		t.Fatalf("codex %v", got)
	}
	// uninstall with yet another bin still removes everything
	if err := Uninstall(p, "/elsewhere/wrangle", time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(foreign), &want)
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(readJSON(t, p.ClaudeSettings))
	if string(w) != string(g) {
		t.Fatalf("want %s got %s", w, g)
	}
}

func TestStableBinIgnoresUnrelatedCandidate(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "real")
	other := filepath.Join(dir, "other")
	same := filepath.Join(dir, "link")
	write(t, exe, "a")
	write(t, other, "b")
	old := stableCandidates
	defer func() { stableCandidates = old }()
	stableCandidates = func() []string { return []string{other} }
	if got := StableBin(exe); got != exe {
		t.Fatalf("unrelated file must not win: %s", got)
	}
	if err := os.Symlink(exe, same); err != nil {
		t.Fatal(err)
	}
	stableCandidates = func() []string { return []string{other, same} }
	if got := StableBin(exe); got != same {
		t.Fatalf("symlink to the executable should win: %s", got)
	}
}

func TestUninstallRestoresFromLiveCommand(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{"statusLine":{"type":"command","command":"it's a 'test'","padding":2}}`)
	_, _ = Install(p, bin, time.Unix(1, 0))
	if err := Uninstall(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	sl := readJSON(t, p.ClaudeSettings)["statusLine"].(map[string]any)
	if sl["command"] != "it's a 'test'" || sl["padding"].(float64) != 2 {
		t.Fatalf("quotes must round-trip: %v", sl)
	}

	// user edits the wrapped command; backup file is gone
	write(t, p.ClaudeSettings, `{"statusLine":{"type":"command","command":"~/bin/my-status"}}`)
	_, _ = Install(p, bin, time.Unix(3, 0))
	_ = os.Remove(filepath.Join(p.Backup, "claude-statusline.json"))
	m := readJSON(t, p.ClaudeSettings)
	m["statusLine"].(map[string]any)["command"] = bin + " statusline --then '~/bin/edited'"
	data, _ := json.Marshal(m)
	write(t, p.ClaudeSettings, string(data))
	if err := Uninstall(p, bin, time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}
	if c := readJSON(t, p.ClaudeSettings)["statusLine"].(map[string]any)["command"]; c != "~/bin/edited" {
		t.Fatalf("%v", c)
	}
}

func TestShellQuoteRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "a'b", "'", "''", "x y 'z' \"q\" $HOME", "end'"} {
		if got, ok := shellUnquote(shellQuote(s)); !ok || got != s {
			t.Fatalf("%q -> %q %v", s, got, ok)
		}
	}
}

func TestMalformedCodexWritesNothing(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, foreign)
	write(t, p.CodexHooks, `{broken`)
	if _, err := Install(p, bin, time.Unix(1, 0)); err == nil {
		t.Fatal("want error")
	}
	if data, _ := os.ReadFile(p.ClaudeSettings); string(data) != foreign {
		t.Fatal("claude settings must be untouched")
	}
	if _, err := os.Stat(p.Backup); err == nil {
		t.Fatal("nothing should be backed up either")
	}
}

func TestPlistLogsUnderWrangleHomeAndEscapesBin(t *testing.T) {
	p := paths(t)
	if _, err := Install(p, "/a&b/wrangle", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	plist, _ := os.ReadFile(filepath.Join(p.ServiceDir, "com.stackframe.wrangle.plist"))
	s := string(plist)
	if !strings.Contains(s, filepath.Join(p.WrangleHome, "serve.log")) || strings.Contains(s, "/tmp/") {
		t.Fatalf("log path: %s", s)
	}
	if !strings.Contains(s, "/a&amp;b/wrangle") {
		t.Fatalf("bin not escaped: %s", s)
	}
}

func TestLookalikeToolsAreLeftAlone(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/usr/bin/not-wrangle hook claude stop"}]}]},
 "statusLine":{"type":"command","command":"mywrangle statusline"}}`)
	write(t, p.CodexHooks, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"mywrangle hook codex stop"}]}]}}`)
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p.ClaudeSettings)
	if got := commands(m, "Stop"); len(got) != 2 || got[0] != "/usr/bin/not-wrangle hook claude stop" {
		t.Fatalf("Stop %v", got)
	}
	if sl := m["statusLine"].(map[string]any)["command"]; sl != bin+" statusline --then 'mywrangle statusline'" {
		t.Fatalf("%v", sl)
	}
	if got := commands(readJSON(t, p.CodexHooks), "Stop"); len(got) != 2 || got[0] != "mywrangle hook codex stop" {
		t.Fatalf("codex %v", got)
	}
	if err := Uninstall(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	m = readJSON(t, p.ClaudeSettings)
	if got := commands(m, "Stop"); len(got) != 1 || got[0] != "/usr/bin/not-wrangle hook claude stop" {
		t.Fatalf("Stop %v", got)
	}
	if sl := m["statusLine"].(map[string]any)["command"]; sl != "mywrangle statusline" {
		t.Fatalf("%v", sl)
	}
	if got := commands(readJSON(t, p.CodexHooks), "Stop"); len(got) != 1 || got[0] != "mywrangle hook codex stop" {
		t.Fatalf("codex %v", got)
	}
}

func TestBareAndAbsoluteWranglePathsAreRecognised(t *testing.T) {
	for _, c := range []string{"wrangle hook claude stop", "/opt/homebrew/bin/wrangle hook claude stop"} {
		if !hookRe.MatchString(c) {
			t.Fatal(c)
		}
	}
}

func TestHandEditedUnquotedThenIsKept(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{"statusLine":{"type":"command","command":"`+bin+` statusline --then ~/bin/x"}}`)
	if err := Uninstall(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if c := readJSON(t, p.ClaudeSettings)["statusLine"].(map[string]any)["command"]; c != "~/bin/x" {
		t.Fatalf("%v", c)
	}
}

func TestClaudePostToolUseHook(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"prettier-hook"}]}]}}`)
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, p.ClaudeSettings)
	got := commands(m, "PostToolUse")
	if len(got) != 2 || got[0] != "prettier-hook" || got[1] != bin+" hook claude posttool" {
		t.Fatalf("PostToolUse %v", got)
	}
	groups := m["hooks"].(map[string]any)["PostToolUse"].([]any)
	ours := groups[1].(map[string]any)
	if _, ok := ours["matcher"]; ok {
		t.Fatalf("our PostToolUse group must have no matcher: %v", ours)
	}
	if _, ok := ours["hooks"].([]any)[0].(map[string]any)["timeout"]; ok {
		t.Fatalf("our PostToolUse hook must have no timeout: %v", ours)
	}
	if got := commands(readJSON(t, p.CodexHooks), "PostToolUse"); len(got) != 0 {
		t.Fatalf("codex must not get PostToolUse: %v", got)
	}
	if err := Uninstall(p, bin, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if got := commands(readJSON(t, p.ClaudeSettings), "PostToolUse"); len(got) != 1 || got[0] != "prettier-hook" {
		t.Fatalf("after uninstall %v", got)
	}
}

func TestPostToolHookUnderOldBinIsMigrated(t *testing.T) {
	p := paths(t)
	write(t, p.ClaudeSettings, `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"/usr/local/bin/wrangle hook claude posttool"}]}]}}`)
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if got := commands(readJSON(t, p.ClaudeSettings), "PostToolUse"); len(got) != 1 || got[0] != bin+" hook claude posttool" {
		t.Fatalf("PostToolUse %v", got)
	}
}

func TestServiceCarriesCodexHome(t *testing.T) {
	p := paths(t)
	p.CodexHome = `/Users/a&b/"co\dex"<x>%h`
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	plist, _ := os.ReadFile(filepath.Join(p.ServiceDir, "com.stackframe.wrangle.plist"))
	want := `<key>EnvironmentVariables</key><dict><key>CODEX_HOME</key><string>/Users/a&amp;b/&#34;co\dex&#34;&lt;x&gt;%h</string></dict>`
	if !strings.Contains(string(plist), want) {
		t.Fatalf("plist missing escaped CODEX_HOME:\n%s", plist)
	}
	p.GOOS = "linux"
	if _, err := Install(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(p.ServiceDir, "wrangle.service"))
	if !strings.Contains(string(unit), "\nEnvironment=\"CODEX_HOME=/Users/a&b/\\\"co\\\\dex\\\"<x>%%h\"\n") {
		t.Fatalf("unit missing quoted CODEX_HOME:\n%s", unit)
	}
}

func TestServiceWithoutCodexHomeHasNoEnvironment(t *testing.T) {
	p := paths(t)
	if _, err := Install(p, bin, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	plist, _ := os.ReadFile(filepath.Join(p.ServiceDir, "com.stackframe.wrangle.plist"))
	if strings.Contains(string(plist), "EnvironmentVariables") || strings.Contains(string(plist), "CODEX_HOME") {
		t.Fatalf("plist must have no environment:\n%s", plist)
	}
	p.GOOS = "linux"
	if _, err := Install(p, bin, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(filepath.Join(p.ServiceDir, "wrangle.service"))
	if strings.Contains(string(unit), "Environment") {
		t.Fatalf("unit must have no environment:\n%s", unit)
	}
}

func TestDefaultPathsCodexHomeOnlyWhenSet(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	if p := DefaultPaths(t.TempDir()); p.CodexHome != "" {
		t.Fatalf("unset CODEX_HOME must give empty CodexHome, got %q", p.CodexHome)
	}
	t.Setenv("CODEX_HOME", "/srv/codex")
	if p := DefaultPaths(t.TempDir()); p.CodexHome != "/srv/codex" || p.CodexHooks != "/srv/codex/hooks.json" {
		t.Fatalf("%+v", p)
	}
}

func TestHooksPresentAfterInstall(t *testing.T) {
	p := paths(t)
	if HooksPresent(p) {
		t.Fatal("nothing installed yet")
	}
	if _, err := Install(p, bin, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if !HooksPresent(p) {
		t.Fatal("want present after install")
	}
}

// I4: a HOME override (as dev setups use) moves every agent and service path under it; nothing points at the real
// home. An unset HOME never yields relative paths in the working directory.
func TestDefaultPathsHonourAHomeOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	p := DefaultPaths(filepath.Join(home, "w"))
	for _, got := range []string{p.ClaudeSettings, p.CodexHooks, p.ServiceDir} {
		if !strings.HasPrefix(got, home+string(filepath.Separator)) {
			t.Fatalf("%q is outside HOME %q", got, home)
		}
	}
	if p.CodexHome != "" {
		t.Fatalf("CodexHome %q", p.CodexHome)
	}
	t.Setenv("HOME", "")
	p = DefaultPaths(filepath.Join(home, "w"))
	if !filepath.IsAbs(p.ClaudeSettings) || !filepath.IsAbs(p.CodexHooks) || !filepath.IsAbs(p.ServiceDir) {
		t.Fatalf("relative paths with an empty HOME: %+v", p)
	}
}
