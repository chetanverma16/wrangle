package usage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const claudeStatus = `{"model":{"display_name":"Opus"},"rate_limits":{"five_hour":{"used_percentage":62,"resets_at":1791982443},"seven_day":{"used_percentage":12.5,"resets_at":1792569243}}}`

func TestStatuslineSavesClaudeUsageAndPrintsNothingWithoutThen(t *testing.T) {
	home := t.TempDir()
	var out bytes.Buffer
	if Statusline(strings.NewReader(claudeStatus), &out, "", home, time.UnixMilli(5000)) != 0 || out.Len() != 0 {
		t.Fatalf("out %q", out.String())
	}
	s, err := ReadClaude(home)
	if err != nil {
		t.Fatal(err)
	}
	if s.Agent != "claude" || s.Primary.UsedPercent != 62 || s.Primary.WindowMinutes != 300 || s.Secondary.WindowMinutes != 10080 || s.UpdatedAt != 5000 {
		t.Fatalf("%+v %+v", s, s.Primary)
	}
}

func TestStatuslinePassesThroughToUsersCommand(t *testing.T) {
	home := t.TempDir()
	var out bytes.Buffer
	Statusline(strings.NewReader(claudeStatus), &out, `cat | grep -o '"display_name":"[A-Za-z]*"'`, home, time.Now())
	if strings.TrimSpace(out.String()) != `"display_name":"Opus"` {
		t.Fatalf("then-command must get the same stdin, got %q", out.String())
	}
}

func TestStatuslineWithoutRateLimitsKeepsOldSnapshot(t *testing.T) {
	home := t.TempDir()
	Statusline(strings.NewReader(claudeStatus), &bytes.Buffer{}, "", home, time.UnixMilli(1))
	Statusline(strings.NewReader(`{"model":{}}`), &bytes.Buffer{}, "", home, time.UnixMilli(2))
	s, _ := ReadClaude(home)
	if s == nil || s.UpdatedAt != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestLatestCodexReadsNewestRollout(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sessions", "2026", "10", "14")
	_ = os.MkdirAll(dir, 0o755)
	old := `{"type":"event_msg","payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":1,"window_minutes":300,"resets_at":1},"secondary":{"used_percent":1,"window_minutes":10080,"resets_at":2}}}}`
	newer := `{"type":"event_msg","payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":5.0,"window_minutes":300,"resets_at":1791982443},"secondary":{"used_percent":1.0,"window_minutes":10080,"resets_at":1792569243}}}}`
	_ = os.WriteFile(filepath.Join(dir, "rollout-2026-10-14T10-00-00-a.jsonl"), []byte(old+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "rollout-2026-10-14T13-26-30-b.jsonl"), []byte(`{"type":"session_meta","payload":{}}`+"\n"+old+"\n"+newer+"\n"), 0o644)
	s, err := LatestCodex(root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Agent != "codex" || s.Primary.UsedPercent != 5 || s.Secondary.ResetsAt != 1792569243 {
		t.Fatalf("%+v %+v", s, s.Primary)
	}
}

func TestLatestCodexWithNoSessionsIsNil(t *testing.T) {
	if s, _ := LatestCodex(t.TempDir()); s != nil {
		t.Fatalf("%+v", s)
	}
}

func tcLine(p float64) string {
	return fmt.Sprintf(`{"type":"event_msg","payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":%v,"window_minutes":300,"resets_at":1},"secondary":{"used_percent":1,"window_minutes":10080,"resets_at":2}}}}`, p) + "\n"
}

func writeRollout(t *testing.T, root, day, name, content string) {
	t.Helper()
	dir := filepath.Join(root, "sessions", filepath.FromSlash(day))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLatestCodexTailReadsLargeRollout(t *testing.T) {
	root := t.TempDir()
	filler := strings.Repeat(`{"type":"event_msg","payload":{"type":"other"}}`+"\n", 30000) // > 1 MiB
	writeRollout(t, root, "2026/10/14", "rollout-2026-10-14T10-00-00-a.jsonl", tcLine(1)+filler+tcLine(42)+`{"type":"x"}`+"\n")
	s, err := LatestCodex(root)
	if err != nil || s == nil || s.Primary.UsedPercent != 42 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestLatestCodexPicksNewestDayWithoutScanningOldYears(t *testing.T) {
	root := t.TempDir()
	writeRollout(t, root, "2025/12/31", "rollout-2025-12-31T10-00-00-z.jsonl", "{not json token_count\n")
	writeRollout(t, root, "2026/09/30", "rollout-2026-09-30T10-00-00-a.jsonl", tcLine(7))
	writeRollout(t, root, "2026/10/02", "rollout-2026-10-02T10-00-00-a.jsonl", tcLine(9))
	if err := os.MkdirAll(filepath.Join(root, "sessions", "2026", "10", "03"), 0o755); err != nil { // empty newest day: fall back
		t.Fatal(err)
	}
	s, err := LatestCodex(root)
	if err != nil || s == nil || s.Primary.UsedPercent != 9 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestLatestCodexSurvivesHugeLineBeforeSnapshot(t *testing.T) {
	root := t.TempDir()
	huge := strings.Repeat("a", 17<<20) + "\n"
	writeRollout(t, root, "2026/10/14", "rollout-2026-10-14T10-00-00-a.jsonl", tcLine(1)+huge+tcLine(33))
	s, err := LatestCodex(root)
	if err != nil || s == nil || s.Primary.UsedPercent != 33 {
		t.Fatalf("%+v %v", s, err)
	}
}
