package usage

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const codexTailBytes = 1 << 20

// newestRollout descends sessions/YYYY/MM/DD choosing the lexically largest directory at each level (falling back
// to the next-largest when a branch has no rollout) and returns the largest rollout-*.jsonl name found there.
func newestRollout(dir string, depth int) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if depth == 3 {
			if !e.IsDir() && strings.HasPrefix(e.Name(), "rollout-") && strings.HasSuffix(e.Name(), ".jsonl") {
				names = append(names, e.Name())
			}
		} else if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if depth == 3 {
		if len(names) > 0 {
			return filepath.Join(dir, names[0])
		}
		return ""
	}
	for _, n := range names {
		if p := newestRollout(filepath.Join(dir, n), depth+1); p != "" {
			return p
		}
	}
	return ""
}

// LatestCodex returns the last token_count rate limits near the end of the newest rollout file, or nil if there are
// none. Only the final 1 MiB of the file is read, and a found snapshot is returned even if other lines are bad.
func LatestCodex(codexHome string) (*Snapshot, error) {
	path := newestRollout(filepath.Join(codexHome, "sessions"), 0)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := st.Size() - codexTailBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	buf, readErr := io.ReadAll(io.LimitReader(f, codexTailBytes))
	lines := bytes.Split(buf, []byte("\n"))
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is partial
	}
	var last *Snapshot
	for _, line := range lines {
		if !bytes.Contains(line, []byte(`"token_count"`)) {
			continue
		}
		var rec struct {
			Payload struct {
				Type       string `json:"type"`
				RateLimits *struct {
					Primary *struct {
						UsedPercent   float64 `json:"used_percent"`
						WindowMinutes int     `json:"window_minutes"`
						ResetsAt      int64   `json:"resets_at"`
					} `json:"primary"`
					Secondary *struct {
						UsedPercent   float64 `json:"used_percent"`
						WindowMinutes int     `json:"window_minutes"`
						ResetsAt      int64   `json:"resets_at"`
					} `json:"secondary"`
				} `json:"rate_limits"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Payload.Type != "token_count" || rec.Payload.RateLimits == nil {
			continue
		}
		s := &Snapshot{Agent: "codex", UpdatedAt: st.ModTime().UnixMilli()}
		if p := rec.Payload.RateLimits.Primary; p != nil {
			s.Primary = &Window{p.UsedPercent, p.ResetsAt, p.WindowMinutes}
		}
		if p := rec.Payload.RateLimits.Secondary; p != nil {
			s.Secondary = &Window{p.UsedPercent, p.ResetsAt, p.WindowMinutes}
		}
		last = s
	}
	if last != nil {
		return last, nil
	}
	return nil, readErr
}
