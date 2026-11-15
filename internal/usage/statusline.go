// Package usage collects agents' rate-limit usage: Claude via the documented status line JSON (spike S6), Codex
// via its transcript's token_count records.
package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Window struct {
	UsedPercent   float64 `json:"usedPercent"`
	ResetsAt      int64   `json:"resetsAt"`
	WindowMinutes int     `json:"windowMinutes"`
}

type Snapshot struct {
	Agent     string  `json:"agent"`
	Primary   *Window `json:"primary,omitempty"`
	Secondary *Window `json:"secondary,omitempty"`
	UpdatedAt int64   `json:"updatedAt"`
}

func claudePath(home string) string { return filepath.Join(home, "usage-claude.json") }

func Statusline(stdin io.Reader, stdout io.Writer, then string, home string, now time.Time) int {
	data, _ := io.ReadAll(io.LimitReader(stdin, 1<<20))
	var in struct {
		RateLimits struct {
			FiveHour *struct {
				UsedPercentage float64 `json:"used_percentage"`
				ResetsAt       int64   `json:"resets_at"`
			} `json:"five_hour"`
			SevenDay *struct {
				UsedPercentage float64 `json:"used_percentage"`
				ResetsAt       int64   `json:"resets_at"`
			} `json:"seven_day"`
		} `json:"rate_limits"`
	}
	if json.Unmarshal(data, &in) == nil && (in.RateLimits.FiveHour != nil || in.RateLimits.SevenDay != nil) {
		s := Snapshot{Agent: "claude", UpdatedAt: now.UnixMilli()}
		if w := in.RateLimits.FiveHour; w != nil {
			s.Primary = &Window{w.UsedPercentage, w.ResetsAt, 300}
		}
		if w := in.RateLimits.SevenDay; w != nil {
			s.Secondary = &Window{w.UsedPercentage, w.ResetsAt, 10080}
		}
		if b, err := json.Marshal(s); err == nil && os.MkdirAll(home, 0o700) == nil {
			_ = os.WriteFile(claudePath(home), b, 0o600)
		}
	}
	if then == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", then)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = stdout
	_ = cmd.Run()
	return 0
}

func ReadClaude(home string) (*Snapshot, error) {
	data, err := os.ReadFile(claudePath(home))
	if err != nil {
		return nil, err
	}
	var s Snapshot
	return &s, json.Unmarshal(data, &s)
}
