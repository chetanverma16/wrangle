// Package config stores the helper's pairing and settings in ~/.wrangle/config.json (0600).
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Device is one linked phone and the host key pair made for it.
type Device struct {
	DeviceID    string `json:"device_id"`
	Name        string `json:"name"`
	AppPublic   string `json:"app_public"`
	HostPrivate string `json:"host_private"` // a fresh host key per phone (protocol/README.md)
	HostPublic  string `json:"host_public"`
	PairedAt    int64  `json:"paired_at"`
}

type Config struct {
	RelayURL              string   `json:"relay_url"`
	HostID                string   `json:"host_id"`
	HostSecret            string   `json:"host_secret"`
	HostName              string   `json:"host_name"`
	Devices               []Device `json:"devices"`
	TmuxPath              string   `json:"tmux_path,omitempty"`
	KeepAwakeOff          bool     `json:"keep_awake_off,omitempty"`
	ApprovalTimeoutClaude int      `json:"approval_timeout_claude"`
	ApprovalTimeoutCodex  int      `json:"approval_timeout_codex"`
}

func Home() string {
	if h := os.Getenv("WRANGLE_HOME"); h != "" {
		return h
	}
	dir, _ := os.UserHomeDir()
	return filepath.Join(dir, ".wrangle")
}

func Load(home string) (Config, error) {
	var c Config
	data, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if c.ApprovalTimeoutClaude <= 0 {
		c.ApprovalTimeoutClaude = 120
	}
	if c.ApprovalTimeoutCodex <= 0 {
		c.ApprovalTimeoutCodex = 30
	}
	return c, nil
}

func Save(home string, c Config) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// A unique temp file, so concurrent saves (setup, unlink, `wrangle config`) never write into each other's.
	f, err := os.CreateTemp(home, "config.json.tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp, 0o600)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(home, "config.json")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (c Config) Paired() bool { return c.HostID != "" && c.HostSecret != "" }

func (c *Config) UpsertDevice(d Device) {
	for i := range c.Devices {
		if c.Devices[i].DeviceID == d.DeviceID {
			c.Devices[i] = d
			return
		}
	}
	c.Devices = append(c.Devices, d)
}

func (c *Config) RemoveDevice(id string) bool {
	for i := range c.Devices {
		if c.Devices[i].DeviceID == id {
			c.Devices = append(c.Devices[:i], c.Devices[i+1:]...)
			return true
		}
	}
	return false
}

// Status is written by `wrangle serve` every few seconds; `wrangle doctor` reads it.
type Status struct {
	Relay string `json:"relay"` // "up" or "down"
	At    int64  `json:"at"`    // Unix ms
}

func WriteStatus(home string, relayUp bool, now time.Time) error {
	s := Status{Relay: "down", At: now.UnixMilli()}
	if relayUp {
		s.Relay = "up"
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(s)
	tmp := filepath.Join(home, "status.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(home, "status.json"))
}

func ReadStatus(home string) (Status, error) {
	var s Status
	data, err := os.ReadFile(filepath.Join(home, "status.json"))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}
