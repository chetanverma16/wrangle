// Package sshkeys adds and removes the phone's key in ~/.ssh/authorized_keys, one tagged line per device.
package sshkeys

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	ErrBadKey = errors.New("not an ecdsa-sha2-nistp256 or ssh-ed25519 public key")
	ErrBadID  = errors.New("bad device id")
	// ErrDanglingLink: authorized_keys is a symlink to a file that isn't there. Writing would replace the link with
	// a file, so nothing is written; the fix is to restore the link's target or remove the link.
	ErrDanglingLink = errors.New("~/.ssh/authorized_keys is a symlink to a missing file; restore its target or remove the link")

	idRE  = regexp.MustCompile(`^dev_[A-Za-z0-9_-]{1,60}$`)
	b64RE = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,3}$`)
)

// DefaultPath is ~/.ssh/authorized_keys. WRANGLE_AUTHORIZED_KEYS overrides it (local end-to-end runs only).
func DefaultPath() string {
	if p := os.Getenv("WRANGLE_AUTHORIZED_KEYS"); p != "" {
		return p
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".ssh", "authorized_keys")
}

// Line builds the tagged line. `restrict` turns off port, agent and X11 forwarding; `pty` keeps the terminal working.
// Only "<type> <base64>" is taken from key (a trailing comment is dropped); anything else is refused.
func Line(key, deviceID, name string) (string, error) {
	if !idRE.MatchString(deviceID) {
		return "", ErrBadID
	}
	if strings.ContainsAny(key, "\r\n\x00") {
		return "", ErrBadKey
	}
	f := strings.Fields(key)
	if len(f) < 2 || (f[0] != "ecdsa-sha2-nistp256" && f[0] != "ssh-ed25519") || !b64RE.MatchString(f[1]) {
		return "", ErrBadKey
	}
	if _, err := base64.StdEncoding.DecodeString(f[1]); err != nil {
		return "", ErrBadKey
	}
	return "restrict,pty " + f[0] + " " + f[1] + " " + marker(deviceID) + " " + cleanName(name), nil
}

func marker(deviceID string) string { return "wrangle:" + deviceID }

// cleanName keeps printable characters, turns newlines and tabs into spaces, and cuts to 64 runes.
func cleanName(s string) string {
	var b []rune
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b = append(b, ' ')
		case unicode.IsPrint(r):
			b = append(b, r)
		}
	}
	out := strings.Join(strings.Fields(string(b)), " ")
	if r := []rune(out); len(r) > 64 {
		out = string(r[:64])
	}
	if out == "" {
		out = "iPhone"
	}
	return out
}

// isDeviceLine is true only for a line Wrangle wrote: "restrict,pty <type> <b64> wrangle:<id> ...".
// The marker must be the 4th field, so a device name or a user's own line can never match.
func isDeviceLine(line, deviceID string) bool {
	f := strings.Fields(line)
	return len(f) >= 4 && f[0] == "restrict,pty" && f[3] == marker(deviceID)
}

// resolve follows a symlinked path so edits land in the real file and the link stays a link. A missing path is
// returned as is (it will be created); a symlink whose target can't be resolved is ErrDanglingLink.
func resolve(path string) (string, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ErrDanglingLink
	}
	return r, nil
}

// readLines returns the file's lines and mode. A missing file is empty with mode 0600 (and ~/.ssh is created 0700).
func readLines(path string) ([]string, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if _, statErr := os.Stat(filepath.Dir(path)); os.IsNotExist(statErr) {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return nil, 0, err
			}
		}
		return nil, 0o600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil, st.Mode().Perm(), nil
	}
	return strings.Split(text, "\n"), st.Mode().Perm(), nil
}

// write replaces path (already resolved) atomically: a unique temp file beside it, synced, then renamed over it.
// Callers hold config.Lock across their read-modify-write, so concurrent edits from other processes aren't lost.
func write(path string, lines []string, mode os.FileMode) error {
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".authorized_keys.wrangle-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(body)
	if err := errors.Join(werr, f.Chmod(mode), f.Sync(), f.Close()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Add writes (or replaces) the device's line. Hold config.Lock around it.
func Add(path, key, deviceID, name string) error {
	line, err := Line(key, deviceID, name)
	if err != nil {
		return err
	}
	path, err = resolve(path)
	if err != nil {
		return err
	}
	lines, mode, err := readLines(path)
	if err != nil {
		return err
	}
	kept := lines[:0:0]
	for _, l := range lines {
		if !isDeviceLine(l, deviceID) {
			kept = append(kept, l)
		}
	}
	return write(path, append(kept, line), mode)
}

// Remove deletes the device's line. Hold config.Lock around it.
func Remove(path, deviceID string) (bool, error) {
	path, err := resolve(path)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}
	lines, mode, err := readLines(path)
	if err != nil {
		return false, err
	}
	var kept []string
	for _, l := range lines {
		if !isDeviceLine(l, deviceID) {
			kept = append(kept, l)
		}
	}
	if len(kept) == len(lines) {
		return false, nil
	}
	return true, write(path, kept, mode)
}

func Has(path, deviceID string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if isDeviceLine(l, deviceID) {
			return true
		}
	}
	return false
}

// DeviceIDs lists the device ids of every line Wrangle wrote, in file order. A missing file has none.
func DeviceIDs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] == "restrict,pty" && strings.HasPrefix(f[3], "wrangle:") && idRE.MatchString(strings.TrimPrefix(f[3], "wrangle:")) {
			ids = append(ids, strings.TrimPrefix(f[3], "wrangle:"))
		}
	}
	return ids, nil
}
