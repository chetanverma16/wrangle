package setup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

const docKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func healthyDoctor(t *testing.T) (*fake, DoctorDeps, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "w")
	keys := filepath.Join(dir, "authorized_keys")
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s", TmuxPath: "/opt/homebrew/bin/tmux",
		Devices: []config.Device{{DeviceID: "dev_1", Name: "iPhone"}}})
	_ = config.WriteStatus(home, true, time.UnixMilli(100_000))
	_ = sshkeys.Add(keys, docKey, "dev_1", "iPhone")
	f := &fake{paths: map[string]string{"tmux": "/opt/homebrew/bin/tmux"}, banners: []string{"SSH-2.0-OpenSSH_9.8"},
		runs: map[string]string{"scutil --get LocalHostName": "Mac\n"}}
	d := DoctorDeps{Home: home, KeysPath: keys, Health: func() error { return nil }, HooksPresent: func() bool { return true },
		SocketAlive: func() bool { return true }, Now: func() time.Time { return time.UnixMilli(105_000) }}
	return f, d, &bytes.Buffer{}
}

func runDoctor(f *fake, d DoctorDeps, out *bytes.Buffer) int {
	e := f.env()
	e.Out = out
	return Doctor(e, d)
}

func TestDoctorAllGood(t *testing.T) {
	f, d, out := healthyDoctor(t)
	if code := runDoctor(f, d, out); code != 0 || strings.Contains(out.String(), "✗") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorPrintsAFixForEachFailure(t *testing.T) {
	cases := map[string]struct {
		breakIt func(f *fake, d *DoctorDeps)
		fix     string
	}{
		"tmux":         {func(f *fake, d *DoctorDeps) { delete(f.paths, "tmux") }, "brew install tmux"},
		"remote login": {func(f *fake, d *DoctorDeps) { f.banners = []string{""} }, "System Settings → General → Sharing"},
		"relay":        {func(f *fake, d *DoctorDeps) { d.Health = func() error { return errors.New("dns") } }, "Check your internet connection"},
		"daemon":       {func(f *fake, d *DoctorDeps) { d.SocketAlive = func() bool { return false } }, "launchctl load -w ~/Library/LaunchAgents/com.stackframe.wrangle.plist"},
		"stale status": {func(f *fake, d *DoctorDeps) { d.Now = func() time.Time { return time.UnixMilli(200_000) } }, "isn't connected to the Wrangle server"},
		"hooks":        {func(f *fake, d *DoctorDeps) { d.HooksPresent = func() bool { return false } }, "wrangle install"},
		"key":          {func(f *fake, d *DoctorDeps) { _, _ = sshkeys.Remove(d.KeysPath, "dev_1") }, "Remove this Mac in the Wrangle app"},
		"tailscale ssh": {func(f *fake, d *DoctorDeps) {
			cli := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
			f.paths[cli] = cli
			f.runs[cli+" ip -4"] = "100.101.102.103\n"
			f.runs[cli+" debug prefs"] = `{"RunSSH":true}`
		}, "tailscale set --ssh=false"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, d, out := healthyDoctor(t)
			tc.breakIt(f, &d)
			if code := runDoctor(f, d, out); code != 1 || !strings.Contains(out.String(), tc.fix) {
				t.Fatalf("exit %d, want fix %q:\n%s", code, tc.fix, out)
			}
		})
	}
}

func TestDoctorBeforeSetup(t *testing.T) {
	f, d, out := healthyDoctor(t)
	d.Home = filepath.Join(t.TempDir(), "empty")
	if code := runDoctor(f, d, out); code != 1 || !strings.Contains(out.String(), "This Mac isn't connected to an iPhone yet. Run `wrangle setup`.") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorReportsAnUnreadableConfigInsteadOfCallingItNotSetUp(t *testing.T) {
	f, d, out := healthyDoctor(t)
	if err := os.WriteFile(filepath.Join(d.Home, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := runDoctor(f, d, out)
	if code != 1 || strings.Contains(out.String(), "isn't connected to an iPhone yet") || !strings.Contains(out.String(), "Couldn't read ~/.wrangle/config.json") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorFailsWhenNoPhoneIsLinked(t *testing.T) {
	f, d, out := healthyDoctor(t)
	_ = config.Save(d.Home, config.Config{HostID: "host_1", HostSecret: "s"})
	if code := runDoctor(f, d, out); code != 1 || !strings.Contains(out.String(), "No iPhone is connected. Run `wrangle setup`.") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorPrintsAPhoneNameSafely(t *testing.T) {
	f, d, out := healthyDoctor(t)
	_ = config.Save(d.Home, config.Config{HostID: "host_1", HostSecret: "s",
		Devices: []config.Device{{DeviceID: "dev_1", Name: "evil\x1b[2J\nname"}}})
	_, _ = sshkeys.Remove(d.KeysPath, "dev_1")
	runDoctor(f, d, out)
	if strings.ContainsAny(out.String(), "\x1b\r") || strings.Contains(out.String(), "evil\n") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}

// I1: lines Wrangle wrote for phones this Mac no longer knows are reported, with the command that removes them.
func TestDoctorReportsUnknownWrangleKeys(t *testing.T) {
	f, d, out := healthyDoctor(t)
	_ = sshkeys.Add(d.KeysPath, docKey, "dev_old", "Lost iPhone")
	if code := runDoctor(f, d, out); code != 1 ||
		!strings.Contains(out.String(), "✗ 1 SSH key in ~/.ssh/authorized_keys belongs to an iPhone this Mac no longer knows (dev_old). Run: wrangle remove-device --unknown") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorReportsUnknownWrangleKeysEvenBeforeSetup(t *testing.T) {
	f, d, out := healthyDoctor(t)
	d.Home = filepath.Join(t.TempDir(), "empty") // config.json was removed, as setup's 401 message says
	if code := runDoctor(f, d, out); code != 1 || !strings.Contains(out.String(), "(dev_1). Run: wrangle remove-device --unknown") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}
