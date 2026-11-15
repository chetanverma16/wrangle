package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTripWithPrivatePermissions(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	c := Config{RelayURL: "https://r", HostID: "host_1", HostSecret: "s", HostName: "mac",
		Devices: []Device{{DeviceID: "dev_1", Name: "iPhone", AppPublic: "a", HostPrivate: "p", HostPublic: "q", PairedAt: 7}}}
	if err := Save(home, c); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(home, "config.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config must be 0600, got %v", st.Mode().Perm())
	}
	d, _ := os.Stat(home)
	if d.Mode().Perm() != 0o700 {
		t.Fatalf("dir must be 0700, got %v", d.Mode().Perm())
	}
	got, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != "host_1" || len(got.Devices) != 1 || got.Devices[0].HostPrivate != "p" || got.ApprovalTimeoutClaude != 120 || got.ApprovalTimeoutCodex != 30 || !got.Paired() {
		t.Fatalf("unexpected %+v", got)
	}
}

func TestUpsertAndRemoveDevice(t *testing.T) {
	var c Config
	c.UpsertDevice(Device{DeviceID: "dev_1", Name: "iPhone"})
	c.UpsertDevice(Device{DeviceID: "dev_2", Name: "iPad"})
	c.UpsertDevice(Device{DeviceID: "dev_1", Name: "Alex's iPhone"})
	if len(c.Devices) != 2 || c.Devices[0].Name != "Alex's iPhone" {
		t.Fatalf("%+v", c.Devices)
	}
	if !c.RemoveDevice("dev_1") || c.RemoveDevice("dev_1") || len(c.Devices) != 1 {
		t.Fatalf("%+v", c.Devices)
	}
	if (Config{HostID: "h"}).Paired() {
		t.Fatal("no secret: not paired")
	}
}

func TestStatusFileRoundTrip(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	if err := WriteStatus(home, true, time.UnixMilli(42)); err != nil {
		t.Fatal(err)
	}
	s, err := ReadStatus(home)
	if err != nil || s != (Status{Relay: "up", At: 42}) {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestLoadMissingIsError(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("want error when not paired")
	}
}

func TestHomeHonoursEnv(t *testing.T) {
	t.Setenv("WRANGLE_HOME", "/tmp/x-wrangle")
	if Home() != "/tmp/x-wrangle" {
		t.Fatal(Home())
	}
}

func TestConcurrentSavesDoNotClobberTheTempFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(i int) { errs <- Save(home, Config{HostID: "h", HostSecret: "s", HostName: string(rune('a' + i))}) }(i)
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(home); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(home, "config.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("%v", st.Mode().Perm())
	}
	left, _ := filepath.Glob(filepath.Join(home, "*.tmp*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}
