package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chetanverma16/wrangle/internal/config"
	"github.com/chetanverma16/wrangle/internal/relayhttp"
	"github.com/chetanverma16/wrangle/internal/sshkeys"
)

type fakeRemover struct {
	ids []string
	err error
}

func (f *fakeRemover) RemoveLink(_ context.Context, _ relayhttp.Auth, id string) error {
	f.ids = append(f.ids, id)
	return f.err
}

func deviceHome(t *testing.T) (string, string) {
	dir := t.TempDir()
	home, keys := filepath.Join(dir, "w"), filepath.Join(dir, "authorized_keys")
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s",
		Devices: []config.Device{{DeviceID: "dev_1", Name: "Alex's iPhone"}, {DeviceID: "dev_2", Name: "iPad"}}})
	_ = sshkeys.Add(keys, phoneKey, "dev_1", "Alex's iPhone")
	_ = sshkeys.Add(keys, phoneKey, "dev_2", "iPad")
	return home, keys
}

func TestRemoveDeviceByNameUnlinksAndDeletesTheKey(t *testing.T) {
	home, keys := deviceHome(t)
	rel := &fakeRemover{}
	var out bytes.Buffer
	if code := removeDevice(context.Background(), home, keys, rel, "alex's iphone", &out); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	c, _ := config.Load(home)
	if len(rel.ids) != 1 || rel.ids[0] != "dev_1" || sshkeys.Has(keys, "dev_1") || !sshkeys.Has(keys, "dev_2") || len(c.Devices) != 1 {
		t.Fatalf("%v %+v", rel.ids, c.Devices)
	}
	if !strings.Contains(out.String(), "✓ Removed “Alex's iPhone”") {
		t.Fatal(out.String())
	}
}

func TestRemoveDeviceNeedsANameWhenThereAreSeveral(t *testing.T) {
	home, keys := deviceHome(t)
	var out bytes.Buffer
	if code := removeDevice(context.Background(), home, keys, &fakeRemover{}, "", &out); code != 2 || !strings.Contains(out.String(), "iPad") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if code := removeDevice(context.Background(), home, keys, &fakeRemover{}, "Pixel", &out); code != 2 {
		t.Fatalf("unknown name: exit %d", code)
	}
}

func TestRemoveDeviceWithOnePhoneNeedsNoName(t *testing.T) {
	home, keys := deviceHome(t)
	_ = removeDevice(context.Background(), home, keys, &fakeRemover{}, "iPad", &bytes.Buffer{})
	if code := removeDevice(context.Background(), home, keys, &fakeRemover{}, "", &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var out bytes.Buffer
	if code := removeDevice(context.Background(), home, keys, &fakeRemover{}, "", &out); code != 1 || !strings.Contains(out.String(), "No iPhone is connected") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestRemoveDeviceChangesNothingWhenTheServerIsUnreachable(t *testing.T) {
	home, keys := deviceHome(t)
	var out bytes.Buffer
	code := removeDevice(context.Background(), home, keys, &fakeRemover{err: errors.New("dns")}, "iPad", &out)
	c, _ := config.Load(home)
	if code != 1 || !sshkeys.Has(keys, "dev_2") || len(c.Devices) != 2 || !strings.Contains(out.String(), "try again") {
		t.Fatalf("exit %d %+v\n%s", code, c.Devices, out.String())
	}
}

func TestRemoveDeviceStillRemovesLocallyWhenTheLinkIsNoLongerValid(t *testing.T) {
	home, keys := deviceHome(t)
	var out bytes.Buffer
	code := removeDevice(context.Background(), home, keys, &fakeRemover{err: relayhttp.ErrUnauthorized}, "iPad", &out)
	c, _ := config.Load(home)
	if code != 0 || sshkeys.Has(keys, "dev_2") || len(c.Devices) != 1 {
		t.Fatalf("exit %d %+v\n%s", code, c.Devices, out.String())
	}
}

func TestRemoveDeviceNeverOverwritesAnUnreadableConfig(t *testing.T) {
	home, keys := deviceHome(t)
	bad := []byte("{not json")
	if err := os.WriteFile(filepath.Join(home, "config.json"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	rel := &fakeRemover{}
	var out bytes.Buffer
	code := removeDevice(context.Background(), home, keys, rel, "iPad", &out)
	got, _ := os.ReadFile(filepath.Join(home, "config.json"))
	if code != 1 || string(got) != string(bad) || len(rel.ids) != 0 || !sshkeys.Has(keys, "dev_2") || strings.Contains(out.String(), "No iPhone is connected") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestRemoveDevicePrintsNamesSafely(t *testing.T) {
	home, keys := deviceHome(t)
	_ = config.Save(home, config.Config{HostID: "host_1", HostSecret: "s",
		Devices: []config.Device{{DeviceID: "dev_1", Name: "a\x1b[2Jb\nc"}, {DeviceID: "dev_2", Name: "x"}}})
	var out bytes.Buffer
	removeDevice(context.Background(), home, keys, &fakeRemover{}, "", &out)
	removeDevice(context.Background(), home, keys, &fakeRemover{}, "dev_1", &out)
	if strings.ContainsAny(out.String(), "\x1b\r") || strings.Contains(out.String(), "b\nc") {
		t.Fatalf("%q", out.String())
	}
}

// I1: --unknown removes only the wrangle: lines whose phone isn't in the config, without asking the relay.
func TestRemoveDeviceUnknownRemovesOnlyLinesForPhonesNotInTheConfig(t *testing.T) {
	home, keys := deviceHome(t)
	_ = sshkeys.Add(keys, phoneKey, "dev_old", "Lost iPhone")
	rel := &fakeRemover{}
	var out bytes.Buffer
	if code := removeUnknownDevices(home, keys, &out); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if len(rel.ids) != 0 || sshkeys.Has(keys, "dev_old") || !sshkeys.Has(keys, "dev_1") || !sshkeys.Has(keys, "dev_2") {
		t.Fatalf("%v", rel.ids)
	}
	if !strings.Contains(out.String(), "✓ Removed 1 unknown iPhone key from ~/.ssh/authorized_keys.") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := removeUnknownDevices(home, keys, &out); code != 0 || !strings.Contains(out.String(), "No unknown iPhone keys") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestRemoveDeviceUnknownWorksWithoutAConfig(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "authorized_keys")
	_ = os.WriteFile(keys, []byte("ssh-rsa AAAAB3mine laptop\n"), 0o600)
	_ = sshkeys.Add(keys, phoneKey, "dev_old", "Lost iPhone")
	var out bytes.Buffer
	if code := removeUnknownDevices(filepath.Join(dir, "none"), keys, &out); code != 0 || sshkeys.Has(keys, "dev_old") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if b, _ := os.ReadFile(keys); string(b) != "ssh-rsa AAAAB3mine laptop\n" {
		t.Fatalf("%q", b)
	}
}

func TestRemoveDeviceUnknownRefusesAnUnreadableConfig(t *testing.T) {
	home, keys := deviceHome(t)
	_ = os.WriteFile(filepath.Join(home, "config.json"), []byte("{not json"), 0o600)
	var out bytes.Buffer
	if code := removeUnknownDevices(home, keys, &out); code != 1 || !sshkeys.Has(keys, "dev_1") {
		t.Fatalf("exit %d\n%s", code, out.String()) // every phone would look unknown
	}
}
