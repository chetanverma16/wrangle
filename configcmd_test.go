package main

import (
	"path/filepath"
	"testing"

	"github.com/chetanverma16/wrangle/internal/config"
)

func TestConfigKeepAwakeOffAndOnPersist(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	t.Setenv("WRANGLE_HOME", home)
	_ = config.Save(home, config.Config{HostID: "host_1"})
	if code := runConfig([]string{"keep-awake", "off"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	c, _ := config.Load(home)
	if !c.KeepAwakeOff || c.HostID != "host_1" {
		t.Fatalf("%+v", c)
	}
	if code := runConfig([]string{"keep-awake", "on"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if c, _ := config.Load(home); c.KeepAwakeOff {
		t.Fatal("on must clear it")
	}
}

func TestConfigBeforePairingCreatesTheFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	t.Setenv("WRANGLE_HOME", home)
	if code := runConfig([]string{"keep-awake", "off"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if c, err := config.Load(home); err != nil || !c.KeepAwakeOff {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestConfigBadArgsExit2(t *testing.T) {
	t.Setenv("WRANGLE_HOME", filepath.Join(t.TempDir(), "w"))
	for _, args := range [][]string{nil, {"keep-awake"}, {"keep-awake", "maybe"}, {"colour", "on"}} {
		if code := runConfig(args); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}
