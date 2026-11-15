package sshkeys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/chetanverma16/wrangle/internal/config"
)

const ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
const ec = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAddCreatesSSHDirAndFileWithPrivateModes(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	if err := Add(p, ec+" wrangle@iPhone", "dev_1", "iPhone"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p); got != "restrict,pty "+ec+" wrangle:dev_1 iPhone\n" {
		t.Fatalf("got %q", got)
	}
	d, _ := os.Stat(filepath.Dir(p))
	f, _ := os.Stat(p)
	if d.Mode().Perm() != 0o700 || f.Mode().Perm() != 0o600 {
		t.Fatalf("modes dir %v file %v", d.Mode().Perm(), f.Mode().Perm())
	}
}

func TestAddKeepsOtherLinesAndModeAndReplacesTheSameDevice(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	orig := "# my keys\nssh-rsa AAAAB3mine laptop\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Add(p, ec, "dev_1", "iPhone"); err != nil {
		t.Fatal(err)
	}
	if err := Add(p, ed, "dev_1", "iPhone"); err != nil { // re-enrol: replaces, never duplicates
		t.Fatal(err)
	}
	if err := Add(p, ec, "dev_2", "iPad"); err != nil {
		t.Fatal(err)
	}
	want := orig + "restrict,pty " + ed + " wrangle:dev_1 iPhone\n" + "restrict,pty " + ec + " wrangle:dev_2 iPad\n"
	if got := read(t, p); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed to %v", st.Mode().Perm())
	}
}

func TestRemoveDeletesOnlyThatDevice(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	_ = os.WriteFile(p, []byte("ssh-rsa AAAAB3mine laptop\n"), 0o600)
	_ = Add(p, ec, "dev_1", "iPhone")
	_ = Add(p, ec, "dev_12", "Other")
	removed, err := Remove(p, "dev_1")
	if err != nil || !removed {
		t.Fatalf("%v %v", removed, err)
	}
	if got := read(t, p); got != "ssh-rsa AAAAB3mine laptop\nrestrict,pty "+ec+" wrangle:dev_12 Other\n" {
		t.Fatalf("got %q", got)
	}
	if removed, _ := Remove(p, "dev_1"); removed {
		t.Fatal("second remove must report nothing removed")
	}
	if removed, err := Remove(filepath.Join(t.TempDir(), "none"), "dev_1"); removed || err != nil {
		t.Fatalf("missing file: %v %v", removed, err)
	}
	if !Has(p, "dev_12") || Has(p, "dev_1") {
		t.Fatal("Has is wrong")
	}
}

func TestDefaultPathHonoursOverride(t *testing.T) {
	t.Setenv("WRANGLE_AUTHORIZED_KEYS", "/tmp/e2e/authorized_keys")
	if DefaultPath() != "/tmp/e2e/authorized_keys" {
		t.Fatal(DefaultPath())
	}
	t.Setenv("WRANGLE_AUTHORIZED_KEYS", "")
	if !strings.HasSuffix(DefaultPath(), "/.ssh/authorized_keys") {
		t.Fatal(DefaultPath())
	}
}

func TestAddRejectsInjectionAndSanitisesName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	for _, bad := range []string{
		ed + "\nssh-ed25519 AAAAevil attacker",
		`command="sh" ` + ed,
		"no-pty " + ed,
		"ssh-rsa AAAAB3NzaC1yc2E",
		"ssh-ed25519 not*base64",
		"",
	} {
		if err := Add(p, bad, "dev_1", "x"); !errors.Is(err, ErrBadKey) {
			t.Fatalf("%q: want ErrBadKey, got %v", bad, err)
		}
	}
	for _, id := range []string{"dev_1 x", "dev_1\n", "host_1", ""} {
		if err := Add(p, ed, id, "x"); !errors.Is(err, ErrBadID) {
			t.Fatalf("%q: want ErrBadID, got %v", id, err)
		}
	}
	if err := Add(p, ed, "dev_1", "Alex's\niPhone\x1b[31m"+strings.Repeat("x", 100)); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "restrict,pty "+ed+" wrangle:dev_1 Alex's iPhone[31m") {
		t.Fatalf("got %q", got)
	}
	name := strings.TrimSuffix(strings.SplitN(got, "wrangle:dev_1 ", 2)[1], "\n")
	if len([]rune(name)) != 64 {
		t.Fatalf("name must be cut to 64 runes, got %d", len([]rune(name)))
	}
}

func TestAddKeepsSymlinkedAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "dotfiles", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("ssh-rsa AAAAB3mine laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "authorized_keys")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := Add(link, ec, "dev_1", "iPhone"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced: %v %v", st, err)
	}
	if got := read(t, real); got != "ssh-rsa AAAAB3mine laptop\nrestrict,pty "+ec+" wrangle:dev_1 iPhone\n" {
		t.Fatalf("target got %q", got)
	}
	if removed, err := Remove(link, "dev_1"); err != nil || !removed {
		t.Fatalf("%v %v", removed, err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced by Remove")
	}
}

func TestDeviceNameCannotImpersonateAnotherDevice(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	_ = Add(p, ec, "dev_1", "iPhone")
	_ = Add(p, ed, "dev_2", "wrangle:dev_1")
	if removed, err := Remove(p, "dev_1"); err != nil || !removed {
		t.Fatalf("%v %v", removed, err)
	}
	if got := read(t, p); got != "restrict,pty "+ed+" wrangle:dev_2 wrangle:dev_1\n" {
		t.Fatalf("got %q", got)
	}
	if Has(p, "dev_1") || !Has(p, "dev_2") {
		t.Fatal("Has matched the name instead of the marker")
	}
}

// Separate lockers (as `wrangle serve` and `wrangle remove-device` are separate processes) each take the
// enrolment lock around their edit; no edit is lost and the user's own key survives.
func TestConcurrentLockedEditsLoseNothing(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "wrangle")
	p := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(p, []byte("ssh-rsa AAAAB3mine laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			unlock, err := config.Lock(home)
			if err != nil {
				errs <- err
				return
			}
			defer unlock()
			errs <- Add(p, ed, fmt.Sprintf("dev_%d", i), "iPhone")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got := read(t, p)
	if !strings.HasPrefix(got, "ssh-rsa AAAAB3mine laptop\n") || strings.Count(got, "\n") != n+1 {
		t.Fatalf("lost an edit:\n%s", got)
	}
	ids, err := DeviceIDs(p)
	if err != nil || len(ids) != n {
		t.Fatalf("ids %v %v", ids, err)
	}
}

func TestWritesLeaveNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	if err := Add(p, ed, "dev_1", "iPhone"); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(p, "dev_1"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "authorized_keys" {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestADanglingSymlinkIsRefusedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "authorized_keys")
	if err := os.Symlink(filepath.Join(dir, "gone", "authorized_keys"), link); err != nil {
		t.Fatal(err)
	}
	if err := Add(link, ed, "dev_1", "iPhone"); !errors.Is(err, ErrDanglingLink) {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Remove(link, "dev_1"); !errors.Is(err, ErrDanglingLink) {
		t.Fatalf("Remove: %v", err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", st, err)
	}
}

func TestDeviceIDsListsOnlyWrangleLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	body := "ssh-rsa AAAAB3mine wrangle:dev_fake\nrestrict,pty " + ed + " wrangle:dev_a iPhone\nrestrict,pty " + ec + " wrangle:dev_b iPad\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := DeviceIDs(p)
	if err != nil || strings.Join(ids, ",") != "dev_a,dev_b" {
		t.Fatalf("%v %v", ids, err)
	}
	if ids, err := DeviceIDs(filepath.Join(t.TempDir(), "missing")); err != nil || len(ids) != 0 {
		t.Fatalf("missing file: %v %v", ids, err)
	}
}
