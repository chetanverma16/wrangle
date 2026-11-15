package install

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func servicePath(p Paths) string {
	if p.GOOS == "darwin" {
		return filepath.Join(p.ServiceDir, "com.stackframe.wrangle.plist")
	}
	return filepath.Join(p.ServiceDir, "wrangle.service")
}

func writeService(p Paths, bin string) (string, error) {
	var body string
	if p.GOOS == "darwin" {
		body = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.stackframe.wrangle</string>
  <key>ProgramArguments</key><array><string>%s</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>%s</string>
%s</dict></plist>
`, xmlEscape(bin), xmlEscape(logPath(p)), plistEnv(p.CodexHome))
	} else {
		body = fmt.Sprintf("[Unit]\nDescription=Wrangle helper\nAfter=network-online.target\n\n[Service]\nExecStart=%s serve\n%sRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n", bin, unitEnv(p.CodexHome))
	}
	if p.GOOS == "darwin" {
		if err := os.MkdirAll(filepath.Dir(logPath(p)), 0o700); err != nil {
			return "", err
		}
	}
	path := servicePath(p)
	if err := os.MkdirAll(p.ServiceDir, 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(body), 0o644)
}

func removeService(p Paths) error {
	if p.ServiceDir == "" {
		return nil
	}
	err := os.Remove(servicePath(p))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// logPath keeps logs under the Wrangle home (private), never in a shared directory like /tmp.
func logPath(p Paths) string {
	home := p.WrangleHome
	if home == "" {
		home = filepath.Dir(p.Backup)
	}
	return filepath.Join(home, "serve.log")
}

// plistEnv and unitEnv carry CODEX_HOME into the service, so `wrangle serve` reads the same Codex sessions as
// Codex itself. An unset CODEX_HOME writes no environment entry.
func plistEnv(codexHome string) string {
	if codexHome == "" {
		return ""
	}
	return "  <key>EnvironmentVariables</key><dict><key>CODEX_HOME</key><string>" + xmlEscape(codexHome) + "</string></dict>\n"
}

// unitEnv quotes the whole assignment (systemd's documented form), escaping `\` and `"`, and doubles `%` so
// systemd doesn't read it as a specifier.
func unitEnv(codexHome string) string {
	if codexHome == "" {
		return ""
	}
	v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace("CODEX_HOME=" + codexHome)
	return `Environment="` + v + "\"\n"
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
