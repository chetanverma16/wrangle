package qrterm

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestRenderFitsEightyColumnsWithExplicitColours(t *testing.T) {
	text := "wrangle://pair?v=1&r=aHR0cHM6Ly9hcGkud3JhbmdsZS5zdGFja2ZyYW1lcy5kZXY&o=off_AbCdEfGhIjKlMnOp&t=EBESExQVFhcYGRobHB0eHw&k=ICEiIyQlJicoKSorLC0uLw&h=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A&n=Q2hldGFuJ3MgTWFjQm9vayBQcm8"
	out, err := Render(text)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 20 {
		t.Fatalf("too few lines: %d", len(lines))
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, "\x1b[30;47m") || !strings.HasSuffix(l, "\x1b[0m") {
			t.Fatalf("line %d lacks explicit colours: %q", i, l)
		}
		plain := ansi.ReplaceAllString(l, "")
		if w := utf8.RuneCountInString(plain); w > 80 || w != utf8.RuneCountInString(ansi.ReplaceAllString(lines[0], "")) {
			t.Fatalf("line %d width %d", i, w)
		}
		if strings.Trim(plain, " █▀▄") != "" {
			t.Fatalf("line %d has other characters: %q", i, plain)
		}
	}
	// Line 0 is the quiet zone. Line 1 holds QR rows 0 and 1: the finder's top edge over its hollow second row.
	if strings.TrimSpace(ansi.ReplaceAllString(lines[0], "")) != "" {
		t.Fatalf("line 0 must be blank: %q", lines[0])
	}
	if !strings.HasPrefix(ansi.ReplaceAllString(lines[1], ""), "  █▀▀▀▀▀█") {
		t.Fatalf("no finder pattern on line 1: %q", lines[1])
	}
}
