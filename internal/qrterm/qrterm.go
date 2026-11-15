// Package qrterm prints a QR code in a terminal with half-block characters.
package qrterm

import (
	"strings"

	"rsc.io/qr"
)

const quiet = 2 // modules of white border; scanners need some

// Render draws two QR rows per text line. Colours are explicit (black on white), so it scans on dark and light themes.
func Render(text string) (string, error) {
	c, err := qr.Encode(text, qr.L)
	if err != nil {
		return "", err
	}
	n := c.Size + 2*quiet
	black := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("\x1b[30;47m")
		for x := 0; x < n; x++ {
			top, bottom := black(x, y), black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}
