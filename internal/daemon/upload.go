package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"github.com/chetanverma16/wrangle/internal/hookio"
)

// uploadName is the only name the iPhone gives a picture it sends: <UUID>.png.
var uploadName = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\.png$`)

// readsPhoneUpload reports whether this is Claude asking to Read a picture the phone uploaded: the exact clean path
// ~/.wrangle/uploads/<UUID>.png, and a regular file there (not a link to somewhere else). The person picked that
// picture on the phone and sent its path, so asking them again would only be noise.
func readsPhoneUpload(req hookio.Request) bool {
	if req.Agent != "claude" || req.Event != "permission" {
		return false
	}
	var in struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			FilePath string `json:"file_path"`
		} `json:"tool_input"`
	}
	if json.Unmarshal(req.Payload, &in) != nil || in.ToolName != "Read" {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	path := in.ToolInput.FilePath
	if path != filepath.Clean(path) || filepath.Dir(path) != filepath.Join(home, ".wrangle", "uploads") || !uploadName.MatchString(filepath.Base(path)) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
