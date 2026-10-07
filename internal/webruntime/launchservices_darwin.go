package webruntime

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// lsregister is the fixed system path; it is never looked up through PATH.
const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

// unregisterApp removes a Chrome for Testing .app and the helper apps nested
// in its framework from LaunchServices. Launching CfT registers them (the
// main app for http, https and file); the records would otherwise outlive
// the helper and the files. lsregister -u also accepts a path already gone.
func unregisterApp(app string) {
	if app == "" {
		return
	}
	paths := []string{}
	nested, _ := filepath.Glob(filepath.Join(app, "Contents", "Frameworks", "*.framework", "Versions", "*", "Helpers", "*.app"))
	for _, p := range nested {
		if !strings.Contains(p, string(filepath.Separator)+"Current"+string(filepath.Separator)) {
			paths = append(paths, p)
		}
	}
	paths = append(paths, app)
	_ = exec.Command(lsregister, append([]string{"-u"}, paths...)...).Run()
}
