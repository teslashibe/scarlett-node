//go:build webbrowser_live

package webruntime

import "runtime"

func runtimeGOOS() string { return runtime.GOOS }
