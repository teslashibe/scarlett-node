//go:build unix

package worker

import "os"

func makeSessionPublic(path string) error  { return os.Chmod(path, 0644) }
func makeSessionPrivate(path string) error { return os.Chmod(path, 0600) }
