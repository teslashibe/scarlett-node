package localfs

// CheckDir already verifies the current-user owner, private ACL and ancestry.
func CheckOwnedDir(path string) error { return CheckDir(path) }
