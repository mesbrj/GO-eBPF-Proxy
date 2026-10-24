package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// errKeylogNotTmpfs marks a keylog directory whose filesystem is not tmpfs.
var errKeylogNotTmpfs = errors.New("not on tmpfs")

// checkKeylogTmpfs refuses a keylog file whose directory is not on tmpfs
// (statfs f_type TMPFS_MAGIC). The keylog is one of the only two places TLS
// keys may rest, and the one that must never reach a disk-backed filesystem
// (AD-006, AD-023). While that directory does not exist yet -- keylog.NewWriter
// creates it -- its nearest existing ancestor is checked instead: that is the
// filesystem it will be created on. The check only reads; it creates nothing.
func checkKeylogTmpfs(keylogPath string) error {
	keylogDir := filepath.Dir(keylogPath)
	dir := keylogDir
	var st unix.Statfs_t
	for {
		err := unix.Statfs(dir, &st)
		if err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if !errors.Is(err, unix.ENOENT) || parent == dir {
			return fmt.Errorf("app: statfs keylog directory %q: %w", dir, err)
		}
		dir = parent
	}
	if st.Type == unix.TMPFS_MAGIC {
		return nil
	}
	where := fmt.Sprintf("%q", keylogDir)
	if dir != keylogDir {
		where += fmt.Sprintf(" (not created yet; its nearest existing ancestor is %q)", dir)
	}
	return fmt.Errorf("app: keylog directory %s is %w: statfs f_type %#x, want %#x", where, errKeylogNotTmpfs, st.Type, unix.TMPFS_MAGIC)
}
