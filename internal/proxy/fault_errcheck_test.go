package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFaultErrcheck(t *testing.T) {
	os.Remove(filepath.Join(t.TempDir(), "planted-fault"))
}
