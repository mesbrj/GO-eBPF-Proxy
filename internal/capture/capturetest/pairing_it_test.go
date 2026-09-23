//go:build integration

package capturetest

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A failed tshark run must say why: the bare exit status ("exit status 2")
// says nothing about which argument tshark rejected, while its stderr does.
func TestDecryptedAppData_FailureCarriesTsharkStderr(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert its failure output")
	}

	missing := filepath.Join(t.TempDir(), "missing.pcapng")
	_, err := DecryptedAppData(t.Context(), missing, "", AppDataFilter)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing.pcapng", "the error must carry tshark's own diagnosis, not just its exit status")
}
