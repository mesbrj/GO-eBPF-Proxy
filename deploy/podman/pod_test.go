// Package podman holds the tests of the rootful Podman harness.
package podman

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C43 (Surface: pod-up.sh exit 1): METRICS_ENDPOINT changes nothing about the
// script's root check, which still refuses a non-root user before it touches
// podman.
func TestPodUp_NonRootStillExitsOneWithMetricsEndpoint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the root check passes")
	}
	up := exec.Command("./pod-up.sh")
	up.Env = append(os.Environ(), "METRICS_ENDPOINT=http://192.0.2.1:4318")

	out, err := up.CombinedOutput()

	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "pod-up.sh must exit with a status; output: %s", out)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, string(out), "must run as root")
}
