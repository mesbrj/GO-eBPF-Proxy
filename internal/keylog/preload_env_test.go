package keylog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// UT-02.7: PreloadEnv emits exactly the two expected KEY=VALUE strings, in
// order, and no others.
func TestPreloadEnv_ExactlyTwoExpectedVars(t *testing.T) {
	got := PreloadEnv("/opt/preload/libkeylogpreload.so", "/run/sidecar/keylog.sock")

	assert.Equal(t, []string{
		"LD_PRELOAD=/opt/preload/libkeylogpreload.so",
		"GOEBPF_PRELOAD_SOCKET=/run/sidecar/keylog.sock",
	}, got)
	assert.Len(t, got, 2, "must emit exactly two env vars, no more, no fewer")
}
