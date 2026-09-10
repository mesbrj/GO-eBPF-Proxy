//go:build integration

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sockops re-key behaviour (cookie->tuple, IT-01.5/01.6) requires a live
// socket + cookie and is verified end-to-end in Feature 03. Here we confirm the
// program compiles, passes the kernel verifier, and has the correct type.
func TestSockops_LoadsWithCorrectType(t *testing.T) {
	objs := loadOrSkip(t)
	require.NotNil(t, objs.SockopsProg)
	assert.Equal(t, ebpf.SockOps, objs.SockopsProg.Type())
}
