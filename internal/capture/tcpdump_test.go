package capture

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Edge case (spec.md): "IF tcpdump is unavailable THEN the system SHALL fall
// back to the in-process gopacket backend." Tested at the selection-logic
// level so it never depends on whether tcpdump is actually installed.
func TestBackendFor_FallsBackWhenTcpdumpUnavailable(t *testing.T) {
	found := func(string) (string, error) { return "/usr/bin/tcpdump", nil }
	notFound := func(string) (string, error) { return "", errors.New("not found") }

	assert.Equal(t, "tcpdump", backendFor(found), "tcpdump on PATH must be selected")
	assert.Equal(t, "gopacket", backendFor(notFound), "missing tcpdump must fall back to gopacket")
}
