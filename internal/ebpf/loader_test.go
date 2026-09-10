package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UT-01.5: default config carries the compiled-in constants and a bpffs pin dir.
func TestDefaultConfig_Constants(t *testing.T) {
	c := DefaultConfig()
	assert.Equal(t, uint32(1337), c.ProxyUID)
	assert.Equal(t, uint16(15001), c.ProxyPort)
	assert.Contains(t, c.PinDir, "/sys/fs/bpf")
}

// UT-01.5: validation rejects unsafe/invalid configuration.
func TestConfig_Validate(t *testing.T) {
	base := func() Config {
		c := DefaultConfig()
		c.CgroupPath = "/sys/fs/cgroup"
		return c
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, base().Validate())
	})
	t.Run("empty cgroup rejected", func(t *testing.T) {
		c := base()
		c.CgroupPath = ""
		assert.Error(t, c.Validate())
	})
	t.Run("uid 0 rejected", func(t *testing.T) {
		c := base()
		c.ProxyUID = 0
		assert.ErrorContains(t, c.Validate(), "ProxyUID")
	})
	t.Run("port 0 rejected", func(t *testing.T) {
		c := base()
		c.ProxyPort = 0
		assert.ErrorContains(t, c.Validate(), "ProxyPort")
	})
	t.Run("pin dir outside bpffs rejected", func(t *testing.T) {
		c := base()
		c.PinDir = "/tmp/pins"
		assert.ErrorContains(t, c.Validate(), "under /sys/fs/bpf")
	})
}
