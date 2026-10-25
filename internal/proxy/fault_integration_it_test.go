//go:build integration

package proxy

import "testing"

func TestPlantedFaultIntegration(t *testing.T) {
	t.Fatal("planted fault for C14")
}
