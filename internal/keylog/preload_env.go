package keylog

// PreloadEnv returns the exact env-var strings the app container needs to
// load the LD_PRELOAD keylog interposer: LD_PRELOAD pointing at soPath and
// GOEBPF_PRELOAD_SOCKET pointing at socketPath, in that order, and no others.
func PreloadEnv(soPath, socketPath string) []string {
	return []string{
		"LD_PRELOAD=" + soPath,
		"GOEBPF_PRELOAD_SOCKET=" + socketPath,
	}
}
