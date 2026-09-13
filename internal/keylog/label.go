package keylog

// Label identifies which NSS keylog line a secret belongs to.
//
// SPEC_DEVIATION: AD-010 removes event.go's ring-buffer secret_event codec
// (DecodeEvent/SecretEvent/secretEventSize), but nss.go/nss_test.go/
// writer_test.go (all required to stay unchanged) still depend on this Label
// type and its constants for Classify/FormatLine. Kept as its own minimal
// file rather than folded into nss.go, so nss.go's content stays byte-for-
// byte untouched per T1's Done-when.
type Label uint16

// Label values mirror the NSS keylog line names; see internal/keylog/nss.go.
const (
	LabelClientRandom Label = iota // TLS 1.2 "CLIENT_RANDOM" (48-byte master secret)
	LabelClientHandshakeTrafficSecret
	LabelServerHandshakeTrafficSecret
	LabelClientTrafficSecret0
	LabelServerTrafficSecret0
	LabelExporterSecret
)
