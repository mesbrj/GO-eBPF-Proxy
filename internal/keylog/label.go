package keylog

// Label identifies which NSS keylog line a secret belongs to.
type Label uint16

// Label values mirror the NSS keylog line names; see labelName in
// internal/keylog/nss.go.
const (
	LabelClientRandom Label = iota // TLS 1.2 "CLIENT_RANDOM" (48-byte master secret)
	LabelClientHandshakeTrafficSecret
	LabelServerHandshakeTrafficSecret
	LabelClientTrafficSecret0
	LabelServerTrafficSecret0
	LabelExporterSecret
)
