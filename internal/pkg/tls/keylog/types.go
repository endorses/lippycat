//go:build cli || hunter || tap || all

// Package keylog provides parsing and storage for TLS session keys
// in the NSS Key Log format (SSLKEYLOGFILE).
//
// The NSS Key Log format is used by browsers (Chrome, Firefox) and other
// TLS implementations to log pre-master secrets and session keys for
// passive decryption. This is the same format used by Wireshark.
//
// Format: <label> <client_random_hex> <secret_hex>
//
// TLS 1.2 and earlier:
//   - CLIENT_RANDOM: Pre-master secret
//
// TLS 1.3:
//   - CLIENT_HANDSHAKE_TRAFFIC_SECRET: Client handshake encryption
//   - SERVER_HANDSHAKE_TRAFFIC_SECRET: Server handshake encryption
//   - CLIENT_TRAFFIC_SECRET_0: Client application data encryption
//   - SERVER_TRAFFIC_SECRET_0: Server application data encryption
//   - EXPORTER_SECRET: Key export material
//   - EARLY_EXPORTER_SECRET: 0-RTT key export material
package keylog

// LabelType represents the type of TLS key log entry.
type LabelType int

const (
	// LabelUnknown indicates an unrecognized label.
	LabelUnknown LabelType = iota

	// TLS 1.2 and earlier

	// LabelClientRandom is the pre-master secret for TLS 1.2 and earlier.
	// Format: CLIENT_RANDOM <32-byte client_random> <48-byte premaster_secret>
	LabelClientRandom

	// TLS 1.3

	// LabelClientHandshakeTrafficSecret is the client handshake traffic secret.
	// Used to decrypt client handshake messages after ServerHello.
	LabelClientHandshakeTrafficSecret

	// LabelServerHandshakeTrafficSecret is the server handshake traffic secret.
	// Used to decrypt server handshake messages after ServerHello.
	LabelServerHandshakeTrafficSecret

	// LabelClientTrafficSecret0 is the initial client application traffic secret.
	// Used to decrypt client application data.
	LabelClientTrafficSecret0

	// LabelServerTrafficSecret0 is the initial server application traffic secret.
	// Used to decrypt server application data.
	LabelServerTrafficSecret0

	// LabelExporterSecret is the exporter master secret.
	// Used for deriving keying material for application-level protocols.
	LabelExporterSecret

	// LabelEarlyExporterSecret is the early exporter secret for 0-RTT.
	LabelEarlyExporterSecret

	// LabelClientEarlyTrafficSecret is the client early traffic secret for 0-RTT.
	LabelClientEarlyTrafficSecret
)

// String returns the NSS key log format label string.
func (l LabelType) String() string {
	switch l {
	case LabelClientRandom:
		return "CLIENT_RANDOM"
	case LabelClientHandshakeTrafficSecret:
		return "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	case LabelServerHandshakeTrafficSecret:
		return "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	case LabelClientTrafficSecret0:
		return "CLIENT_TRAFFIC_SECRET_0"
	case LabelServerTrafficSecret0:
		return "SERVER_TRAFFIC_SECRET_0"
	case LabelExporterSecret:
		return "EXPORTER_SECRET"
	case LabelEarlyExporterSecret:
		return "EARLY_EXPORTER_SECRET"
	case LabelClientEarlyTrafficSecret:
		return "CLIENT_EARLY_TRAFFIC_SECRET"
	default:
		return "UNKNOWN"
	}
}

// IsTLS13 returns true if this label is for TLS 1.3 secrets.
func (l LabelType) IsTLS13() bool {
	switch l {
	case LabelClientHandshakeTrafficSecret,
		LabelServerHandshakeTrafficSecret,
		LabelClientTrafficSecret0,
		LabelServerTrafficSecret0,
		LabelExporterSecret,
		LabelEarlyExporterSecret,
		LabelClientEarlyTrafficSecret:
		return true
	default:
		return false
	}
}

// ParseLabel parses a label string into a LabelType.
func ParseLabel(s string) LabelType {
	switch s {
	case "CLIENT_RANDOM":
		return LabelClientRandom
	case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		return LabelClientHandshakeTrafficSecret
	case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
		return LabelServerHandshakeTrafficSecret
	case "CLIENT_TRAFFIC_SECRET_0":
		return LabelClientTrafficSecret0
	case "SERVER_TRAFFIC_SECRET_0":
		return LabelServerTrafficSecret0
	case "EXPORTER_SECRET":
		return LabelExporterSecret
	case "EARLY_EXPORTER_SECRET":
		return LabelEarlyExporterSecret
	case "CLIENT_EARLY_TRAFFIC_SECRET":
		return LabelClientEarlyTrafficSecret
	default:
		return LabelUnknown
	}
}

// KeyEntry represents a single entry from a TLS key log file.
type KeyEntry struct {
	// Label identifies the type of secret.
	Label LabelType

	// ClientRandom is the 32-byte client random value from the TLS handshake.
	// This is used to correlate the key entry with a TLS session.
	ClientRandom [32]byte

	// Secret is the actual secret value.
	// Length varies by label type:
	// - CLIENT_RANDOM (TLS 1.2): 48 bytes (pre-master secret)
	// - TLS 1.3 secrets: 32 or 48 bytes depending on cipher suite hash
	Secret []byte
}

// ClientRandomHex returns the client random as a hex string.
func (e *KeyEntry) ClientRandomHex() string {
	return bytesToHex(e.ClientRandom[:])
}

// SecretHex returns the secret as a hex string.
func (e *KeyEntry) SecretHex() string {
	return bytesToHex(e.Secret)
}

// bytesToHex converts bytes to lowercase hex string.
func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// SessionKeys holds all keys for a TLS session, indexed by client random.
type SessionKeys struct {
	// ClientRandom is the session identifier.
	ClientRandom [32]byte

	// TLS 1.2 and earlier
	PreMasterSecret []byte // CLIENT_RANDOM entry

	// TLS 1.3
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ClientTrafficSecret0         []byte
	ServerTrafficSecret0         []byte
	ExporterSecret               []byte
	EarlyExporterSecret          []byte
	ClientEarlyTrafficSecret     []byte
}

// IsTLS13 returns true if this session has TLS 1.3 keys.
func (s *SessionKeys) IsTLS13() bool {
	return len(s.ClientTrafficSecret0) > 0 || len(s.ServerTrafficSecret0) > 0
}

// IsTLS12 returns true if this session has TLS 1.2 (or earlier) keys.
func (s *SessionKeys) IsTLS12() bool {
	return len(s.PreMasterSecret) > 0
}

// HasDecryptionKeys returns true if this session has keys needed for decryption.
func (s *SessionKeys) HasDecryptionKeys() bool {
	// TLS 1.2: need pre-master secret
	if len(s.PreMasterSecret) > 0 {
		return true
	}
	// TLS 1.3: need at least traffic secrets
	return len(s.ClientTrafficSecret0) > 0 && len(s.ServerTrafficSecret0) > 0
}

// AddEntry adds a key entry to this session.
func (s *SessionKeys) AddEntry(entry *KeyEntry) {
	switch entry.Label {
	case LabelClientRandom:
		s.PreMasterSecret = entry.Secret
	case LabelClientHandshakeTrafficSecret:
		s.ClientHandshakeTrafficSecret = entry.Secret
	case LabelServerHandshakeTrafficSecret:
		s.ServerHandshakeTrafficSecret = entry.Secret
	case LabelClientTrafficSecret0:
		s.ClientTrafficSecret0 = entry.Secret
	case LabelServerTrafficSecret0:
		s.ServerTrafficSecret0 = entry.Secret
	case LabelExporterSecret:
		s.ExporterSecret = entry.Secret
	case LabelEarlyExporterSecret:
		s.EarlyExporterSecret = entry.Secret
	case LabelClientEarlyTrafficSecret:
		s.ClientEarlyTrafficSecret = entry.Secret
	}
}
