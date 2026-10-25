package events

const KindSSH Kind = "ssh"

type SSHRole string
type SSHRoleEvidence string
type SSHStatus string
type SSHReason string

const (
	SSHRoleUnknown              SSHRole         = "unknown"
	SSHRoleClient               SSHRole         = "client"
	SSHRoleServer               SSHRole         = "server"
	SSHRoleEvidenceUnknown      SSHRoleEvidence = "unknown"
	SSHRoleEvidenceTCPSYN       SSHRoleEvidence = "tcp_syn"
	SSHRoleEvidenceTCPSYNACK    SSHRoleEvidence = "tcp_synack"
	SSHRoleEvidenceProtocol     SSHRoleEvidence = "protocol"
	SSHRoleEvidenceConflict     SSHRoleEvidence = "conflict"
	SSHStatusBanner             SSHStatus       = "banner"
	SSHStatusComplete           SSHStatus       = "complete"
	SSHStatusPartial            SSHStatus       = "partial"
	SSHReasonNone               SSHReason       = ""
	SSHReasonKEXComplete        SSHReason       = "kex_complete"
	SSHReasonNewKeys            SSHReason       = "newkeys_before_kex"
	SSHReasonUnsupportedVersion SSHReason       = "unsupported_version"
	SSHReasonMalformed          SSHReason       = "malformed"
	SSHReasonResourceLimit      SSHReason       = "resource_limit"
	SSHReasonMissingBanner      SSHReason       = "missing_banner"
	SSHReasonIncomplete         SSHReason       = "incomplete"
	SSHReasonNoKEX              SSHReason       = "no_kex"
	SSHReasonGap                SSHReason       = "gap"
	SSHReasonDisconnect         SSHReason       = "disconnect"
)

// SSHEvent is an immutable observation of one initial cleartext half-handshake.
// Role describes Envelope.Flow.Source; the UID remains shared by both directions.
// Banner snapshots and terminal snapshots have separate delivery identities.
// A complete KEX with unknown endpoint role retains ordered evidence without a
// fingerprint. No authentication, encrypted rekey, or application bytes appear.
type SSHEvent struct {
	eventBase
	Role         SSHRole
	RoleEvidence SSHRoleEvidence
	Status       SSHStatus
	Reason       SSHReason
	Banner       string
	// Escaped banners contain the complete strconv.QuoteToASCII representation,
	// including its quotes, preserving invalid UTF-8/control bytes losslessly.
	BannerEscaped                                    bool
	ProtocolVersion, SoftwareVersion                 string
	KEXAlgorithms, ServerHostKeyAlgorithms           string
	EncryptionClientServer, EncryptionServerClient   string
	MACClientServer, MACServerClient                 string
	CompressionClientServer, CompressionServerClient string
	LanguagesClientServer, LanguagesServerClient     string
	FirstKEXPacketFollows                            bool
	HASSH, HASSHAlgorithms, HASSHVersion             string
}

func NewSSHEvent(env Envelope) SSHEvent {
	return SSHEvent{eventBase: eventBase{env}, Role: SSHRoleUnknown, RoleEvidence: SSHRoleEvidenceUnknown, Status: SSHStatusBanner}
}
func (SSHEvent) Kind() Kind   { return KindSSH }
func (SSHEvent) eventMarker() {}
func (e SSHEvent) Clone() SSHEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	return e
}
