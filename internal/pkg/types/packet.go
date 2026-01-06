package types

import (
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket/layers"
)

// PacketDisplay represents a packet for display purposes.
// This type is shared between capture, remote capture, and TUI components.
type PacketDisplay struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Length    int
	Info      string
	RawData   []byte          // Raw packet bytes for hex dump
	NodeID    string          // Source node identifier: "Local", hunter_id, or processor_id
	Interface string          // Network interface where packet was captured
	VoIPData  *VoIPMetadata   // Parsed VoIP metadata (nil if not VoIP)
	DNSData   *DNSMetadata    // Parsed DNS metadata (nil if not DNS)
	EmailData *EmailMetadata  // Parsed Email metadata (nil if not email)
	TLSData   *TLSMetadata    // Parsed TLS metadata (nil if not TLS handshake)
	LinkType  layers.LinkType // Link layer type for PCAP writing
}

// VoIPMetadata contains parsed VoIP protocol information.
type VoIPMetadata struct {
	// SIP fields
	CallID      string
	Method      string            // SIP method (INVITE, ACK, etc.)
	Status      int               // SIP response code
	From        string            // SIP From header
	To          string            // SIP To header
	FromTag     string            // SIP From tag parameter (for dialog correlation)
	ToTag       string            // SIP To tag parameter (for dialog correlation)
	User        string            // Username from URI
	ContentType string            // Content-Type header
	Headers     map[string]string // All SIP headers

	// RTP fields
	IsRTP       bool   // Whether this is an RTP packet
	SSRC        uint32 // RTP SSRC
	PayloadType uint8  // RTP payload type
	SequenceNum uint16 // RTP sequence number
	SeqNumber   uint16 // Alias for SequenceNum (for compatibility)
	Timestamp   uint32 // RTP timestamp
	Codec       string // RTP codec (if applicable)
}

// DNSMetadata contains parsed DNS protocol information.
type DNSMetadata struct {
	// Header fields
	TransactionID uint16 // DNS transaction ID for query/response correlation
	IsResponse    bool   // True if response, false if query
	Opcode        string // Operation type (QUERY, IQUERY, STATUS, NOTIFY, UPDATE, DSO)
	ResponseCode  string // Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)

	// Header flags
	Authoritative      bool // AA: Authoritative Answer
	Truncated          bool // TC: Message truncated
	RecursionDesired   bool // RD: Recursion Desired
	RecursionAvailable bool // RA: Recursion Available
	AuthenticatedData  bool // AD: Authenticated Data (DNSSEC)
	CheckingDisabled   bool // CD: Checking Disabled (DNSSEC)

	// Record counts
	QuestionCount   uint16 // Number of questions
	AnswerCount     uint16 // Number of answer records
	AuthorityCount  uint16 // Number of authority records
	AdditionalCount uint16 // Number of additional records

	// Query information (parsed from question section)
	QueryName  string // Queried domain name (e.g., "example.com")
	QueryType  string // Record type (A, AAAA, MX, CNAME, TXT, etc.)
	QueryClass string // Query class (usually IN for Internet)

	// Response information (parsed from answer section)
	Answers []DNSAnswer // Parsed answer records

	// Correlation and timing
	QueryResponseTimeMs int64 // Response latency (only for correlated responses)
	CorrelatedQuery     bool  // True if response was correlated with a query

	// Security analysis
	TunnelingScore float64 // DNS tunneling probability (0.0-1.0)
	EntropyScore   float64 // Entropy of query name (for tunneling detection)
}

// DNSAnswer represents a single DNS answer record.
type DNSAnswer struct {
	Name  string // Domain name
	Type  string // Record type (A, AAAA, CNAME, etc.)
	Class string // Record class (usually IN)
	TTL   uint32 // Time to live in seconds
	Data  string // Answer data (IP address, CNAME target, etc.)
}

// EmailMetadata contains parsed email protocol information (SMTP/IMAP/POP3).
type EmailMetadata struct {
	// Protocol identification
	Protocol string // "SMTP", "IMAP", "POP3"
	IsServer bool   // True if from server, false if from client

	// SMTP envelope (extracted during SMTP transaction)
	MailFrom  string   // MAIL FROM address
	RcptTo    []string // RCPT TO addresses
	Subject   string   // Subject header from DATA
	MessageID string   // Message-ID header for correlation

	// SMTP transaction state
	Command      string // Current command (HELO, EHLO, MAIL, RCPT, DATA, etc.)
	ResponseCode int    // Response code (220, 250, 354, etc.)
	ResponseText string // Response text

	// TLS/Security
	STARTTLSOffered   bool // Server advertised STARTTLS
	STARTTLSRequested bool // Client requested STARTTLS
	Encrypted         bool // Session is encrypted (after STARTTLS)

	// Authentication
	AuthMethod string // AUTH method (PLAIN, LOGIN, CRAM-MD5)
	AuthUser   string // Authenticated username (if available)

	// Session tracking
	SessionID    string    // Unique session identifier (for correlation)
	ServerBanner string    // Initial server banner (220 greeting)
	ClientHelo   string    // HELO/EHLO hostname
	Timestamp    time.Time // Message timestamp

	// Size information
	MessageSize int // SIZE parameter or actual message size

	// Body content (opt-in capture)
	BodyPreview   string // Body preview (limited to configured max size)
	BodySize      int    // Full body size in bytes
	BodyTruncated bool   // True if body was truncated due to size limit

	// Correlation and timing
	TransactionTimeMs int64 // Transaction completion time
	Correlated        bool  // True if response was correlated with command
}

// TLSMetadata contains parsed TLS handshake information.
type TLSMetadata struct {
	// TLS version information
	Version       string // Human-readable version (e.g., "TLS 1.3")
	VersionRaw    uint16 // Raw version bytes (e.g., 0x0303 for TLS 1.2)
	RecordVersion uint16 // Record layer version (may differ from handshake version)

	// Handshake information
	HandshakeType string // "ClientHello", "ServerHello", "Certificate", etc.
	IsServer      bool   // True if ServerHello, false if ClientHello
	SessionID     string // Hex-encoded session ID

	// SNI (Server Name Indication)
	SNI string // Server hostname from ClientHello extension

	// ClientHello data (if ClientHello)
	CipherSuites    []uint16 // Advertised cipher suites
	Extensions      []uint16 // Extension types
	SupportedGroups []uint16 // Elliptic curves / named groups
	SignatureAlgos  []uint16 // Signature algorithms
	ECPointFormats  []uint8  // EC point formats
	ALPNProtocols   []string // ALPN protocols (e.g., ["h2", "http/1.1"])

	// ServerHello data (if ServerHello)
	SelectedCipher uint16 // Selected cipher suite
	Compression    uint8  // Selected compression method

	// JA3/JA3S fingerprinting (client fingerprint)
	JA3String      string // Full JA3 string (version,ciphers,extensions,curves,formats)
	JA3Fingerprint string // MD5 hash of JA3 string

	// JA3S fingerprinting (server fingerprint)
	JA3SString      string // Full JA3S string (version,cipher,extensions)
	JA3SFingerprint string // MD5 hash of JA3S string

	// JA4 fingerprinting (modern TLS fingerprint)
	JA4String      string // Full JA4 string
	JA4Fingerprint string // JA4 fingerprint

	// Session correlation
	FlowKey         string // "srcIP:srcPort-dstIP:dstPort" for correlation
	CorrelatedPeer  bool   // True if matched with ClientHello/ServerHello pair
	HandshakeTimeMs int64  // Time from ClientHello to ServerHello

	// Security analysis
	RiskScore float64 // Risk score 0.0-1.0 (weak ciphers, old versions, etc.)
	RiskFlags int     // Bitmask of specific risk indicators
}

// HunterInfo represents a hunter node's status information.
// This type is shared between processor, remote capture client, and TUI.
type HunterInfo struct {
	ID               string
	Hostname         string
	RemoteAddr       string
	Status           management.HunterStatus
	ConnectedAt      int64
	LastHeartbeat    int64
	PacketsCaptured  uint64
	PacketsMatched   uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	ActiveFilters    uint32
	Interfaces       []string
	ProcessorAddr    string                         // Address of processor this hunter belongs to
	Capabilities     *management.HunterCapabilities // Hunter capabilities (filter types, etc.)
}
