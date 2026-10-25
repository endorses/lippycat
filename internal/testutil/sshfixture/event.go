// Package sshfixture supplies bounded ordered SSH handshake metadata for wire,
// query and output tests. Generated packet fixtures live in eventfixture.
package sshfixture

import (
	"github.com/endorses/lippycat/internal/pkg/events"
	"net/netip"
	"time"
)

func Event() events.SSHEvent {
	env := events.Envelope{Timestamp: time.Unix(1700000000, 123).UTC(), NodeID: "ssh-sensor", ProducerSessionID: "ssh-session", EventSequence: 2, UID: "Cssh", CommunityID: "1:ssh", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("198.51.100.2"), SourcePort: 40022, DestinationPort: 2222}, CaptureScope: events.CaptureScopeFull, Provenance: events.SourceProvenance{CaptureSource: "pcap", InterfaceName: "ssh.pcap", InputFile: "ssh.pcap", ProcessorNodeIDs: []string{"relay"}}}
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, env.EventSequence)
	e := events.NewSSHEvent(env)
	e.Role, e.RoleEvidence, e.Status, e.Reason = events.SSHRoleClient, events.SSHRoleEvidenceTCPSYN, events.SSHStatusComplete, events.SSHReasonKEXComplete
	e.Banner, e.ProtocolVersion, e.SoftwareVersion = "SSH-2.0-OpenSSH_9.9 test", "2.0", "OpenSSH_9.9"
	e.KEXAlgorithms, e.ServerHostKeyAlgorithms = "curve25519-sha256,ext-info-c", "ssh-ed25519"
	e.EncryptionClientServer, e.EncryptionServerClient = "aes128-ctr", "aes256-ctr"
	e.MACClientServer, e.MACServerClient = "hmac-sha2-256", "hmac-sha2-512"
	e.CompressionClientServer, e.CompressionServerClient = "none", "zlib@openssh.com,none"
	e.HASSH = "cafb69eb1dbb2a4a505b5b25342a4940"
	e.HASSHAlgorithms = "curve25519-sha256,ext-info-c;aes128-ctr;hmac-sha2-256;none"
	e.HASSHVersion = "1.0"
	return e
}
