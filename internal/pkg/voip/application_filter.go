//go:build hunter || tap || all

package voip

import "github.com/google/gopacket"

// ApplicationFilter provides application-layer packet filtering. It is
// implemented by hunter.ApplicationFilter but declared here to avoid an
// import cycle (voip cannot import hunter).
//
// It lives in its own file under a hunter||tap||all build tag because both
// the hunter packet handlers (udp_handler_hunter.go, tcp_handler_hunter.go,
// voip_packet_processor.go — hunter||all) and the tap packet handlers
// (tcp_handler_tap.go — tap||all) depend on it. Defining it in a
// hunter||all file alone broke the standalone tap build.
type ApplicationFilter interface {
	// MatchPacket checks if a packet matches any filter.
	// Returns true if no filters are configured (promiscuous mode) OR if a match is found.
	MatchPacket(packet gopacket.Packet) bool
}
