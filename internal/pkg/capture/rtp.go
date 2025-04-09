package capture

import (
	"strings"

	"github.com/google/gopacket"
)

var portToCallID = make(map[string]string) // key = port, value = CallID

func ExtractPortFromSDP(line string, callID string) {
	_, partThatContainsPort, hasPort := strings.Cut(line, "m=audio")
	if hasPort != true {
		return
	}
	parts := strings.Fields(partThatContainsPort)
	if len(parts) >= 1 {
		port := parts[0]
		portToCallID[port] = callID
	}
}

func IsTracked(packet gopacket.Packet) bool {
	dst := packet.TransportLayer().TransportFlow().Dst().String()
	src := packet.TransportLayer().TransportFlow().Src().String()
	_, dstOk := portToCallID[dst]
	_, srcOk := portToCallID[src]
	return dstOk || srcOk
}

func GetCallIDForPacket(packet gopacket.Packet) string {
	dst := packet.TransportLayer().TransportFlow().Dst().String()
	return portToCallID[dst]
}
