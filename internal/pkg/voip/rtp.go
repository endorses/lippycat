package voip

import (
	"strings"
	"sync"

	"github.com/google/gopacket"
)

var (
	portToCallID = make(map[string]string) // key = port, value = CallID
	portMu       sync.Mutex
)

func ExtractPortFromSdp(line string, callID string) {
	_, partThatContainsPort, hasPort := strings.Cut(line, "m=audio")
	if !hasPort {
		return
	}
	parts := strings.Fields(partThatContainsPort)
	if len(parts) >= 1 {
		portMu.Lock()
		defer portMu.Unlock()
		port := parts[0]
		portToCallID[port] = callID
	}
}

func IsTracked(packet gopacket.Packet) bool {
	dst := packet.TransportLayer().TransportFlow().Dst().String()
	src := packet.TransportLayer().TransportFlow().Src().String()
	portMu.Lock()
	defer portMu.Unlock()
	_, dstOk := portToCallID[dst]
	_, srcOk := portToCallID[src]
	return dstOk || srcOk
}

func GetCallIDForPacket(packet gopacket.Packet) string {
	dst := packet.TransportLayer().TransportFlow().Dst().String()
	portMu.Lock()
	defer portMu.Unlock()
	portDst := portToCallID[dst]
	return portDst
}
