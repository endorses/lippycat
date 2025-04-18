package voip

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

func handleUdpPackets(pkt capture.PacketInfo, layer *layers.UDP) {
	packet := pkt.Packet
	if layer.SrcPort == 5060 || layer.DstPort == 5060 {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			payload := udp.Payload
			if !handleSipMessage(payload) {
				return
			}
			headers, body := parseSipHeaders(payload)
			callID := headers["call-id"]
			if callID != "" {
				GetOrCreateCall(callID, pkt.LinkType)
				if viper.GetViper().GetBool("writeVoip") {
					WriteSIP(callID, packet)
				} else {
					fmt.Printf("[%s]%s\n", callID, packet)
				}
				if strings.Contains(body, "m=audio") {
					ExtractPortFromSdp(body, callID)
				}
			}
		}
	} else if IsTracked(packet) {
		callID := GetCallIDForPacket(packet)
		// fmt.Println("caught tracked packet, callid", callID)
		if viper.GetViper().GetBool("writeVoip") {
			WriteRTP(callID, packet)
		} else {
			fmt.Printf("[%s]%s\n", callID, packet)
		}
	}
}

// func extractCallIDFromUDP(packet gopacket.Packet) string {
// 	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
// 		udp, _ := udpLayer.(*layers.UDP)
// 		// payload := udp.Payload
// 		return (extractCallIDFromPayload(udp.Payload))
// 	}
// 	return ""
// }

// func extractCallIDFromPayload(payload gopacket.Payload) string {
// 	text := string(payload)
// 	lines := strings.Split(text, "\n")
// 	for _, line := range lines {
// 		if strings.HasPrefix(strings.ToLower(line), "call-id:") {
// 			callID := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
// 			return string(callID)
// 		}
// 	}
// 	return ""
// }
