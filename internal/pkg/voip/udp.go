package voip

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

func handleUdpPackets(pkt capture.PacketInfo, layer *layers.UDP) {
	packet := pkt.Packet
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				logger.Debug("Failed to assert UDP layer type")
				return
			}
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
		if viper.GetViper().GetBool("writeVoip") {
			WriteRTP(callID, packet)
		} else {
			fmt.Printf("[%s]%s\n", callID, packet)
		}
	}
}
