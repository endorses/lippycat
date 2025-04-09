package sniff

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/spf13/cobra"
)

var voipCmd = &cobra.Command{
	Use:   "voip",
	Short: "Sniff in VOIP mode",
	Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
	Run:   voipHandler,
}

var (
	sipusers []string
	sipuser  string
)

func voipHandler(cmd *cobra.Command, args []string) {
	for _, user := range strings.Split(sipuser, ",") {
		sipusers = append(sipusers, user)
	}

	fmt.Println("Sniffing Voip")

	streamFactory := NewSIPStreamFactory(sipusers)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	capture.Init(strings.Split(interfaces, ","), filter, StartProcessor, assembler)
}

type sipStreamFactory struct {
	targets []string
}

func NewSIPStreamFactory(usernames []string) tcpassembly.StreamFactory {
	return &sipStreamFactory{targets: usernames}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processSIPStream(&r, f.targets)
	return &r
}

func StartProcessor(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	defer capture.CloseWriters()
	fmt.Println("Starting Processor")

	for pkt := range ch {

		packet := pkt.Packet
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			continue
		}

		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			if layer.SrcPort == 5060 || layer.DstPort == 5060 {

				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					payload := tcp.Payload
					if HandleSIPMessage(payload, sipusers) == false {
						continue
					}
					callID := extractCallID(packet)
					if callID != "" {
						// fmt.Println("Call-ID:", callID)
						capture.WriteSIP(callID, packet)
						// _, body := capture.ParseSIPHeaders(payload)
						// if strings.Contains(body, "m=audio") {
						// 	fmt.Println("Extracting Port")
						// 	capture.ExtractPortFromSDP(body, callID)
						// }
					}
					capture.UpdateCallState(callID, "TCP-SIP", pkt.LinkType)
					assembler.AssembleWithTimestamp(
						packet.NetworkLayer().NetworkFlow(),
						layer,
						packet.Metadata().Timestamp,
					)
				}
			}
		case *layers.UDP:
			if layer.SrcPort == 5060 || layer.DstPort == 5060 {
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					payload := udp.Payload
					if HandleSIPMessage(payload, sipusers) == false {
						continue
					}
					headers, body := capture.ParseSIPHeaders(payload)

					callID := headers["call-id"]
					if callID != "" {
						capture.UpdateCallState(callID, "UDP-SIP", pkt.LinkType)
						capture.WriteSIP(callID, packet)
						if strings.Contains(body, "m=audio") {
							capture.ExtractPortFromSDP(body, callID)
						}
					}
				}
			} else if capture.IsTracked(packet) {
				callID := capture.GetCallIDForPacket(packet)
				fmt.Println("caught tracked packet, callid", callID)
				capture.WriteRTP(callID, packet)
			}
		}
	}
}

func extractCallID(packet gopacket.Packet) string {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		payload := udp.Payload
		text := string(payload)
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "call-id:") {
				callID := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				return string(callID)
			}
		}
	}
	return ""
}

func HandleSIPMessage(data []byte, usernames []string) bool {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) == 0 {
		return false
	}
	startLine := strings.TrimSpace(string(lines[0]))
	if !isSIPStartLine(startLine) {
		return false
	}

	headers, body := capture.ParseSIPHeaders(data)

	if containsUserInHeaders(headers, usernames) {
		callID := headers["call-id"]
		if callID != "" {
			// method := detectSIPMethod(startLine)

			if strings.Contains(body, "m=audio") {
				fmt.Println("extracting Port for callid", callID)
				capture.ExtractPortFromSDP(body, callID)
			}
		}
		return true
	}
	return false
}

func processSIPStream(r io.Reader, usernames []string) {
	fmt.Println("processSIPStream")
	full, err := io.ReadAll(r)
	if err != nil || len(full) == 0 {
		return
	}
	HandleSIPMessage(full, usernames)
}

func isSIPStartLine(line string) bool {
	return strings.HasPrefix(line, "INVITE") ||
		strings.HasPrefix(line, "BYE") ||
		strings.HasPrefix(line, "ACK") ||
		strings.HasPrefix(line, "OPTIONS") ||
		strings.HasPrefix(line, "REGISTER") ||
		strings.HasPrefix(line, "CANCEL") ||
		strings.HasPrefix(line, "SIP/2.0")
}

func containsUserInHeaders(headers map[string]string, usernames []string) bool {
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		for _, u := range usernames {
			if strings.Contains(val, u) {
				// fmt.Println("true", val)
				return true
			}
		}
	}
	return false
}

// func detectSIPMethod(line string) string {
// 	if strings.HasPrefix(line, "INVITE") {
// 		return "INVITE"
// 	}
// 	if strings.HasPrefix(line, "BYE") {
// 		return "BYE"
// 	}
// 	if strings.HasPrefix(line, "ACK") {
// 		return "ACK"
// 	}
// 	if strings.HasPrefix(line, "SIP/2.0 200") {
// 		return "OK"
// 	}
// 	return "UNKNOWN"
// }

// func containsAny(s string, substrs []string) bool {
// 	for _, u := range substrs {
// 		if strings.Contains(s, u) {
// 			return true
// 		}
// 	}
// 	return false
// }

func init() {
	voipCmd.Flags().StringVarP(&sipuser, "sipuser", "u", "", "SIP user to intercept")
}
