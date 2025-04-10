package voip

import (
	"io"
	"log"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type CallIDDetector struct {
	mu     sync.Mutex
	callID string
	found  bool
	done   chan struct{}
}

func (c *CallIDDetector) SetCallID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.found {
		c.callID = id
		c.found = true
		close(c.done) // signal others
	}
}

func (c *CallIDDetector) Wait() string {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callID
}

type sipStreamFactory struct{}

func NewSIPStreamFactory() tcpassembly.StreamFactory {
	return &sipStreamFactory{}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processTCPSIPStream(&r)
	return &r
}

func processTCPSIPStream(r io.Reader) {
	// fmt.Println("processSIPStream")
	full, err := io.ReadAll(r)
	if err != nil || len(full) == 0 {
		return
	}
	handleSIPMessage(full)
}

func HandleTCPPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	if layer.SrcPort == 5060 || layer.DstPort == 5060 {
		packet := pkt.Packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// tcp, _ := tcpLayer.(*layers.TCP)
			// payload := tcp.Payload
			// if handleSIPMessage(payload) == false {
			// 	return
			// }

			callIDDetector := &CallIDDetector{done: make(chan struct{})}

			// callID := extractCallIDFromTCP(packet)
			// if capture.HasCall(callID) == false {
			// 	capture.GetOrCreateCall(callID, pkt.LinkType)
			// } else {
			// 	capture.UpdateCallState(callID, "TCP-SIP")
			// }
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
			// Wait until Call-ID is found
			callID := callIDDetector.Wait()
			log.Printf("Got Call-ID: %s", callID)
			if callID != "" {
				WriteSIP(callID, packet)
			}
		}
	}
}
