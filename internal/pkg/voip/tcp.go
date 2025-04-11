package voip

import (
	"io"
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
		close(c.done)
	}
}

func (c *CallIDDetector) Wait() string {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callID
}

type sipStreamFactory struct{}

func NewSipStreamFactory() tcpassembly.StreamFactory {
	return &sipStreamFactory{}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processTcpSipStream(&r)
	return &r
}

func processTcpSipStream(r io.Reader) {
	full, err := io.ReadAll(r)
	if err != nil || len(full) == 0 {
		return
	}
	handleSipMessage(full)
}

func HandleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	if layer.SrcPort == 5060 || layer.DstPort == 5060 {
		packet := pkt.Packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			callIDDetector := &CallIDDetector{done: make(chan struct{})}
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
			callID := callIDDetector.Wait()
			if callID != "" {
				WriteSIP(callID, packet)
			}
		}
	}
}
