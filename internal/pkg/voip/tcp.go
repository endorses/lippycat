package voip

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/spf13/viper"
)

type CallIDDetector struct {
	mu     sync.Mutex
	callID string
	found  bool
	done   chan struct{}
}

func (c *CallIDDetector) SetCallID(id string) {
	fmt.Println("setcallid c,id", c, id)
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
	fmt.Println("wait c.callID", c.callID)
	return c.callID
}

type sipStreamFactory struct {
	callIDDetector *CallIDDetector
}

func NewSipStreamFactory() tcpassembly.StreamFactory {
	return &sipStreamFactory{callIDDetector: &CallIDDetector{done: make(chan struct{})}}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	fmt.Println("New() callIDDetector", f.callIDDetector)
	r := tcpreader.NewReaderStream()
	stream := &SIPStream{
		reader:         &r,
		callIDDetector: f.callIDDetector,
	}
	go stream.run()
	return &r
	// r := tcpreader.NewReaderStream()
	// go processTcpSipStream(&r)
	// return &r
}

type SIPStream struct {
	reader         *tcpreader.ReaderStream
	callIDDetector *CallIDDetector
}

func (s *SIPStream) run() {
	fmt.Println("run")
	buf := bufio.NewReader(s.reader)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading SIP stream: %v", err)
			}
			return
		}
		fmt.Println("run line", line)

		// Detect SIP header line
		if strings.HasPrefix(line, "Call-ID:") || strings.HasPrefix(line, "i:") {
			fmt.Println("HasPrefix")
			callID := strings.TrimSpace(strings.TrimPrefix(line, "Call-ID:"))
			callID = strings.TrimSpace(strings.TrimPrefix(callID, "i:")) // short form
			s.callIDDetector.SetCallID(callID)
			return // done after detecting first Call-ID
		}
	}
}

// func processTcpSipStream(r io.Reader) {
// 	full, err := io.ReadAll(r)
// 	if err != nil || len(full) == 0 {
// 		return
// 	}
// 	handleSipMessage(full)
// }

func handleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	if layer.SrcPort == 5060 || layer.DstPort == 5060 {
		packet := pkt.Packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			callIDDetector := &CallIDDetector{done: make(chan struct{})}
			// callIDDetector := str
			// fmt.Println("handleTcpPackets callIDDetector", callIDDetector)
			// streamFactory := &sipStreamFactory{callIDDetector: callIDDetector}
			// streamPool := tcpassembly.NewStreamPool(streamFactory)
			// assembler2 := tcpassembly.NewAssembler(streamPool)
			// assembler2.AssembleWithTimestamp(
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
			select {
			// case <-streamFactory.callIDDetector.done:
			// 	callID := streamFactory.callIDDetector.Wait()
			case <-callIDDetector.done:
				callID := callIDDetector.Wait()
				if callID != "" {
					fmt.Println("handleTcpPackets callID", callID)
					if viper.GetViper().GetBool("writeVoip") {
					} else {
						fmt.Printf("[%s]%s\n", callID, packet)
					}
					WriteSIP(callID, packet)
				}
			case <-time.After(5 * time.Second):
				log.Println("Timeout: No Call-ID found in any stream")
			}
		}
	}
}
