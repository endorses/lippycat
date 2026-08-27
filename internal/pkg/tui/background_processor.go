//go:build tui || all

package tui

import (
	"sync"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

const backgroundQueueSize = 1000

type BackgroundProcessorConfig struct {
	CallAgg     *LocalCallAggregator
	CaptureMode components.CaptureMode
}

type DNSPacketResultMsg struct {
	Generation uint64
	Packet     types.PacketDisplay
}
type HTTPPacketResultMsg struct {
	Generation uint64
	Packet     types.PacketDisplay
}
type EmailPacketResultMsg struct {
	Generation uint64
	Packet     types.PacketDisplay
}
type LocalCallPacketResultMsg struct {
	Generation uint64
	Packet     types.PacketDisplay
}
type backgroundProcessorStoppedMsg struct{}

type backgroundPacket struct {
	packet     types.PacketDisplay
	linkType   layers.LinkType
	generation uint64
}

// BackgroundProcessor parses immutable packet snapshots and publishes results.
// It never mutates Bubble Tea components.
type BackgroundProcessor struct {
	packetChan       chan backgroundPacket
	resultChan       chan tea.Msg
	done             chan struct{}
	stopOnce         sync.Once
	wg               sync.WaitGroup
	generation       atomic.Uint64
	packetsProcessed atomic.Int64
	packetsDropped   atomic.Int64
	resultsDropped   atomic.Int64
}

func NewBackgroundProcessor() *BackgroundProcessor {
	bp := &BackgroundProcessor{packetChan: make(chan backgroundPacket, backgroundQueueSize), resultChan: make(chan tea.Msg, backgroundQueueSize), done: make(chan struct{})}
	bp.generation.Store(1)
	bp.wg.Add(1)
	go bp.run()
	return bp
}

// Configure begins a new capture generation. Results already in flight retain
// their old generation and are ignored by Model.Update.
func (bp *BackgroundProcessor) Configure(_ BackgroundProcessorConfig) uint64 {
	return bp.generation.Add(1)
}
func (bp *BackgroundProcessor) SetCallAggregator(_ *LocalCallAggregator, _ components.CaptureMode) {
	bp.generation.Add(1)
}
func (bp *BackgroundProcessor) Generation() uint64 { return bp.generation.Load() }

func (bp *BackgroundProcessor) Submit(packet components.PacketDisplay, linkType layers.LinkType) {
	item := backgroundPacket{packet: cloneBackgroundPacket(types.PacketDisplay(packet)), linkType: linkType, generation: bp.generation.Load()}
	select {
	case <-bp.done:
		bp.packetsDropped.Add(1)
	case bp.packetChan <- item:
	default:
		bp.packetsDropped.Add(1)
	}
}

func (bp *BackgroundProcessor) SubmitBatch(packets []components.PacketDisplay, linkType layers.LinkType) {
	for i := range packets {
		bp.Submit(packets[i], linkType)
	}
}

func (bp *BackgroundProcessor) WaitForResult() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-bp.resultChan:
			return msg
		case <-bp.done:
			return backgroundProcessorStoppedMsg{}
		}
	}
}

func (bp *BackgroundProcessor) Stop() { bp.stopOnce.Do(func() { close(bp.done) }); bp.wg.Wait() }
func (bp *BackgroundProcessor) Stats() (processed, dropped int64) {
	return bp.packetsProcessed.Load(), bp.packetsDropped.Load()
}
func (bp *BackgroundProcessor) ResultDrops() int64 { return bp.resultsDropped.Load() }

func (bp *BackgroundProcessor) run() {
	defer bp.wg.Done()
	for {
		select {
		case <-bp.done:
			return
		case item := <-bp.packetChan:
			bp.processPacket(item)
			bp.packetsProcessed.Add(1)
		}
	}
}

func (bp *BackgroundProcessor) publish(msg tea.Msg) {
	select {
	case <-bp.done:
		return
	case bp.resultChan <- msg:
	default:
		bp.resultsDropped.Add(1)
	}
}

func (bp *BackgroundProcessor) processPacket(item backgroundPacket) {
	packet := item.packet
	switch packet.Protocol {
	case "DNS":
		if packet.DNSData == nil && len(packet.RawData) > 0 {
			packet.DNSData = parseDNSFromRawData(packet.RawData, item.linkType)
		}
		if packet.DNSData != nil {
			bp.publish(DNSPacketResultMsg{item.generation, packet})
		}
	case "HTTP":
		if packet.HTTPData == nil && len(packet.RawData) > 0 {
			packet.HTTPData = parseHTTPFromRawData(packet.RawData, item.linkType)
		}
		if packet.HTTPData != nil {
			bp.publish(HTTPPacketResultMsg{item.generation, packet})
		}
	}
	if packet.EmailData != nil {
		bp.publish(EmailPacketResultMsg{item.generation, packet})
	}
	if packet.Protocol == "SIP" || packet.Protocol == "RTP" {
		bp.publish(LocalCallPacketResultMsg{item.generation, packet})
	}
}

func cloneBackgroundPacket(packet types.PacketDisplay) types.PacketDisplay {
	packet.RawData = append([]byte(nil), packet.RawData...)
	if packet.DNSData != nil {
		metadata := *packet.DNSData
		metadata.Answers = append([]types.DNSAnswer(nil), metadata.Answers...)
		packet.DNSData = &metadata
	}
	if packet.HTTPData != nil {
		metadata := *packet.HTTPData
		metadata.Headers = cloneStringMap(metadata.Headers)
		packet.HTTPData = &metadata
	}
	if packet.EmailData != nil {
		metadata := *packet.EmailData
		metadata.RcptTo = append([]string(nil), metadata.RcptTo...)
		metadata.IMAPFlags = append([]string(nil), metadata.IMAPFlags...)
		packet.EmailData = &metadata
	}
	if packet.VoIPData != nil {
		metadata := *packet.VoIPData
		metadata.Headers = cloneStringMap(metadata.Headers)
		metadata.RawSIP = append([]byte(nil), metadata.RawSIP...)
		if metadata.AccessNetworkInfo != nil {
			ani := *metadata.AccessNetworkInfo
			ani.Parameters = cloneStringMap(ani.Parameters)
			metadata.AccessNetworkInfo = &ani
		}
		packet.VoIPData = &metadata
	}
	return packet
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
