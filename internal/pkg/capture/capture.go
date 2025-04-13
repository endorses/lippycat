package capture

import (
	"log"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

type PacketInfo struct {
	LinkType layers.LinkType
	Packet   gopacket.Packet
}

func Init(ifaces []pcaptypes.PcapInterface, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {
	packetChan := make(chan PacketInfo, 1000)
	var wg sync.WaitGroup
	var processorWg sync.WaitGroup
	processorWg.Add(1)
	for _, iface := range ifaces {
		wg.Add(1)
		go func(pif pcaptypes.PcapInterface) {
			defer wg.Done()
			err := pif.SetHandle()
			if err != nil {
				log.Fatal("Error setting TCP pcap handle:", err)
			}
			handle, err := pif.Handle()
			defer handle.Close()
			captureFromInterface(pif, filter, packetChan)
		}(iface)
	}
	go func() {
		wg.Wait()
		close(packetChan)
	}()
	go func() {
		defer processorWg.Done()
		packetProcessor(packetChan, assembler)
	}()
	processorWg.Wait()
}

func captureFromInterface(iface pcaptypes.PcapInterface, filter string, ch chan PacketInfo) {
	handle, err := iface.Handle()
	if err != nil {
		log.Fatal("Unable to set handle")
	}
	filterErr := handle.SetBPFFilter(filter)
	if filterErr != nil {
		log.Fatal("Error setting BPF filter:", filter, err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ch <- PacketInfo{
			LinkType: handle.LinkType(),
			Packet:   packet,
		}
	}
}
