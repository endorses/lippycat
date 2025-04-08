package capture

import (
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

type PacketInfo struct {
	Device   string
	LinkType layers.LinkType
	Packet   gopacket.Packet
}

type InterfaceInfo struct {
	Device   string
	LinkType layers.LinkType
	Handle   *pcap.Handle
}

func Init(devices []string, filter string, packetProcessor func(ch <-chan PacketInfo, assembler *tcpassembly.Assembler), assembler *tcpassembly.Assembler) {

	packetChan := make(chan PacketInfo, 1000)

	promiscuous := false
	snapshotLen := int32(65535)
	timeout := pcap.BlockForever

	var info InterfaceInfo
	var wg sync.WaitGroup

	for _, iface := range devices {
		wg.Add(1)
		go func(device string) {
			defer wg.Done()
			handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
			if err != nil {
				log.Fatal("Error setting pcap handle:", err)
			}
			defer handle.Close()
			info.Device = device
			info.LinkType = handle.LinkType()
			info.Handle = handle
			captureFromInterface(info, filter, packetChan)
		}(iface)
	}
	go packetProcessor(packetChan, assembler)

	wg.Wait()
	close(packetChan)
}

func captureFromInterface(info InterfaceInfo, filter string, ch chan PacketInfo) {

	handle := info.Handle

	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Error setting BPF filter:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ch <- PacketInfo{
			Device:   info.Device,
			LinkType: info.LinkType,
			Packet:   packet,
		}
	}
}
