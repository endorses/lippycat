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

	var udpInfo, tcpInfo InterfaceInfo
	var wg sync.WaitGroup

	for _, iface := range devices {
		wg.Add(1)
		go func(device string) {
			defer wg.Done()
			// TCP handle
			tcpHandle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
			tcpHandle.SetBPFFilter("tcp and port 5060")
			if err != nil {
				log.Fatal("Error setting TCP pcap handle:", err)
			}
			defer tcpHandle.Close()
			tcpInfo.Device = device
			tcpInfo.LinkType = tcpHandle.LinkType()
			tcpInfo.Handle = tcpHandle
			go captureFromInterface(tcpInfo, iface, packetChan)

			// UDP handle
			udpHandle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
			udpHandle.SetBPFFilter("udp and port 5060")
			// handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
			if err != nil {
				log.Fatal("Error setting UDP pcap handle:", err)
			}
			defer udpHandle.Close()
			udpInfo.Device = device
			udpInfo.LinkType = udpHandle.LinkType()
			udpInfo.Handle = udpHandle
			go captureFromInterface(udpInfo, iface, packetChan)

			// captureFromInterface(info, filter, packetChan)
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
