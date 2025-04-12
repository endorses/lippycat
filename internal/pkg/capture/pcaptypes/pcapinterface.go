package pcaptypes

import "github.com/google/gopacket/pcap"

type PcapInterface interface {
	SetHandle() error
	GetHandle() (*pcap.Handle, error)
}

func CreateLiveInterface(device string) PcapInterface {
	var result PcapInterface
	iface := liveInterface{device, nil}
	result = PcapInterface(&iface)
	return result
}
