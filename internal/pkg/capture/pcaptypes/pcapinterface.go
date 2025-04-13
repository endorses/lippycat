package pcaptypes

import (
	"os"

	"github.com/google/gopacket/pcap"
)

type PcapInterface interface {
	SetHandle() error
	Handle() (*pcap.Handle, error)
}

func CreateLiveInterface(device string) PcapInterface {
	var result PcapInterface
	iface := liveInterface{device, nil}
	result = PcapInterface(&iface)
	return result
}

func CreateOfflineInterface(f *os.File) PcapInterface {
	var result PcapInterface
	iface := offlineInterface{f, nil}
	result = PcapInterface(&iface)
	return result
}
