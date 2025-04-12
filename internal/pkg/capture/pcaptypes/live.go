package pcaptypes

import (
	"errors"

	"github.com/google/gopacket/pcap"
)

type liveInterface struct {
	Device string
	Handle *pcap.Handle
}

func (iface *liveInterface) SetHandle() error {
	promiscuous := false
	snapshotLen := int32(65535)
	timeout := pcap.BlockForever
	handle, err := pcap.OpenLive(iface.Device, snapshotLen, promiscuous, timeout)
	iface.Handle = handle
	return err
}

func (iface liveInterface) GetHandle() (*pcap.Handle, error) {
	var err error
	if iface.Handle == nil {
		err = errors.New("Interface has no handle")
	}
	return iface.Handle, err
}
