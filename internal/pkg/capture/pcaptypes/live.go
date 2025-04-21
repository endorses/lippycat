package pcaptypes

import (
	"errors"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/viper"
)

type liveInterface struct {
	Device string
	handle *pcap.Handle
}

func (iface *liveInterface) SetHandle() error {
	promiscuous := viper.GetViper().GetBool("promiscuous")
	snapshotLen := int32(65535)
	timeout := pcap.BlockForever
	handle, err := pcap.OpenLive(iface.Device, snapshotLen, promiscuous, timeout)
	iface.handle = handle
	return err
}

func (iface liveInterface) Handle() (*pcap.Handle, error) {
	var err error
	if iface.handle == nil {
		err = errors.New("Interface has no handle")
	}
	return iface.handle, err
}
