package pcaptypes

import (
	"errors"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/viper"
)

type liveInterface struct {
	Device string
	handle *pcap.Handle
}

func (iface *liveInterface) SetHandle() error {
	// Close existing handle if it exists to prevent leaks
	if iface.handle != nil {
		iface.handle.Close()
		iface.handle = nil
	}

	promiscuous := viper.GetViper().GetBool("promiscuous")
	snapshotLen := int32(MaxPcapSnapshotLen)

	// Use a timeout to allow graceful shutdown and prevent orphaned goroutines
	// BlockForever causes capture goroutines to hang when context is cancelled
	// 200ms is responsive enough for shutdown while being infrequent enough to avoid choppiness
	timeout := 200 * time.Millisecond
	handle, err := pcap.OpenLive(iface.Device, snapshotLen, promiscuous, timeout)
	if err != nil {
		return err
	}

	iface.handle = handle
	return nil
}

func (iface liveInterface) Handle() (*pcap.Handle, error) {
	var err error
	if iface.handle == nil {
		err = errors.New("interface has no handle")
	}
	return iface.handle, err
}

func (iface liveInterface) Name() string {
	return iface.Device
}
