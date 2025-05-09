package pcaptypes

import (
	"errors"
	"os"

	"github.com/google/gopacket/pcap"
)

type offlineInterface struct {
	file   *os.File
	handle *pcap.Handle
}

func (iface *offlineInterface) SetHandle() error {
	handle, err := pcap.OpenOfflineFile(iface.file)
	iface.handle = handle
	return err
}

func (iface offlineInterface) Handle() (*pcap.Handle, error) {
	var err error
	if iface.handle == nil {
		err = errors.New("Interface has no handle")
	}
	return iface.handle, err
}
