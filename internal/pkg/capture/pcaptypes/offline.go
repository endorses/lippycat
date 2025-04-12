package pcaptypes

import (
	"errors"
	"os"

	"github.com/google/gopacket/pcap"
)

type offlineInterface struct {
	file   *os.File
	Handle *pcap.Handle
}

func (iface *offlineInterface) SetHandle() error {
	handle, err := pcap.OpenOfflineFile(iface.file)
	iface.Handle = handle
	return err
}

func (iface offlineInterface) GetHandle() (*pcap.Handle, error) {
	var err error
	if iface.Handle == nil {
		err = errors.New("Interface has no handle")
	}
	return iface.Handle, err
}
