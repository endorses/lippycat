package pcaptypes

import (
	"errors"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/viper"
)

// DefaultPcapBufferSize is the default kernel buffer size for packet capture.
// 16MB is suitable for high-traffic interfaces like bridges.
// The default libpcap value (~2MB) causes kernel drops on busy interfaces.
const DefaultPcapBufferSize = 16 * 1024 * 1024 // 16MB

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

	// Use configurable timeout to allow graceful shutdown and prevent orphaned goroutines
	// BlockForever causes capture goroutines to hang when context is cancelled
	// Default 200ms is responsive enough for shutdown while being infrequent enough to avoid choppiness
	// Configure via pcap_timeout_ms in config file or LIPPYCAT_PCAP_TIMEOUT_MS env var
	timeoutMs := viper.GetInt("pcap_timeout_ms")
	if timeoutMs <= 0 {
		timeoutMs = 200 // Default 200ms
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Configurable kernel buffer size for high-traffic interfaces
	// Default 16MB prevents kernel drops on busy interfaces like bridges
	// Configure via pcap_buffer_size in config file or LIPPYCAT_PCAP_BUFFER_SIZE env var
	bufferSize := viper.GetInt("pcap_buffer_size")
	if bufferSize <= 0 {
		bufferSize = DefaultPcapBufferSize
	}

	// Use inactive handle to set buffer size before activation
	inactive, err := pcap.NewInactiveHandle(iface.Device)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(int(snapshotLen)); err != nil {
		return err
	}
	if err := inactive.SetPromisc(promiscuous); err != nil {
		return err
	}
	if err := inactive.SetTimeout(timeout); err != nil {
		return err
	}
	if err := inactive.SetBufferSize(bufferSize); err != nil {
		return err
	}

	handle, err := inactive.Activate()
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
