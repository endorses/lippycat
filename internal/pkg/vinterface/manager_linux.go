//go:build linux

package vinterface

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/vishvananda/netlink"
)

const (
	// TUN/TAP device path
	tunDevice = "/dev/net/tun"

	// ioctl flags for TUN/TAP
	iffTun    = 0x0001
	iffTap    = 0x0002
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

// ifReq is the structure for TUN/TAP ioctl requests.
type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte // padding
}

// linuxManager implements Manager for Linux TAP/TUN interfaces.
type linuxManager struct {
	config Config
	fd     *os.File
	link   netlink.Link

	// Async injection queue
	queue      chan []byte
	queueStop  chan struct{}
	queueWg    sync.WaitGroup
	shutdownMu sync.RWMutex
	shutdown   bool

	// Statistics
	stats struct {
		packetsInjected  atomic.Uint64
		packetsDropped   atomic.Uint64
		injectionErrors  atomic.Uint64
		conversionErrors atomic.Uint64
		bytesInjected    atomic.Uint64
		lastInjection    atomic.Int64 // Unix timestamp in nanoseconds
	}

	// State
	started atomic.Bool
}

// NewManager creates a new virtual interface manager for Linux.
func NewManager(config Config) (Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	m := &linuxManager{
		config:    config,
		queue:     make(chan []byte, config.BufferSize),
		queueStop: make(chan struct{}),
	}

	return m, nil
}

func (m *linuxManager) Name() string {
	return m.config.Name
}

func (m *linuxManager) Start() error {
	if m.started.Swap(true) {
		return ErrAlreadyStarted
	}

	logger.Info("Starting virtual interface", "name", m.config.Name, "type", m.config.Type)

	// Create TUN/TAP device
	if err := m.createInterface(); err != nil {
		m.started.Store(false)
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Bring interface up
	if err := m.bringUp(); err != nil {
		m.cleanup()
		m.started.Store(false)
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Start async injection worker
	m.queueWg.Add(1)
	go m.injectionWorker()

	logger.Info("Virtual interface started successfully", "name", m.config.Name)
	return nil
}

func (m *linuxManager) createInterface() error {
	// Open /dev/net/tun
	fd, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		if os.IsPermission(err) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	// Prepare ioctl request
	var req ifReq
	copy(req.Name[:], m.config.Name)

	// Set flags based on interface type
	if m.config.Type == "tap" {
		req.Flags = iffTap | iffNoPi
	} else {
		req.Flags = iffTun | iffNoPi
	}

	// Create interface via ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		tunSetIff,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		fd.Close()
		if errno == syscall.EPERM || errno == syscall.EACCES {
			return ErrPermissionDenied
		}
		if errno == syscall.EEXIST {
			return ErrInterfaceExists
		}
		return fmt.Errorf("ioctl failed: %v", errno)
	}

	m.fd = fd
	return nil
}

func (m *linuxManager) bringUp() error {
	// Get link by name
	link, err := netlink.LinkByName(m.config.Name)
	if err != nil {
		return fmt.Errorf("failed to get link: %w", err)
	}
	m.link = link

	// Set MTU
	if err := netlink.LinkSetMTU(link, m.config.MTU); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring link up: %w", err)
	}

	return nil
}

func (m *linuxManager) InjectPacket(packet []byte) error {
	m.shutdownMu.RLock()
	defer m.shutdownMu.RUnlock()

	if m.shutdown {
		return ErrShuttingDown
	}

	if !m.started.Load() {
		return ErrNotStarted
	}

	// Non-blocking send to queue
	select {
	case m.queue <- packet:
		return nil
	default:
		// Queue full, drop packet
		m.stats.packetsDropped.Add(1)
		return nil
	}
}

func (m *linuxManager) InjectPacketBatch(packets []types.PacketDisplay) error {
	m.shutdownMu.RLock()
	defer m.shutdownMu.RUnlock()

	if m.shutdown {
		return ErrShuttingDown
	}

	if !m.started.Load() {
		return ErrNotStarted
	}

	for i := range packets {
		// Convert PacketDisplay to raw frame based on interface type
		var frame []byte
		var err error

		if m.config.Type == "tun" {
			// TUN: Convert to IP packet (Layer 3 only, no Ethernet header)
			frame, err = ConvertToIP(&packets[i])
		} else {
			// TAP: Convert to Ethernet frame (Layer 2, includes Ethernet header)
			frame, err = ConvertToEthernet(&packets[i])
		}

		if err != nil {
			m.stats.conversionErrors.Add(1)
			logger.Debug("Packet conversion failed", "error", err, "type", m.config.Type)
			continue
		}

		// Non-blocking send to queue
		select {
		case m.queue <- frame:
		default:
			// Queue full, drop packet
			m.stats.packetsDropped.Add(1)
		}
	}

	return nil
}

func (m *linuxManager) injectionWorker() {
	defer m.queueWg.Done()

	for {
		select {
		case <-m.queueStop:
			return
		case packet := <-m.queue:
			if err := m.writePacket(packet); err != nil {
				m.stats.injectionErrors.Add(1)
				logger.Debug("Packet injection failed", "error", err)
			} else {
				m.stats.packetsInjected.Add(1)
				m.stats.bytesInjected.Add(uint64(len(packet)))
				m.stats.lastInjection.Store(time.Now().UnixNano())
			}
		}
	}
}

func (m *linuxManager) writePacket(packet []byte) error {
	if m.fd == nil {
		return ErrNotStarted
	}

	_, err := m.fd.Write(packet)
	return err
}

func (m *linuxManager) Shutdown() error {
	m.shutdownMu.Lock()
	m.shutdown = true
	m.shutdownMu.Unlock()

	if !m.started.Load() {
		return nil
	}

	logger.Info("Shutting down virtual interface", "name", m.config.Name)

	// Stop injection worker
	close(m.queueStop)
	m.queueWg.Wait()

	// Cleanup interface
	m.cleanup()

	logger.Info("Virtual interface shutdown complete", "name", m.config.Name,
		"packets_injected", m.stats.packetsInjected.Load(),
		"packets_dropped", m.stats.packetsDropped.Load(),
		"bytes_injected", m.stats.bytesInjected.Load())

	return nil
}

func (m *linuxManager) cleanup() {
	// Close file descriptor
	if m.fd != nil {
		m.fd.Close()
		m.fd = nil
	}

	// Delete link
	if m.link != nil {
		netlink.LinkDel(m.link)
		m.link = nil
	}
}

func (m *linuxManager) Stats() Stats {
	var lastInjection time.Time
	if ts := m.stats.lastInjection.Load(); ts > 0 {
		lastInjection = time.Unix(0, ts)
	}

	queueLen := len(m.queue)
	queueCap := cap(m.queue)
	var queueUtil float64
	if queueCap > 0 {
		queueUtil = float64(queueLen) / float64(queueCap)
	}

	return Stats{
		PacketsInjected:  m.stats.packetsInjected.Load(),
		PacketsDropped:   m.stats.packetsDropped.Load(),
		InjectionErrors:  m.stats.injectionErrors.Load(),
		ConversionErrors: m.stats.conversionErrors.Load(),
		QueueUtilization: queueUtil,
		BytesInjected:    m.stats.bytesInjected.Load(),
		LastInjection:    lastInjection,
	}
}
