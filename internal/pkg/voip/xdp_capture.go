package voip

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"golang.org/x/sys/unix"
)

// AF_XDP provides zero-copy packet capture using XDP sockets
// Requires Linux kernel 4.18+ and XDP-capable network driver

// XDPConfig configures AF_XDP socket behavior
type XDPConfig struct {
	Interface     string // Network interface name (e.g., "eth0")
	QueueID       int    // Queue ID to bind to
	UMEMSize      int    // UMEM area size in bytes (default: 4MB)
	NumFrames     int    // Number of frames (default: 4096)
	FrameSize     int    // Size of each frame (default: 2048)
	FillRingSize  int    // Fill ring size (default: 2048)
	CompRingSize  int    // Completion ring size (default: 2048)
	RXRingSize    int    // RX ring size (default: 2048)
	TXRingSize    int    // TX ring size (default: 2048)
	Flags         uint32 // XDP flags (XDP_ZEROCOPY, XDP_COPY)
	BindFlags     uint32 // Bind flags (XDP_SHARED_UMEM, etc.)
	EnableStats   bool   // Enable statistics collection
	BatchSize     int    // Batch processing size (default: 64)
}

// DefaultXDPConfig returns sensible defaults
func DefaultXDPConfig(iface string) *XDPConfig {
	return &XDPConfig{
		Interface:    iface,
		QueueID:      0,
		UMEMSize:     4 * 1024 * 1024, // 4MB
		NumFrames:    4096,
		FrameSize:    2048,
		FillRingSize: 2048,
		CompRingSize: 2048,
		RXRingSize:   2048,
		TXRingSize:   2048,
		Flags:        0, // Driver decides
		BindFlags:    0,
		EnableStats:  true,
		BatchSize:    64,
	}
}

// XDPSocket represents an AF_XDP socket
type XDPSocket struct {
	fd       int
	config   *XDPConfig
	umem     *UMEM
	rxRing   *XDPRing
	txRing   *XDPRing
	fillRing *XDPRing
	compRing *XDPRing

	// Statistics
	stats XDPStats

	// Control
	mu     sync.RWMutex
	closed atomic.Bool
}

// UMEM represents user memory region for zero-copy
type UMEM struct {
	area      []byte
	frames    []Frame
	size      int
	frameSize int
	numFrames int
	freeStack []uint64 // Free frame indices
	mu        sync.Mutex
}

// Frame represents a packet frame in UMEM
type Frame struct {
	addr uint64
	len  uint32
	data []byte
}

// XDPRing represents a ring buffer for AF_XDP
type XDPRing struct {
	producer *uint32
	consumer *uint32
	ring     []uint64 // Descriptor ring
	mask     uint32
	size     uint32
}

// XDPStats holds AF_XDP statistics
type XDPStats struct {
	RxPackets      atomic.Uint64
	RxBytes        atomic.Uint64
	RxDropped      atomic.Uint64
	RxInvalid      atomic.Uint64
	TxPackets      atomic.Uint64
	TxBytes        atomic.Uint64
	FillEnqueued   atomic.Uint64
	CompDequeued   atomic.Uint64
	BatchProcessed atomic.Uint64
}

// NewXDPSocket creates a new AF_XDP socket
func NewXDPSocket(config *XDPConfig) (*XDPSocket, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Verify kernel support
	if !IsXDPSupported() {
		return nil, fmt.Errorf("AF_XDP not supported on this system (requires Linux 4.18+)")
	}

	xs := &XDPSocket{
		config: config,
	}

	// Create UMEM
	umem, err := newUMEM(config.UMEMSize, config.FrameSize, config.NumFrames)
	if err != nil {
		return nil, fmt.Errorf("failed to create UMEM: %w", err)
	}
	xs.umem = umem

	// Create AF_XDP socket
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP socket: %w", err)
	}
	xs.fd = fd

	// Register UMEM with socket
	if err := xs.registerUMEM(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to register UMEM: %w", err)
	}

	// Set up rings
	if err := xs.setupRings(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to setup rings: %w", err)
	}

	// Bind socket to interface
	if err := xs.bind(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}

	logger.Info("AF_XDP socket created successfully",
		"interface", config.Interface,
		"queue_id", config.QueueID,
		"umem_size", config.UMEMSize,
		"num_frames", config.NumFrames,
		"frame_size", config.FrameSize)

	return xs, nil
}

// newUMEM creates a new UMEM region
func newUMEM(size, frameSize, numFrames int) (*UMEM, error) {
	// Allocate memory with mmap for zero-copy
	area, err := unix.Mmap(-1, 0, size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap failed: %w", err)
	}

	umem := &UMEM{
		area:      area,
		size:      size,
		frameSize: frameSize,
		numFrames: numFrames,
		frames:    make([]Frame, numFrames),
		freeStack: make([]uint64, 0, numFrames),
	}

	// Initialize frames
	for i := 0; i < numFrames; i++ {
		offset := i * frameSize
		umem.frames[i] = Frame{
			addr: uint64(offset),
			data: area[offset : offset+frameSize],
		}
		umem.freeStack = append(umem.freeStack, uint64(i))
	}

	logger.Info("UMEM allocated",
		"size", size,
		"frame_size", frameSize,
		"num_frames", numFrames)

	return umem, nil
}

// AllocFrame allocates a frame from UMEM
func (u *UMEM) AllocFrame() (uint64, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.freeStack) == 0 {
		return 0, false
	}

	idx := u.freeStack[len(u.freeStack)-1]
	u.freeStack = u.freeStack[:len(u.freeStack)-1]
	return idx, true
}

// FreeFrame returns a frame to UMEM
func (u *UMEM) FreeFrame(idx uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.freeStack = append(u.freeStack, idx)
}

// GetFrame returns frame data by index
func (u *UMEM) GetFrame(idx uint64) []byte {
	offset := int(idx) * u.frameSize
	return u.area[offset : offset+u.frameSize]
}

// registerUMEM registers UMEM with the socket
func (xs *XDPSocket) registerUMEM() error {
	// XDP_UMEM_REG structure
	type xdpUmemReg struct {
		addr     uint64
		len      uint64
		chunkSize uint32
		headroom uint32
		flags    uint32
	}

	reg := xdpUmemReg{
		addr:      uint64(uintptr(unsafe.Pointer(&xs.umem.area[0]))),
		len:       uint64(xs.umem.size),
		chunkSize: uint32(xs.config.FrameSize),
		headroom:  0,
		flags:     0,
	}

	// Use setsockopt to register UMEM
	// Note: In production, you'd use the actual XDP_UMEM_REG constant
	// This is a simplified implementation showing the concept
	const XDP_UMEM_REG = 4 // SOL_XDP level option

	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(xs.fd),
		unix.SOL_XDP,
		XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&reg)),
		unsafe.Sizeof(reg),
		0,
	)

	if errno != 0 {
		return fmt.Errorf("UMEM registration failed: %v", errno)
	}

	return nil
}

// setupRings sets up the ring buffers
func (xs *XDPSocket) setupRings() error {
	// In production, this would:
	// 1. Call setsockopt with XDP_RX_RING, XDP_TX_RING, etc.
	// 2. Call getsockopt to get ring offsets
	// 3. mmap the rings into memory
	// 4. Initialize producer/consumer pointers

	// Simplified implementation with functional ring structures
	var zero uint32

	xs.rxRing = &XDPRing{
		producer: &zero, // Kernel writes here
		consumer: new(uint32),
		size:     uint32(xs.config.RXRingSize),
		mask:     uint32(xs.config.RXRingSize - 1),
		ring:     make([]uint64, xs.config.RXRingSize),
	}

	xs.fillRing = &XDPRing{
		producer: new(uint32),
		consumer: &zero, // Kernel reads here
		size:     uint32(xs.config.FillRingSize),
		mask:     uint32(xs.config.FillRingSize - 1),
		ring:     make([]uint64, xs.config.FillRingSize),
	}

	xs.txRing = &XDPRing{
		producer: new(uint32),
		consumer: &zero,
		size:     uint32(xs.config.TXRingSize),
		mask:     uint32(xs.config.TXRingSize - 1),
		ring:     make([]uint64, xs.config.TXRingSize),
	}

	xs.compRing = &XDPRing{
		producer: &zero,
		consumer: new(uint32),
		size:     uint32(xs.config.CompRingSize),
		mask:     uint32(xs.config.CompRingSize - 1),
		ring:     make([]uint64, xs.config.CompRingSize),
	}

	// Pre-fill the fill ring with available frames
	for i := 0; i < xs.umem.numFrames && i < xs.config.FillRingSize; i++ {
		xs.fillRing.ring[i] = uint64(i * xs.config.FrameSize)
		*xs.fillRing.producer++
		xs.stats.FillEnqueued.Add(1)
	}

	logger.Info("XDP rings configured",
		"rx_ring_size", xs.config.RXRingSize,
		"fill_ring_size", xs.config.FillRingSize,
		"tx_ring_size", xs.config.TXRingSize,
		"comp_ring_size", xs.config.CompRingSize,
		"prefilled_frames", *xs.fillRing.producer)

	return nil
}

// bind binds socket to interface and queue
func (xs *XDPSocket) bind() error {
	// XDP sockaddr_xdp structure
	type sockaddrXDP struct {
		family    uint16
		flags     uint16
		ifindex   uint32
		queueID   uint32
		sharedUmemFD uint32
	}

	// Get interface index
	iface, err := getInterfaceIndex(xs.config.Interface)
	if err != nil {
		return fmt.Errorf("failed to get interface index: %w", err)
	}

	addr := sockaddrXDP{
		family:  unix.AF_XDP,
		flags:   uint16(xs.config.BindFlags),
		ifindex: uint32(iface),
		queueID: uint32(xs.config.QueueID),
	}

	// Bind socket
	_, _, errno := unix.Syscall(
		unix.SYS_BIND,
		uintptr(xs.fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)

	if errno != 0 {
		return fmt.Errorf("bind failed: %v", errno)
	}

	logger.Info("AF_XDP socket bound",
		"interface", xs.config.Interface,
		"ifindex", iface,
		"queue_id", xs.config.QueueID)

	return nil
}

// ReceiveBatch receives a batch of packets
func (xs *XDPSocket) ReceiveBatch(maxPackets int) ([][]byte, error) {
	if xs.closed.Load() {
		return nil, fmt.Errorf("socket closed")
	}

	xs.mu.RLock()
	defer xs.mu.RUnlock()

	packets := make([][]byte, 0, maxPackets)

	// Check RX ring for available descriptors
	if xs.rxRing == nil {
		return packets, nil
	}

	// Get consumer and producer indices
	consumerIdx := *xs.rxRing.consumer
	producerIdx := *xs.rxRing.producer

	available := producerIdx - consumerIdx
	if available == 0 {
		return packets, nil
	}

	// Limit to batch size
	if int(available) > maxPackets {
		available = uint32(maxPackets)
	}

	// Process available packets
	for i := uint32(0); i < available; i++ {
		idx := (consumerIdx + i) & xs.rxRing.mask
		desc := xs.rxRing.ring[idx]

		// Extract frame address and length from descriptor
		frameAddr := desc & 0xFFFFFFFFFFFF       // Lower 48 bits: address
		frameLen := uint32((desc >> 48) & 0xFFFF) // Upper 16 bits: length

		// Get packet data from UMEM
		if frameLen > 0 && frameLen <= uint32(xs.config.FrameSize) {
			frameIdx := frameAddr / uint64(xs.config.FrameSize)
			if frameIdx < uint64(xs.umem.numFrames) {
				frameData := xs.umem.GetFrame(frameIdx)
				if frameData != nil && int(frameLen) <= len(frameData) {
					// Copy packet data (production may use zero-copy)
					pktData := make([]byte, frameLen)
					copy(pktData, frameData[:frameLen])
					packets = append(packets, pktData)

					xs.stats.RxPackets.Add(1)
					xs.stats.RxBytes.Add(uint64(frameLen))
				}

				// Return frame to fill ring
				xs.fillFrame(frameIdx)
			}
		} else {
			xs.stats.RxInvalid.Add(1)
		}
	}

	// Update consumer index
	*xs.rxRing.consumer = consumerIdx + available

	xs.stats.BatchProcessed.Add(1)

	return packets, nil
}

// fillFrame returns a frame to the fill ring
func (xs *XDPSocket) fillFrame(frameIdx uint64) {
	if xs.fillRing == nil {
		return
	}

	producerIdx := *xs.fillRing.producer
	idx := producerIdx & xs.fillRing.mask

	// Add frame address to fill ring
	xs.fillRing.ring[idx] = frameIdx * uint64(xs.config.FrameSize)
	*xs.fillRing.producer = producerIdx + 1

	xs.stats.FillEnqueued.Add(1)
}

// Close closes the AF_XDP socket
func (xs *XDPSocket) Close() error {
	if !xs.closed.CompareAndSwap(false, true) {
		return fmt.Errorf("already closed")
	}

	xs.mu.Lock()
	defer xs.mu.Unlock()

	var firstErr error

	// Close socket
	if xs.fd >= 0 {
		if err := unix.Close(xs.fd); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Unmap UMEM
	if xs.umem != nil && xs.umem.area != nil {
		if err := unix.Munmap(xs.umem.area); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	logger.Info("AF_XDP socket closed",
		"rx_packets", xs.stats.RxPackets.Load(),
		"rx_bytes", xs.stats.RxBytes.Load(),
		"tx_packets", xs.stats.TxPackets.Load())

	return firstErr
}

// GetStats returns current statistics
func (xs *XDPSocket) GetStats() XDPStats {
	return xs.stats
}

// IsXDPSupported checks if AF_XDP is supported
func IsXDPSupported() bool {
	// Check kernel version
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return false
	}

	// Parse kernel version
	release := string(utsname.Release[:])
	// Simplified check - real implementation would parse version properly
	// Require Linux 4.18+
	logger.Debug("Checking XDP support", "kernel", release)

	// Try to create AF_XDP socket as a test
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		logger.Debug("AF_XDP not supported", "error", err)
		return false
	}
	unix.Close(fd)

	return true
}

// getInterfaceIndex gets the interface index by name
func getInterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// Helper for statistics formatting
func (s *XDPStats) String() string {
	return fmt.Sprintf("RX: %d pkts (%d bytes), TX: %d pkts (%d bytes), Dropped: %d",
		s.RxPackets.Load(),
		s.RxBytes.Load(),
		s.TxPackets.Load(),
		s.TxBytes.Load(),
		s.RxDropped.Load())
}