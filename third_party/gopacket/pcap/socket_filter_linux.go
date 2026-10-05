//go:build linux
// +build linux

package pcap

/*
#include <pcap.h>
#include <arpa/inet.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// SetSocketFilter attaches a BPF_PROG_TYPE_SOCKET_FILTER program to a fresh live
// Linux packet socket. It does not take ownership of programFD or expose the
// borrowed socket descriptor. A handle that has used libpcap classic filtering is
// rejected because libpcap may retain incompatible userspace filter state.
// Subsequent classic-filter calls are rejected. Call only during coordinated
// startup (or startup activation), before readers start.
func (p *Handle) SetSocketFilter(programFD int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isOpen() || atomic.LoadUint64(&p.stop) != 0 {
		return io.EOF
	}
	if p.classicFilterSet {
		return errors.New("pcap: socket admission requires a fresh handle without classic filter state")
	}
	if C.pcap_file(p.cptr) != nil {
		return errors.New("pcap: socket admission requires live capture")
	}
	if programFD < 0 {
		return errors.New("pcap: invalid socket filter descriptor")
	}
	fd := int(C.pcap_fileno(p.cptr))
	if fd < 0 {
		return errors.New("pcap: live capture has no packet socket")
	}
	family, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return fmt.Errorf("pcap: inspect socket domain: %w", err)
	}
	if family != unix.AF_PACKET {
		return errors.New("pcap: socket admission requires AF_PACKET")
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, programFD); err != nil {
		return fmt.Errorf("pcap: attach socket filter: %w", err)
	}
	p.socketFilterOwned = true
	return nil
}

// DrainSocketBuffer discards queued startup packets while the caller's attached
// program rejects all reception. Only immediate packet-ring modes are supported:
// TPACKET_V3 can hide a partially filled block until later retirement. Before
// draining, a protocol rebind waits for old AF_PACKET receive operations to finish.
// New receives run under the already attached reject-all program. No timestamp
// fence is needed after successful draining, even if the host clock steps back.
// The context must have a deadline; cancellation terminates even non-quiet input.
func (p *Handle) DrainSocketBuffer(ctx context.Context) error {
	_, err := p.DrainSocketBufferCount(ctx)
	return err
}

// DrainSocketBufferCount is DrainSocketBuffer with separate startup discard
// accounting. Discarded frames are not kernel drops or reader queue overflows.
func (p *Handle) DrainSocketBufferCount(ctx context.Context) (discarded uint64, result error) {
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("pcap: draining requires a bounded context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isOpen() || atomic.LoadUint64(&p.stop) != 0 {
		return 0, io.EOF
	}
	if !p.socketFilterOwned {
		return 0, errors.New("pcap: drain requires an attached startup filter")
	}
	fd := int(C.pcap_fileno(p.cptr))
	if fd < 0 {
		return 0, errors.New("pcap: drain requires a live packet socket")
	}
	version, err := unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION)
	if err != nil {
		return 0, fmt.Errorf("pcap: read ring version: %w", err)
	}
	if version == unix.TPACKET_V3 {
		return 0, errors.New("pcap: socket admission drain requires immediate capture mode")
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("pcap: drain startup packets: %w", err)
	}
	if err := retireSocketReceivers(fd, unix.Getsockname, unix.Bind); err != nil {
		return 0, err
	}
	var errorBuffer [errorBufferSize]C.char
	oldMode := C.pcap_getnonblock(p.cptr, &errorBuffer[0])
	if oldMode < 0 {
		return 0, errors.New("pcap: cannot read nonblocking state")
	}
	if C.pcap_setnonblock(p.cptr, 1, &errorBuffer[0]) != 0 {
		return 0, errors.New("pcap: cannot enable nonblocking drain")
	}
	defer func() {
		if C.pcap_setnonblock(p.cptr, oldMode, &errorBuffer[0]) != 0 {
			result = errors.Join(result, errors.New("pcap: cannot restore nonblocking state"))
		}
	}()
	// Rebinding synchronizes old receivers. In immediate ring modes all retained
	// frames are now visible and no new frame can pass the startup filter.
	for {
		if err := ctx.Err(); err != nil {
			return discarded, fmt.Errorf("pcap: drain startup packets: %w", err)
		}
		switch status := p.pcapNextPacketEx(); status {
		case NextErrorOk:
			discarded++
		case NextErrorTimeoutExpired:
			return discarded, nil
		case NextErrorNoMorePackets:
			return discarded, errors.New("pcap: packet socket ended during startup drain")
		default:
			return discarded, fmt.Errorf("pcap: startup drain failed: %s", status)
		}
	}
}

// A bind to a different protocol unregisters the old packet hook and calls
// synchronize_net before registering the new hook (Linux packet_do_bind).
// Protocol zero cannot be used to stop an existing socket: the kernel substitutes
// its current protocol. Bounce between nonzero protocols instead, with reception
// still rejected by the startup program, then restore the original binding.
// Fanout sockets are rejected by the kernel rather than being silently rebound.
func retireSocketReceivers(fd int, name func(int) (unix.Sockaddr, error), bind func(int, unix.Sockaddr) error) error {
	address, err := name(fd)
	if err != nil {
		return fmt.Errorf("pcap: inspect startup socket binding: %w", err)
	}
	original, ok := address.(*unix.SockaddrLinklayer)
	if !ok || original.Protocol == 0 {
		return errors.New("pcap: startup drain requires a bound packet socket")
	}
	other := *original
	other.Protocol = uint16(C.htons(C.ushort(unix.ETH_P_IP)))
	if other.Protocol == original.Protocol {
		other.Protocol = uint16(C.htons(C.ushort(unix.ETH_P_IPV6)))
	}
	if err := bind(fd, &other); err != nil {
		return fmt.Errorf("pcap: synchronize startup receivers: %w", err)
	}
	if err := bind(fd, original); err != nil {
		return fmt.Errorf("pcap: restore startup socket binding: %w", err)
	}
	return nil
}
