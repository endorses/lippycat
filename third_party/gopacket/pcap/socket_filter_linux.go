//go:build linux
// +build linux

package pcap

/*
#include <pcap.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

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
// TPACKET_V3 can hide a partially filled block until later retirement. The caller
// must also apply a host-capture timestamp boundary after final activation to
// discard any frame whose receive operation raced the startup filter attachment.
// The context must have a deadline; cancellation terminates even non-quiet input.
func (p *Handle) DrainSocketBuffer(ctx context.Context) (result error) {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("pcap: draining requires a bounded context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isOpen() || atomic.LoadUint64(&p.stop) != 0 {
		return io.EOF
	}
	if !p.socketFilterOwned {
		return errors.New("pcap: drain requires an attached startup filter")
	}
	fd := int(C.pcap_fileno(p.cptr))
	if fd < 0 {
		return errors.New("pcap: drain requires a live packet socket")
	}
	version, err := unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION)
	if err != nil {
		return fmt.Errorf("pcap: read ring version: %w", err)
	}
	if version == unix.TPACKET_V3 {
		return errors.New("pcap: socket admission drain requires immediate capture mode")
	}
	var errorBuffer [errorBufferSize]C.char
	oldMode := C.pcap_getnonblock(p.cptr, &errorBuffer[0])
	if oldMode < 0 {
		return errors.New("pcap: cannot read nonblocking state")
	}
	if C.pcap_setnonblock(p.cptr, 1, &errorBuffer[0]) != 0 {
		return errors.New("pcap: cannot enable nonblocking drain")
	}
	defer func() {
		if C.pcap_setnonblock(p.cptr, oldMode, &errorBuffer[0]) != 0 {
			result = errors.Join(result, errors.New("pcap: cannot restore nonblocking state"))
		}
	}()
	// With no block-retirement delay, a quiet receive timeout is sufficient to
	// drain visible queues; the timestamp fence handles an in-flight old frame.
	quiet := p.timeout
	if quiet <= 0 {
		return errors.New("pcap: draining requires a positive capture timeout")
	}
	quietSince := time.Now()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("pcap: drain startup packets: %w", err)
		}
		switch status := p.pcapNextPacketEx(); status {
		case NextErrorOk:
			quietSince = time.Now()
		case NextErrorTimeoutExpired:
			if time.Since(quietSince) >= quiet {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("pcap: drain startup packets: %w", ctx.Err())
			case <-ticker.C:
			}
		case NextErrorNoMorePackets:
			return errors.New("pcap: packet socket ended during startup drain")
		default:
			return fmt.Errorf("pcap: startup drain failed: %s", status)
		}
	}
}
