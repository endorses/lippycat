//go:build linux
// +build linux

package pcap

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func socketTestHandle(t *testing.T) *Handle {
	t.Helper()
	h, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestSocketAdmissionRetiresReceiversAndRestoresBinding(t *testing.T) {
	for _, protocol := range []uint16{0x0300, 0x0008, 0xdd86} {
		original := &unix.SockaddrLinklayer{Ifindex: 7, Protocol: protocol}
		var bindings []unix.SockaddrLinklayer
		err := retireSocketReceivers(42, func(fd int) (unix.Sockaddr, error) {
			if fd != 42 {
				t.Fatalf("unexpected fd %d", fd)
			}
			return original, nil
		}, func(fd int, sa unix.Sockaddr) error {
			bindings = append(bindings, *sa.(*unix.SockaddrLinklayer))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(bindings) != 2 || bindings[0].Protocol == protocol || bindings[0].Protocol == 0 || bindings[1].Protocol != protocol || bindings[0].Ifindex != 7 || bindings[1].Ifindex != 7 {
			t.Fatalf("unsafe protocol retirement: %+v", bindings)
		}
		if original.Protocol != protocol {
			t.Fatal("original binding mutated")
		}
	}
}

func TestSocketAdmissionRetirementReportsFailure(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		calls := 0
		err := retireSocketReceivers(42, func(int) (unix.Sockaddr, error) {
			return &unix.SockaddrLinklayer{Ifindex: 7, Protocol: 0x0300}, nil
		}, func(int, unix.Sockaddr) error {
			calls++
			if calls == failAt {
				return unix.EPERM
			}
			return nil
		})
		if !errors.Is(err, unix.EPERM) || calls != failAt {
			t.Fatalf("retirement failure: calls %d error %v", calls, err)
		}
	}
	if err := retireSocketReceivers(42, func(int) (unix.Sockaddr, error) { return &unix.SockaddrInet4{}, nil }, unix.Bind); err == nil {
		t.Fatal("accepted nonpacket socket")
	}
}
func TestSocketAdmissionRejectsOfflineAndUnboundedDrain(t *testing.T) {
	h := socketTestHandle(t)
	if err := h.SetSocketFilter(0); err == nil || !strings.Contains(err.Error(), "live capture") {
		t.Fatalf("offline attach: %v", err)
	}
	if err := h.DrainSocketBuffer(context.Background()); err == nil || !strings.Contains(err.Error(), "bounded context") {
		t.Fatalf("unbounded drain: %v", err)
	}
}
func TestSocketAdmissionPreservesFilterOwnership(t *testing.T) {
	h := socketTestHandle(t)
	if err := h.SetBPFFilter("udp"); err != nil {
		t.Fatal(err)
	}
	if err := h.SetSocketFilter(0); err == nil || !strings.Contains(err.Error(), "fresh handle") {
		t.Fatalf("classic filter state: %v", err)
	}
	other := socketTestHandle(t)
	other.socketFilterOwned = true
	if err := other.SetBPFFilter("udp"); err == nil {
		t.Fatal("classic filter replaced socket ownership")
	}
	if err := other.SetBPFInstructionFilter([]BPFInstruction{{Code: 6, K: 65535}}); err == nil {
		t.Fatal("instruction filter replaced socket ownership")
	}
}
func TestSocketAdmissionClosedHandleDoesNotAccessC(t *testing.T) {
	h := socketTestHandle(t)
	h.Close()
	if err := h.SetSocketFilter(0); !errors.Is(err, io.EOF) {
		t.Fatalf("closed attach: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.DrainSocketBuffer(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("closed drain: %v", err)
	}
}
