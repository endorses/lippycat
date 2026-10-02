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
