//go:build linux

package ebpfadmission

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// shadowBoundaryBackend preserves real map operations and adds only test hooks
// at actual publication boundaries. No kernel decision or timestamp is faked.
type shadowBoundaryBackend struct {
	*Backend
	beforePut           func()
	publishedNS         uint64
	publishedGeneration uint64
	t                   *testing.T
}

func (b *shadowBoundaryBackend) PutEndpoint(ctx context.Context, key mediaadmission.EndpointKey) error {
	if b.beforePut != nil {
		callback := b.beforePut
		b.beforePut = nil
		callback()
	}
	return b.Backend.PutEndpoint(ctx, key)
}
func (b *shadowBoundaryBackend) SetControl(ctx context.Context, domain mediaadmission.DomainID, control mediaadmission.Control) error {
	if err := b.Backend.SetControl(ctx, domain, control); err != nil {
		return err
	}
	if control.Generation != 0 {
		b.publishedNS = monotonicForShadow(b.t)
		b.publishedGeneration = control.Generation
	}
	return nil
}
func monotonicForShadow(t *testing.T) uint64 {
	t.Helper()
	var now unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
	return uint64(now.Nano())
}
func shadowFingerprint(packet []byte) uint32 {
	hash := uint32(2166136261)
	for offset := 0; offset < 32; offset += 4 {
		hash = (hash ^ binary.NativeEndian.Uint32(packet[offset:offset+4])) * 16777619
	}
	return hash
}

// This validates correlated evidence from the real kernel ring. Controlled
// serialized injection and unique IPv4 IDs establish identity in this test only;
// the same bounded header fingerprint cannot establish identity on live traffic.
func TestKernelShadowHistoricalCorrelation(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("requires explicit privileged kernel execution")
	}
	backend, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 1, EvidenceBytes: 4096, ShadowSampleEvery: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()
	wrapper := &shadowBoundaryBackend{Backend: backend, t: t}
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = mediaadmission.ModeShadow
	controller, err := mediaadmission.NewController(t.Context(), cfg, wrapper)
	require.NoError(t, err)
	defer func() { require.NoError(t, controller.Close(context.Background())) }()
	program, err := backend.NewProgram(0, 65535, 1, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, program.Close()) }()
	reader, err := backend.DecisionReader()
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	packet := func(id uint16) []byte {
		p := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
		binary.BigEndian.PutUint16(p[18:20], id)
		return p
	}
	emit := func(p []byte) mediaadmission.ShadowSample {
		t.Helper()
		before := monotonicForShadow(t)
		ret, _, err := program.Test(testRunFrame(p))
		require.NoError(t, err)
		require.Equal(t, uint32(65535), ret, "shadow preserves capture")
		reader.SetDeadline(time.Now().Add(time.Second))
		record, err := reader.Read()
		require.NoError(t, err)
		observed := monotonicForShadow(t)
		event, err := DecodeDecision(record.RawSample)
		require.NoError(t, err)
		require.GreaterOrEqual(t, event.TimeNS, before)
		require.LessOrEqual(t, event.TimeNS, observed)
		require.Equal(t, shadowFingerprint(p), event.Fingerprint)
		return mediaadmission.ShadowSample{Domain: event.Domain, Generation: event.Generation, EventMonotonicNS: event.TimeNS, ObservedMonotonicNS: observed, ObservedAt: time.Now(), Reason: event.Reason, Length: event.Length, Fingerprint: event.Fingerprint, Source: event.Source, Destination: event.Destination}
	}
	beforeSelection := emit(packet(101))
	require.Zero(t, beforeSelection.Reason)
	owner, err := controller.BeginOwner(0, "controlled-call")
	require.NoError(t, err)
	selectedNS := monotonicForShadow(t)
	endpoint, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.2"), 5000)
	require.NoError(t, err)
	var publicationWindow mediaadmission.ShadowSample
	wrapper.beforePut = func() { publicationWindow = emit(packet(102)) }
	require.NoError(t, controller.UpdateOwner(t.Context(), 0, owner, []mediaadmission.EndpointKey{endpoint}))
	status := controller.Status()
	require.Len(t, status, 1)
	require.Equal(t, status[0].DesiredGeneration, status[0].InstalledGeneration)
	require.Equal(t, status[0].InstalledGeneration, wrapper.publishedGeneration)
	require.Greater(t, wrapper.publishedNS, selectedNS)
	afterPublication := emit(packet(103))
	require.Equal(t, uint32(1), afterPublication.Reason)
	// An out-of-band map deletion models unexpected kernel/controller divergence.
	// The historical event still carries the last confirmed publication generation.
	require.NoError(t, backend.DeleteEndpoint(t.Context(), endpoint))
	unexpectedlyRejected := emit(packet(104))
	require.Zero(t, unexpectedlyRejected.Reason)
	require.Equal(t, wrapper.publishedGeneration, unexpectedlyRejected.Generation)
	window := mediaadmission.ShadowWindow{IdentityVerified: true, SelectedNS: selectedNS, PublishedNS: wrapper.publishedNS, PublishedGeneration: wrapper.publishedGeneration}
	require.Equal(t, mediaadmission.ShadowPreselection, mediaadmission.ClassifyShadow(beforeSelection, window))
	require.Equal(t, mediaadmission.ShadowPublicationWindow, mediaadmission.ClassifyShadow(publicationWindow, window))
	require.Equal(t, mediaadmission.ShadowAdmitted, mediaadmission.ClassifyShadow(afterPublication, window))
	require.Equal(t, mediaadmission.ShadowUnexpectedRejection, mediaadmission.ClassifyShadow(unexpectedlyRejected, window))
	// Identical packets produce identical header hashes. Without independently
	// verified identity this evidence must stay unclassified, even after a match.
	duplicate := emit(packet(104))
	require.Equal(t, unexpectedlyRejected.Fingerprint, duplicate.Fingerprint)
	window.IdentityVerified = false
	require.Equal(t, mediaadmission.ShadowUnclassified, mediaadmission.ClassifyShadow(duplicate, window))
	// Stop consuming the deliberately small ring and exhaust its bounded space.
	// Counts reveal incomplete evidence; dropped records cannot be reconstructed.
	for i := 0; i < 128; i++ {
		_, _, err := program.Test(testRunFrame(packet(uint16(200 + i))))
		require.NoError(t, err)
	}
	counters, err := backend.Counters(0)
	require.NoError(t, err)
	require.Greater(t, counters[11], uint64(0), "ring overflow must expose incomplete evidence")
}
