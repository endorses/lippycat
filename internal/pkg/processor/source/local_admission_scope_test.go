package source

import (
	"context"
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// The direct/inherited fields tested here are exactly the provenance consumed by
// the LI processor; raw Call-ID equality is never authority to union identities.
func TestLocalSourceScopedAdmissionIdentityProvenance(t *testing.T) {
	cfg := DefaultLocalSourceConfig()
	cfg.BatchSize = 20
	cfg.BatchTimeout = time.Hour
	s := NewLocalSource(cfg)
	s.ctx = context.Background()
	admission := mediaadmission.DefaultConfig()
	admission.InterfaceDomains = map[string]mediaadmission.DomainID{"left": 0, "right": 1, "unselected": 2}
	children := make(map[mediaadmission.DomainID]*voipprocessor.SourceAdapter)
	for domain := mediaadmission.DomainID(0); domain < 3; domain++ {
		id := []string{"li-task-left", "li-task-right", ""}[domain]
		filter := phase2Filter(func(gopacket.Packet) (bool, []string) {
			if id == "" {
				return false, nil
			}
			return true, []string{id}
		}, nil)
		pc := voipprocessor.DefaultConfig()
		pc.ApplicationFilter = filter
		pc.NeedFilterIDs = true
		children[domain] = voipprocessor.NewSourceAdapter(voipprocessor.New(pc))
	}
	adapter, err := voipprocessor.NewScopedSourceAdapter(admission, children, time.Hour)
	require.NoError(t, err)
	defer adapter.Close()
	s.SetVoIPProcessor(adapter)
	s.appFilter = phase2Filter(func(gopacket.Packet) (bool, []string) { return false, nil }, func(gopacket.Packet) (bool, []string) { return false, nil })
	input := make(chan capture.PacketInfo, 6)
	for _, iface := range []string{"left", "right", "unselected"} {
		packet := phase0SIPPacket(t, "INVITE", true)
		packet.Interface = iface
		input <- packet
	}
	for _, iface := range []string{"left", "right", "unselected"} {
		packet := phase0RTPPacket(t)
		packet.Interface = iface
		input <- packet
	}
	close(input)
	done := make(chan struct{})
	go func() { s.batchingWorkerWithInjection(input, false); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("source worker did not drain")
	}
	var packets []*data.CapturedPacket
	select {
	case batch := <-s.Batches():
		for _, envelope := range batch.Envelopes {
			packet, err := grpcadapter.ToCapturedPacket(envelope)
			require.NoError(t, err)
			packets = append(packets, packet)
		}
	default:
		t.Fatal("no selected packets")
	}
	require.Len(t, packets, 4)
	for i, id := range []string{"li-task-left", "li-task-right"} {
		require.Equal(t, []string{id}, packets[i].DirectMatchedFilterIds)
		require.Empty(t, packets[i].InheritedMatchedFilterIds)
		media := packets[i+2]
		require.NotNil(t, media.Metadata.GetRtp())
		require.Empty(t, media.DirectMatchedFilterIds)
		require.Equal(t, []string{id}, media.InheritedMatchedFilterIds)
		require.Equal(t, packets[i].Metadata.GetSip().CallId, media.Metadata.GetSip().CallId)
	}
	require.Equal(t, packets[0].Metadata.GetSip().CallId, packets[1].Metadata.GetSip().CallId)
}
