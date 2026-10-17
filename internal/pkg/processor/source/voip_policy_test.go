package source

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type sourcePolicyFilter struct{ direct bool }

func (f *sourcePolicyFilter) MatchPacket(gopacket.Packet) bool { return f.direct }
func (f *sourcePolicyFilter) MatchPacketWithIDs(gopacket.Packet) (bool, []string) {
	if f.direct {
		return true, []string{"local"}
	}
	return false, nil
}
func (*sourcePolicyFilter) MatchPacketLevelWithIDs(gopacket.Packet) (bool, []string) {
	return true, []string{"independent-ip"}
}

type sourcePolicyResolver struct {
	mu     sync.Mutex
	active bool
	proof  capturepolicy.RemoteCallAssociation
}

func (r *sourcePolicyResolver) ResolveMedia(packet gopacket.Packet, iface string) (capturepolicy.RemoteCallAssociation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !r.active || !ok || iface != "media" || udp.DstPort != 45000 || packet.NetworkLayer().NetworkFlow().Dst().String() != "192.0.2.2" {
		return capturepolicy.RemoteCallAssociation{}, false
	}
	return r.proof, true
}
func (r *sourcePolicyResolver) ResolveSignalling(event sharedsip.Event, _ gopacket.Packet, iface string) (capturepolicy.RemoteCallAssociation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active || iface != "media" || event.CallID != "policy" || event.FromTag != "alice" || event.ToTag != "bob" {
		return capturepolicy.RemoteCallAssociation{}, false
	}
	return r.proof, true
}
func sourcePolicyPacket(t *testing.T, payload []byte, port uint16) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: netip.MustParseAddr("192.0.2.1").AsSlice(), DstIP: netip.MustParseAddr("192.0.2.2").AsSlice(), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 5060, DstPort: layers.UDPPort(port)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(1700000000, 2345)
	return capture.PacketInfo{Packet: packet, Interface: "media", LinkType: layers.LinkTypeRaw}
}
func sourcePolicyMessage() []byte {
	sdp := "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 45000 RTP/AVP 0\r\n"
	return []byte(fmt.Sprintf("INVITE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>;tag=alice\r\nTo: <sip:bob@example.test>;tag=bob\r\nCall-ID: policy\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(sdp), sdp))
}
func TestLocalSourceIndependentVoIPPolicies(t *testing.T) {
	for _, sig := range []capturepolicy.SignallingPolicy{capturepolicy.SignallingMatched, capturepolicy.SignallingAll, capturepolicy.SignallingNone} {
		for _, media := range []capturepolicy.MediaPolicy{capturepolicy.MediaLocal, capturepolicy.MediaProcessor} {
			for _, direct := range []bool{false, true} {
				if sig == capturepolicy.SignallingMatched && media == capturepolicy.MediaLocal {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/direct=%t", sig, media, direct), func(t *testing.T) {
					s := NewLocalSource(LocalSourceConfig{ProtocolMode: "voip"})
					filter := &sourcePolicyFilter{direct: direct}
					s.SetApplicationFilter(filter)
					cfg := voipprocessor.DefaultConfig()
					cfg.ApplicationFilter = filter
					cfg.NeedFilterIDs = true
					adapter := voipprocessor.NewSourceAdapter(voipprocessor.New(cfg))
					s.SetVoIPProcessor(adapter)
					t.Cleanup(adapter.Close)
					require.NoError(t, s.SetCapturePolicies(capturepolicy.CapturePolicies{Signalling: sig, Media: media}, nil))
					handled, accepted := s.policyPacket(sourcePolicyPacket(t, sourcePolicyMessage(), 5060), nil)
					require.True(t, handled)
					expected := sig == capturepolicy.SignallingAll || sig == capturepolicy.SignallingMatched && direct
					require.Equal(t, expected, accepted != nil)
					selected := direct && media == capturepolicy.MediaLocal
					require.Equal(t, selected, len(adapter.ActiveCalls()) == 1, "export-all cannot create a local media selection")
					if accepted != nil {
						require.Equal(t, "policy", accepted.packet.Metadata.Sip.CallId)
						require.Equal(t, time.Unix(1700000000, 2345).UnixNano(), accepted.packet.TimestampNs)
					}
				})
			}
		}
	}
}
func TestLocalSourceRemoteMediaRevalidatesOpaqueSelectionAtBatchRelease(t *testing.T) {
	for _, change := range []string{"unchanged", "withdrawn", "reused call", "selection revision", "control generation"} {
		t.Run(change, func(t *testing.T) {
			cfg := DefaultLocalSourceConfig()
			cfg.ProtocolMode = "voip"
			s := NewLocalSource(cfg)
			s.SetApplicationFilter(&sourcePolicyFilter{})
			proof := capturepolicy.RemoteCallAssociation{CallID: "policy", Lifetime: callregistry.Lifetime{Session: 9, Generation: 1}, SelectionRevision: 1, ProcessorID: "processor", ControlGeneration: 2, InheritedFilterIDs: []string{"remote"}}
			remote := &sourcePolicyResolver{active: true, proof: proof}
			require.NoError(t, s.SetCapturePolicies(capturepolicy.CapturePolicies{Signalling: capturepolicy.SignallingNone, Media: capturepolicy.MediaProcessor}, remote))
			info := sourcePolicyPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, 45000)
			handled, accepted := s.policyPacket(info, nil)
			require.True(t, handled)
			require.NotNil(t, accepted)
			completed := false
			s.appendPolicyPacket(accepted, func() { completed = true })
			switch change {
			case "withdrawn":
				remote.active = false
			case "reused call":
				remote.proof.Lifetime.Generation++
			case "selection revision":
				remote.proof.SelectionRevision++
			case "control generation":
				remote.proof.ControlGeneration++
			}
			s.sendBatch()
			if change == "unchanged" {
				require.Len(t, s.batches, 1)
				batch := <-s.batches
				require.Len(t, batch.Envelopes, 1)
				require.Equal(t, []string{"remote"}, batch.Envelopes[0].InheritedMatchedFilterIDs)
				require.Empty(t, batch.Envelopes[0].DirectMatchedFilterIDs)
				batch.RunAfterProcess()
			} else {
				require.Empty(t, s.batches)
				require.Equal(t, uint64(1), s.Stats().PacketsDropped)
			}
			require.True(t, completed)
		})
	}
}
func TestLocalSourceAllSIPExportClearsExpiredInheritedEvidence(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{ProtocolMode: "voip"})
	s.SetApplicationFilter(&sourcePolicyFilter{})
	remote := &sourcePolicyResolver{active: true, proof: capturepolicy.RemoteCallAssociation{CallID: "policy", InheritedFilterIDs: []string{"remote"}}}
	require.NoError(t, s.SetCapturePolicies(capturepolicy.CapturePolicies{Signalling: capturepolicy.SignallingAll, Media: capturepolicy.MediaProcessor}, remote))
	_, accepted := s.policyPacket(sourcePolicyPacket(t, sourcePolicyMessage(), 5060), nil)
	require.NotNil(t, accepted)
	s.appendPolicyPacket(accepted, nil)
	remote.active = false
	s.sendBatch()
	require.Len(t, s.batches, 1)
	batch := <-s.batches
	require.Empty(t, batch.Envelopes[0].InheritedMatchedFilterIDs)
}

type sourceProofFilter struct {
	sourcePolicyFilter
	epoch  byte
	target string
}

func (f *sourceProofFilter) MatchPacketWithSelectionProof(packet gopacket.Packet) (bool, []string, capturepolicy.FilterSelectionProof) {
	matched := bytes.Contains(packet.TransportLayer().LayerPayload(), []byte(f.target))
	if !matched {
		return false, nil, nil
	}
	return true, []string{"same-id"}, capturepolicy.FilterSelectionProof{"same-id": {f.epoch}}
}
func (f *sourceProofFilter) CurrentSelection(proof capturepolicy.FilterSelectionProof) (bool, []string) {
	if old, ok := proof["same-id"]; ok && old == ([32]byte{f.epoch}) {
		return true, []string{"same-id"}
	}
	return false, nil
}
func TestLocalSourceSemanticSelectionSurvivesRenewalAndRejectsReplacement(t *testing.T) {
	filter := &sourceProofFilter{epoch: 1, target: "alice"}
	s := NewLocalSource(LocalSourceConfig{ProtocolMode: "voip"})
	s.SetApplicationFilter(filter)
	info := sourcePolicyPacket(t, sourcePolicyMessage(), 5060)
	s.storeCallSelection("owned", []string{"same-id"}, info.Packet)
	require.Equal(t, []string{"same-id"}, s.cachedFilterIDsForCall("owned"))
	// A lease refresh leaves semantic epoch unchanged.
	s.storeCallSelection("owned", []string{"same-id"}, info.Packet)
	require.Equal(t, []string{"same-id"}, s.cachedFilterIDsForCall("owned"))
	cfg := voipprocessor.DefaultConfig()
	cfg.ApplicationFilter = filter
	cfg.NeedFilterIDs = true
	proc := voipprocessor.New(cfg)
	defer proc.Close()
	adapter := voipprocessor.NewSourceAdapter(proc)
	first := adapter.ProcessPacketInfo(info)
	require.NotNil(t, first.GetMetadata())
	filter.epoch = 2
	filter.target = "mallory"
	require.Empty(t, s.cachedFilterIDsForCall("owned"), "same ID with a new pattern cannot retain inherited authority")
	bye := bytes.Replace(sourcePolicyMessage(), []byte("INVITE"), []byte("BYE"), -1)
	bye = bytes.ReplaceAll(bye, []byte("alice"), []byte("unknown"))
	rejected := adapter.ProcessPacketInfo(sourcePolicyPacket(t, bye, 5060))
	require.Nil(t, rejected.GetMetadata(), "local processor cannot mutate the dialog through stale sticky selection")
}

func TestLocalProcessorSharesCurrentSelectionAcrossTCPAndUDP(t *testing.T) {
	filter := &sourceProofFilter{epoch: 1, target: "alice"}
	cfg := voipprocessor.DefaultConfig()
	cfg.ApplicationFilter = filter
	cfg.NeedFilterIDs = true
	proc := voipprocessor.New(cfg)
	defer proc.Close()
	info := sourcePolicyPacket(t, sourcePolicyMessage(), 5060)
	event, err := sharedsip.Parse(sourcePolicyMessage(), sharedsip.ParseOptions{})
	require.NoError(t, err)
	metadata, _, err := proc.ProcessReassembledSIPResultWithLifetime(pipeline.SIPResultFromEvent(event, captureadapter.FromPacketInfo(info, pipeline.SourceLiveCapture)))
	require.NoError(t, err)
	require.NotNil(t, metadata)
	adapter := voipprocessor.NewSourceAdapter(proc)
	unknown := bytes.ReplaceAll(sourcePolicyMessage(), []byte("alice"), []byte("unknown"))
	require.NotNil(t, adapter.ProcessPacketInfo(sourcePolicyPacket(t, unknown, 5060)).GetMetadata(), "TCP direct evidence retains current selection for UDP dialog signalling")
	filter.epoch = 2
	filter.target = "mallory"
	_, _, err = proc.ProcessReassembledSIPResultWithLifetime(pipeline.SIPResultFromEvent(event, captureadapter.FromPacketInfo(info, pipeline.SourceLiveCapture)))
	require.Error(t, err, "old TCP selection must be rejected before registry mutation")
}
