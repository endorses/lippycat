//go:build tap || all

package voip

import (
	"bytes"
	"context"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

type tapPolicyResolver struct {
	active bool
	proof  RemoteCallAssociation
}

func (r *tapPolicyResolver) ResolveMedia(gopacket.Packet, string) (RemoteCallAssociation, bool) {
	return r.proof, r.active
}
func (r *tapPolicyResolver) ResolveSignalling(event sharedsip.Event, _ gopacket.Packet, iface string) (RemoteCallAssociation, bool) {
	return r.proof, r.active && iface == "media" && event.FromTag == "alice" && event.ToTag == "bob" && event.CallID == r.proof.CallID
}
func tapPolicyMessage() []byte {
	return []byte("INVITE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>;tag=alice\r\nTo: <sip:bob@example.test>;tag=bob\r\nCall-ID: policy\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
}
func TestTapTCPIndependentCapturePolicies(t *testing.T) {
	for _, sig := range []SignallingPolicy{SignallingMatched, SignallingAll, SignallingNone} {
		for _, media := range []MediaPolicy{MediaLocal, MediaProcessor} {
			for _, direct := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/direct=%t", sig, media, direct), func(t *testing.T) {
					ch := make(chan source.InjectedPacket, 10)
					handler := NewTapTCPHandler(ch)
					t.Cleanup(handler.Close)
					filter := &targetSubstringFilter{target: "absent"}
					if direct {
						filter.target = "alice"
					}
					handler.SetApplicationFilter(filter)
					registry := &recordingSDPRegistrar{calls: make(map[string]string)}
					handler.SetCallRegistry(registry)
					require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Signalling: sig, Media: media}, nil))
					captured := time.Unix(1700000000, 3456)
					want := sig == SignallingAll || sig == SignallingMatched && direct
					require.Equal(t, want, handler.HandleSIPMessageAt(tapPolicyMessage(), "policy", "192.0.2.1:5060", "198.51.100.2:5060", testNetFlow(t, "192.0.2.1", "198.51.100.2"), testTransportFlow(t, 5060, 5060), captured))
					handler.Close()
					require.Equal(t, direct && media == MediaLocal, len(registry.calls) == 1, "all-SIP forwarding cannot select local media")
					if want {
						require.Len(t, ch, 1)
						packet := <-ch
						require.Equal(t, "policy", packet.Metadata.Sip.CallId)
						require.Equal(t, captured, packet.PacketInfo.Packet.Metadata().Timestamp)
					} else {
						require.Empty(t, ch)
					}
				})
			}
		}
	}
}
func TestTapTCPRemoteSignallingRejectsReusedSelectionAtSinkRelease(t *testing.T) {
	message := tapPolicyMessage()
	event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
	require.NoError(t, err)
	info, ok := buildSIPPacketInfo(message, "192.0.2.1:5060", "198.51.100.2:5060", testNetFlow(t, "192.0.2.1", "198.51.100.2"), time.Unix(1, 0))
	require.True(t, ok)
	info.Interface = "media"
	proof := RemoteCallAssociation{CallID: "policy", Lifetime: callregistry.Lifetime{Session: 4, Generation: 1}, SelectionRevision: 1, ProcessorID: "processor", ControlGeneration: 2, InheritedFilterIDs: []string{"selected"}}
	resolver := &tapPolicyResolver{active: true, proof: proof}
	resolver.proof.Lifetime.Generation++
	policy := &tapCapturePolicy{policies: CapturePolicies{Signalling: SignallingMatched, Media: MediaProcessor}, remote: resolver}
	ch := make(chan source.InjectedPacket, 1)
	sink := tapInjectionSink{ch: ch, capturePolicy: policy}
	result := sink.HandleSIP(context.Background(), sipflow.SinkInput{Result: pipeline.SIPResultFromEvent(event, captureadapter.FromPacketInfo(info, pipeline.SourceLiveCapture)), Attachment: tapAttachment{remote: &tapRemoteReceipt{event: event, proof: proof, required: true}}})
	require.Equal(t, pipeline.OutcomeFiltered, result.Outcome)
	require.Empty(t, ch)
}
func TestTapTCPRemoteDialogPreservesActualSource(t *testing.T) {
	ch := make(chan source.InjectedPacket, 1)
	handler := NewTapTCPHandler(ch)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&targetSubstringFilter{target: "absent"})
	resolver := &tapPolicyResolver{active: true, proof: RemoteCallAssociation{CallID: "policy", InheritedFilterIDs: []string{"remote"}}}
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Media: MediaProcessor}, resolver))
	event, err := sharedsip.Parse(tapPolicyMessage(), sharedsip.ParseOptions{Timestamp: time.Unix(1, 0)})
	require.NoError(t, err)
	require.True(t, handler.HandleParsedSIPMessageFromSource(tapPolicyMessage(), event, "192.0.2.1:5060", "198.51.100.2:5060", testNetFlow(t, "192.0.2.1", "198.51.100.2"), testTransportFlow(t, 5060, 5060), pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "media"}))
	handler.Close()
	require.Len(t, ch, 1)
	injected := <-ch
	require.Equal(t, "media", injected.PacketInfo.Interface)
}

type tapProofFilter struct {
	epoch  byte
	target string
}

func (f *tapProofFilter) MatchPacket(packet gopacket.Packet) bool {
	return bytes.Contains(packet.TransportLayer().LayerPayload(), []byte(f.target))
}
func (f *tapProofFilter) MatchPacketWithSelectionProof(packet gopacket.Packet) (bool, []string, capturepolicy.FilterSelectionProof) {
	if !f.MatchPacket(packet) {
		return false, nil, nil
	}
	return true, []string{"same-id"}, capturepolicy.FilterSelectionProof{"same-id": {f.epoch}}
}
func (f *tapProofFilter) CurrentSelection(proof capturepolicy.FilterSelectionProof) (bool, []string) {
	if old, ok := proof["same-id"]; ok && old == ([32]byte{f.epoch}) {
		return true, []string{"same-id"}
	}
	return false, nil
}
func TestTapTCPSemanticSelectionRequiresCurrentDefinition(t *testing.T) {
	channel := make(chan source.InjectedPacket, 8)
	handler := NewTapTCPHandler(channel)
	defer handler.Close()
	filter := &tapProofFilter{epoch: 1, target: "alice"}
	handler.SetApplicationFilter(filter)
	forward := func(message []byte) bool {
		return handler.HandleSIPMessageAt(message, "policy", "192.0.2.1:5060", "198.51.100.2:5060", testNetFlow(t, "192.0.2.1", "198.51.100.2"), testTransportFlow(t, 5060, 5060), time.Unix(1, 0))
	}
	require.True(t, forward(tapPolicyMessage()))
	unknown := bytes.ReplaceAll(tapPolicyMessage(), []byte("alice"), []byte("unknown"))
	require.True(t, forward(unknown), "unchanged definition retains local sticky selection")
	filter.epoch = 2
	filter.target = "mallory"
	require.False(t, forward(unknown), "same ID replacement invalidates prior call selection")
	require.True(t, forward(bytes.ReplaceAll(tapPolicyMessage(), []byte("alice"), []byte("mallory"))))
	require.True(t, forward(unknown), "fresh matching evidence can select under the replacement")
}
