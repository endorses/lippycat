//go:build hunter || all

package voip

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// The fake deliberately checks complete endpoint/domain and dialog evidence;
// handler tests must not accidentally pass from a bare Call-ID match.
type policyRemoteResolver struct {
	mu         sync.Mutex
	active     bool
	sipAllowed bool
	generation uint64
	calls      int
	grantProof []byte
}

func (r *policyRemoteResolver) ResolveMedia(packet gopacket.Packet, iface string) (RemoteCallAssociation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !r.active || !ok || iface != "media-domain" || packet.NetworkLayer().NetworkFlow().Dst().String() != "192.168.1.200" || udp.DstPort != 45000 {
		return RemoteCallAssociation{}, false
	}
	return RemoteCallAssociation{CallID: "policy-call", Lifetime: callregistry.Lifetime{Session: 77, Generation: r.generation}, InheritedFilterIDs: []string{"remote-filter"}, CaptureSelectionProof: append([]byte(nil), r.grantProof...)}, true
}
func (r *policyRemoteResolver) ResolveSignalling(event sharedsip.Event, _ gopacket.Packet, iface string) (RemoteCallAssociation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if !r.active || !r.sipAllowed || iface != "media-domain" || event.CallID != "policy-call" || event.FromTag != "alice-tag" || event.ToTag != "bob-tag" {
		return RemoteCallAssociation{}, false
	}
	return RemoteCallAssociation{CallID: event.CallID, Lifetime: callregistry.Lifetime{Session: 77, Generation: r.generation}, InheritedFilterIDs: []string{"remote-filter"}}, true
}
func (r *policyRemoteResolver) withdraw() { r.mu.Lock(); r.active = false; r.mu.Unlock() }

func policySIPMessage(method, from, tags string) []byte {
	sdp := "v=0\r\nc=IN IP4 192.168.1.200\r\nm=audio 45000 RTP/AVP 0\r\n"
	return []byte(fmt.Sprintf("%s sip:bob@example.test SIP/2.0\r\nFrom: <sip:%s@example.test>;tag=%s\r\nTo: <sip:bob@example.test>;tag=bob-tag\r\nCall-ID: policy-call\r\nCSeq: 1 %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", method, from, tags, method, len(sdp), sdp))
}

func TestHunterIndependentPolicyMatrix(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, signalling := range []SignallingPolicy{SignallingMatched, SignallingAll, SignallingNone} {
			for _, media := range []MediaPolicy{MediaLocal, MediaProcessor} {
				for _, direct := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/direct=%t", transport, signalling, media, direct), func(t *testing.T) {
						forwarder := &recordingHunterForwarder{}
						buffers := NewBufferManager(time.Minute, 100)
						t.Cleanup(buffers.Close)
						tracker := TestCallTracker(t)
						filter := &hunterIdentityFilter{needle: "never-present", ids: []string{"local-filter"}}
						if direct {
							filter.needle = "alice"
						}
						policies := CapturePolicies{Signalling: signalling, Media: media}
						message := policySIPMessage("INVITE", "alice", "alice-tag")
						captured := time.Unix(1700000000, 1234)
						wantForward := signalling == SignallingAll || (signalling == SignallingMatched && direct)
						if transport == "udp" {
							handler := NewUDPPacketHandler(tracker, forwarder, buffers)
							t.Cleanup(handler.Close)
							handler.SetApplicationFilter(filter)
							require.NoError(t, handler.SetCapturePolicies(policies, nil))
							packet := createUDPPacket(5060, 5060, message)
							packet.Metadata().Timestamp = captured
							require.Equal(t, wantForward, handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "capture", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
							handler.Close()
						} else {
							handler := NewHunterForwardHandler(tracker, forwarder, buffers)
							t.Cleanup(handler.Close)
							handler.SetApplicationFilter(filter)
							require.NoError(t, handler.SetCapturePolicies(policies, nil))
							nf, tf := hunterFlow(t)
							require.Equal(t, wantForward, handler.HandleSIPMessageAt(message, "policy-call", "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, captured))
							handler.Close()
						}
						require.Equal(t, direct && media == MediaLocal, buffers.IsCallMatched("policy-call"), "export policy must never broaden media selection")
						if wantForward {
							require.Equal(t, 1, forwarder.count())
							record := forwarder.records[0]
							require.Equal(t, captured, record.packet.Metadata().Timestamp)
							require.Equal(t, "policy-call", record.meta.GetSip().GetCallId())
							if direct {
								require.Equal(t, []string{"local-filter"}, record.directIDs)
							} else {
								require.Empty(t, record.directIDs)
							}
						} else {
							require.Zero(t, forwarder.count())
						}
					})
				}
			}
		}
	}
}

func TestHunterProcessorMediaNeverFallsBackToLocalSelection(t *testing.T) {
	tracker := TestCallTracker(t)
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffers.Close)
	handler := NewUDPPacketHandler(tracker, forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&hunterPacketLevelFilter{directMatch: true, directIDs: []string{"broad-ip"}})
	resolver := &policyRemoteResolver{active: true}
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Signalling: SignallingNone, Media: MediaProcessor}, resolver))
	associateEndpointForTest(tracker, "192.168.1.200:45000", "local-call")
	buffers.MarkCallMatched("local-call", &CallMetadata{CallID: "local-call"}, "media-domain", layers.LinkTypeEthernet)
	payloads := [][]byte{{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, {0x80, 201, 0, 1, 0, 0, 0, 1}}
	for _, payload := range payloads {
		packet := createUDPPacket(30000, 45000, payload)
		info := capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}
		require.True(t, handler.HandleUDPPacket(info, packet.TransportLayer().(*layers.UDP)))
		record := forwarder.records[len(forwarder.records)-1]
		require.Equal(t, "policy-call", record.meta.GetSip().GetCallId())
		require.Equal(t, []string{"remote-filter"}, record.inheritedIDs)
		require.Empty(t, record.directIDs)
		info.Interface = "wrong-domain"
		require.False(t, handler.HandleUDPPacket(info, packet.TransportLayer().(*layers.UDP)))
	}
	resolver.withdraw()
	packet := createUDPPacket(30000, 45000, payloads[0])
	require.False(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
	require.Equal(t, 2, forwarder.count(), "expired remote rules must override retained local call and IP allowances")
}

func TestHunterRemoteSignallingNeedsCurrentDialog(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			tracker := TestCallTracker(t)
			forwarder := &recordingHunterForwarder{}
			buffers := NewBufferManager(time.Minute, 100)
			t.Cleanup(buffers.Close)
			resolver := &policyRemoteResolver{active: true, sipAllowed: true}
			policies := CapturePolicies{Signalling: SignallingMatched, Media: MediaProcessor}
			filter := &hunterIdentityFilter{needle: "absent"}
			send := func([]byte) bool { return false }
			closeHandler := func() {}
			if transport == "udp" {
				handler := NewUDPPacketHandler(tracker, forwarder, buffers)
				t.Cleanup(handler.Close)
				handler.SetApplicationFilter(filter)
				require.NoError(t, handler.SetCapturePolicies(policies, resolver))
				send = func(message []byte) bool {
					packet := createUDPPacket(5060, 5060, message)
					return handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP))
				}
				closeHandler = handler.Close
			} else {
				handler := NewHunterForwardHandler(tracker, forwarder, buffers)
				t.Cleanup(handler.Close)
				handler.captureInterface = "media-domain"
				handler.SetApplicationFilter(filter)
				require.NoError(t, handler.SetCapturePolicies(policies, resolver))
				nf, tf := hunterFlow(t)
				send = func(message []byte) bool {
					return handler.HandleSIPMessageAt(message, "policy-call", "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, time.Unix(1, 0))
				}
				closeHandler = handler.Close
			}
			require.False(t, send(policySIPMessage("BYE", "anonymous", "forged-tag")))
			require.True(t, send(policySIPMessage("BYE", "anonymous", "alice-tag")))
			require.Eventually(t, func() bool { return forwarder.count() == 1 }, time.Second, time.Millisecond)
			resolver.withdraw()
			require.False(t, send(policySIPMessage("BYE", "anonymous", "alice-tag")))
			closeHandler()
			require.Equal(t, 1, forwarder.count())
			require.Empty(t, forwarder.records[0].directIDs)
			require.Equal(t, []string{"remote-filter"}, forwarder.records[0].inheritedIDs)
			require.False(t, buffers.IsCallMatched("policy-call"))
		})
	}
}

func TestHunterRemoteSignallingRevalidatesAtSinkRelease(t *testing.T) {
	resolver := &policyRemoteResolver{active: true, sipAllowed: true}
	policies := defaultHunterCapturePolicy()
	require.NoError(t, policies.set(CapturePolicies{Media: MediaProcessor}, resolver))
	message := policySIPMessage("BYE", "anonymous", "alice-tag")
	packet := createUDPPacket(5060, 5060, message)
	event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
	require.NoError(t, err)
	env := envelopeForHunterPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet})
	forwarder := &recordingHunterForwarder{}
	sink := hunterForwardSink{forwarder: forwarder, capturePolicy: policies}
	resolver.withdraw()
	result := sink.HandleSIP(context.Background(), sipflow.SinkInput{Result: pipeline.SIPResultFromEvent(event, env), Attachment: remoteSignallingReceipt{event: event, required: true}})
	require.Equal(t, pipeline.OutcomeFiltered, result.Outcome)
	require.Zero(t, forwarder.count())
}

func TestHunterTCPPolicyPreservesCompletingSegmentSource(t *testing.T) {
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	forwarder := &recordingHunterForwarder{}
	handler := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.captureInterface = "configured-representative"
	handler.SetApplicationFilter(&hunterIdentityFilter{needle: "absent"})
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Media: MediaProcessor}, &policyRemoteResolver{active: true, sipAllowed: true}))
	message := policySIPMessage("BYE", "anonymous", "alice-tag")
	captured := time.Unix(1700000000, 2345)
	event, err := sharedsip.Parse(message, sharedsip.ParseOptions{Timestamp: captured})
	require.NoError(t, err)
	nf, tf := hunterFlow(t)
	require.True(t, handler.HandleParsedSIPMessageFromSource(message, event, "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "media-domain", InterfaceIndex: 12}))
	handler.Close()
	require.Equal(t, 1, forwarder.count())
	require.Equal(t, "media-domain", forwarder.records[0].iface)
	require.Equal(t, captured, forwarder.records[0].packet.Metadata().Timestamp)
}

func TestHunterProcessorRulesOverrideConventionalPortClassification(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	handler := NewUDPPacketHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&hunterIdentityFilter{needle: "absent"})
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Signalling: SignallingAll, Media: MediaProcessor}, &policyRemoteResolver{active: true}))
	// SIP uses a non-standard port, while RTP happens to use a SIP source port.
	sipPacket := createUDPPacket(5080, 5080, policySIPMessage("INVITE", "alice", "alice-tag"))
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: sipPacket, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, sipPacket.TransportLayer().(*layers.UDP)))
	rtpPacket := createUDPPacket(5060, 45000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: rtpPacket, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, rtpPacket.TransportLayer().(*layers.UDP)))
	handler.Close()
	require.Equal(t, 2, forwarder.count())
}

func TestHunterAllSignallingClearsWithdrawnInheritedEvidenceAtRelease(t *testing.T) {
	resolver := &policyRemoteResolver{active: true, sipAllowed: true}
	policies := defaultHunterCapturePolicy()
	require.NoError(t, policies.set(CapturePolicies{Signalling: SignallingAll, Media: MediaProcessor}, resolver))
	message := policySIPMessage("BYE", "anonymous", "alice-tag")
	packet := createUDPPacket(5060, 5060, message)
	event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
	require.NoError(t, err)
	env := envelopeForHunterPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet})
	setHunterFilterProvenance(env, nil, []string{"withdrawn-filter"})
	forwarder := &recordingHunterForwarder{}
	sink := hunterForwardSink{forwarder: forwarder, capturePolicy: policies}
	resolver.withdraw()
	result := sink.HandleSIP(context.Background(), sipflow.SinkInput{Result: pipeline.SIPResultFromEvent(event, env), Attachment: remoteSignallingReceipt{event: event}})
	require.Equal(t, pipeline.OutcomeAccepted, result.Outcome)
	require.Equal(t, 1, forwarder.count(), "explicit all-SIP export does not depend on remote media authorization")
	require.Empty(t, forwarder.records[0].inheritedIDs, "withdrawn rule must not supply inherited selection evidence")
}

type queuedSelectionForwarder struct {
	recordingHunterForwarder
	queueMu sync.Mutex
	check   func() bool
}

func (f *queuedSelectionForwarder) ForwardPacketWithSelectionCheck(_ gopacket.Packet, _ *data.PacketMetadata, _ string, _ layers.LinkType, _ []string, _ []string, current func() bool) error {
	f.queueMu.Lock()
	defer f.queueMu.Unlock()
	f.check = current
	return nil
}
func (f *queuedSelectionForwarder) selectionCheck() func() bool {
	f.queueMu.Lock()
	defer f.queueMu.Unlock()
	return f.check
}
func TestHunterRemoteMediaRetainsSelectionCheckUntilProducerAcceptance(t *testing.T) {
	resolver := &policyRemoteResolver{active: true, generation: 1}
	forwarder := &queuedSelectionForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	handler := NewUDPPacketHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Signalling: SignallingNone, Media: MediaProcessor}, resolver))
	packet := createUDPPacket(30000, 45000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
	check := forwarder.selectionCheck()
	require.NotNil(t, check)
	require.True(t, check())
	resolver.mu.Lock()
	resolver.generation++
	resolver.mu.Unlock()
	require.False(t, check(), "a reused Call-ID/endpoint cannot authorize the old queued packet")
}

type queuedCaptureProofForwarder struct {
	queuedSelectionForwarder
	proof []byte
}

func (f *queuedCaptureProofForwarder) ForwardPacketWithCaptureSelectionProof(_ gopacket.Packet, _ *data.PacketMetadata, _ string, _ layers.LinkType, _ []string, _ []string, proof []byte, current func() bool) error {
	f.queueMu.Lock()
	defer f.queueMu.Unlock()
	f.proof = append([]byte(nil), proof...)
	f.check = current
	return nil
}
func TestHunterRemoteMediaFreezesSignedProofUntilProducerAcceptance(t *testing.T) {
	resolver := &policyRemoteResolver{active: true, generation: 1, grantProof: []byte("original-signed-rule")}
	forwarder := &queuedCaptureProofForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	handler := NewUDPPacketHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	require.NoError(t, handler.SetCapturePolicies(CapturePolicies{Signalling: SignallingNone, Media: MediaProcessor}, resolver))
	packet := createUDPPacket(30000, 45000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "media-domain", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
	require.Equal(t, []byte("original-signed-rule"), forwarder.proof)
	require.True(t, forwarder.selectionCheck()())
	resolver.mu.Lock()
	resolver.grantProof = []byte("new-lease-rule")
	resolver.mu.Unlock()
	require.False(t, forwarder.selectionCheck()(), "same visible call cannot retag a packet under replacement proof")
	require.Equal(t, []byte("original-signed-rule"), forwarder.proof)
	require.Error(t, forwardPacketWithCaptureSelectionProof(&recordingHunterForwarder{}, packet, nil, "media-domain", layers.LinkTypeEthernet, nil, []string{"opaque"}, []byte("proof"), func() bool { return true }), "unsupported forwarder cannot drop required proof")
}
