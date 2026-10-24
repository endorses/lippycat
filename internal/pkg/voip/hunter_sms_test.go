//go:build hunter || all

package voip

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/smsflow"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// UCS2 SUBMIT, RP-DATA, destination +12345. Test bytes are independent of the
// decoder; short ASCII fixtures encode each UCS2 code unit as 00 xx.
func hunterSMS(t *testing.T, id, text string, seq int, part byte) []byte {
	t.Helper()
	var ud []byte
	first := byte(1)
	if part != 0 {
		first |= 0x40
		ud = []byte{5, 0, 3, 0x42, 2, part}
	}
	for _, ch := range text {
		require.Less(t, ch, rune(128))
		ud = append(ud, 0, byte(ch))
	}
	tp := append([]byte{first, 0, 5, 0x91, 0x21, 0x43, 0xf5, 0, 8, byte(len(ud))}, ud...)
	body := append([]byte{0, byte(seq), 0, 0, byte(len(tp))}, tp...)
	head := fmt.Sprintf("MESSAGE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:bob@example.test>\r\nCall-ID: %s\r\nCSeq: %d MESSAGE\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-%d\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: %d\r\n\r\n", id, seq, seq, len(body))
	return append([]byte(head), body...)
}

func TestHunterSMSOptionalAndMultipartFiltering(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		for _, policy := range []SignallingPolicy{SignallingMatched, SignallingAll, SignallingNone} {
			t.Run(transport+"/"+string(policy), func(t *testing.T) {
				forwarder := &recordingHunterForwarder{}
				buffers := NewBufferManager(time.Minute, 100)
				t.Cleanup(buffers.Close)
				tracker := TestCallTracker(t)
				processor := NewVoIPPacketProcessor(tracker, forwarder, buffers)
				t.Cleanup(processor.Close)
				tcp := NewHunterForwardHandler(tracker, forwarder, buffers)
				processor.SetTCPHandler(tcp)
				processor.SetApplicationFilter(&mutablePayloadFilter{needle: "alice"})
				require.NoError(t, processor.SetCapturePolicies(CapturePolicies{Signalling: policy, Media: MediaLocal}, nil))
				require.NoError(t, processor.SetSMSConfig(smsflow.Config{Keywords: []string{"secret"}}))
				nf, tf := hunterFlow(t)
				at := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
				send := func(raw []byte, id string) {
					if transport == "tcp" {
						tcp.HandleSIPMessageAt(raw, id, "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, at)
					} else {
						fixture := &udpSelectionHarness{t: t, ip: "192.0.2.1", peer: "198.51.100.2", family: "ipv4"}
						packet := fixture.packet(5060, 5060, raw)
						packet.Metadata().Timestamp = at
						info := capture.PacketInfo{Packet: packet, Interface: "test0", LinkType: layers.LinkTypeEthernet}
						processor.udpHandler.HandleUDPPacket(info, packet.TransportLayer().(*layers.UDP))
					}
					at = at.Add(time.Second)
				}
				send(hunterSMS(t, "same", "ordinary", 1, 0), "same")
				send(hunterSMS(t, "same", "sec", 2, 1), "same")
				processed := func() uint64 {
					s := processor.udpHandler.orchestrator.Stats()[hunterSIPSinkName]
					if transport == "tcp" {
						s = tcp.orchestrator.Stats()[hunterSIPSinkName]
					}
					return s.Accepted + s.Filtered + s.Dropped + s.RetryableFailures + s.PermanentFailures + s.Shutdown
				}
				require.Eventually(t, func() bool { return processed() >= 2 }, time.Second, time.Millisecond)
				require.Zero(t, forwarder.count())
				send(hunterSMS(t, "different-call", "ret", 3, 2), "different-call")
				require.Eventually(t, func() bool { return processed() >= 3 }, time.Second, time.Millisecond)
				tcp.orchestrator.Close()
				processor.udpHandler.orchestrator.Close()
				if policy == SignallingNone {
					require.Zero(t, forwarder.count())
					return
				}
				require.Equal(t, 2, forwarder.count())
				for _, record := range forwarder.records {
					require.Equal(t, "secret", record.meta.Sip.Sms.Assembly.Text)
				}
			})
		}
	}
}

func TestHunterSMSDisabledPreservesRawAndMetadata(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	h := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(h.Close)
	h.SetApplicationFilter(&mutablePayloadFilter{needle: "alice"})
	nf, tf := hunterFlow(t)
	msg := hunterSMS(t, "unfiltered", "arbitrary text", 1, 0)
	require.True(t, h.HandleSIPMessageAt(msg, "unfiltered", "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, time.Now()))
	require.Eventually(t, func() bool { return forwarder.count() == 1 }, time.Second, time.Millisecond)
	h.orchestrator.Close()
	require.Equal(t, 1, forwarder.count())
	require.Equal(t, msg, forwarder.records[0].packet.ApplicationLayer().LayerContents())
	require.Equal(t, "arbitrary text", forwarder.records[0].meta.Sip.Sms.Text)
}

func TestHunterSMSRetainsSelectionCheckUntilProducerSeal(t *testing.T) {
	forwarder := &queuedSelectionForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	h := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(h.Close)
	filter := &mutablePayloadFilter{needle: "alice"}
	h.SetApplicationFilter(filter)
	controller, err := smsflow.New(smsflow.Config{Keywords: []string{"secret"}})
	require.NoError(t, err)
	h.capturePolicy.sms.Close()
	h.capturePolicy.sms = controller
	nf, tf := hunterFlow(t)
	raw := hunterSMS(t, "producer-seal", "secret", 1, 0)
	require.True(t, h.HandleSIPMessageAt(raw, "producer-seal", "192.0.2.1:5060", "198.51.100.2:5060", nf, tf, time.Now()))
	require.Eventually(t, func() bool { return forwarder.selectionCheck() != nil }, time.Second, time.Millisecond)
	check := forwarder.selectionCheck()
	require.True(t, check())
	filter.set("withdrawn-target")
	require.False(t, check(), "an old queued SMS must retain its original selection through producer seal")
}

type smsRevisionFilter struct{ revision byte }

func (*smsRevisionFilter) MatchPacket(gopacket.Packet) bool { return true }
func (f *smsRevisionFilter) MatchPacketWithSelectionProof(gopacket.Packet) (bool, []string, capturepolicy.FilterSelectionProof) {
	return true, []string{"selected"}, capturepolicy.FilterSelectionProof{"selected": [32]byte{f.revision}}
}
func (f *smsRevisionFilter) CurrentSelection(proof capturepolicy.FilterSelectionProof) (bool, []string) {
	if proof["selected"] == ([32]byte{f.revision}) {
		return true, []string{"selected"}
	}
	return false, nil
}

func TestHunterSMSInheritedSelectionCannotBorrowReplacementProof(t *testing.T) {
	tracker := TestCallTracker(t)
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	buffers.BindRegistry(tracker.AdmissionRegistry(), 64)
	filter := &smsRevisionFilter{revision: 1}
	buffers.SetSelectionProofMatcher(filter)
	tracker.GetOrCreateCall("inherited", layers.LinkTypeEthernet)
	buffers.StoreMatchedSelection("inherited", []string{"selected"}, capturepolicy.FilterSelectionProof{"selected": [32]byte{1}})
	buffers.MarkCallMatched("inherited", &CallMetadata{CallID: "inherited"}, "test0", layers.LinkTypeEthernet)
	frozen := buffers.SIPSelectionCheck("inherited")
	require.True(t, frozen())
	filter.revision = 2
	buffers.StoreMatchedSelection("inherited", []string{"selected"}, capturepolicy.FilterSelectionProof{"selected": [32]byte{2}})
	require.True(t, buffers.SelectionProofCurrent("inherited"), "replacement is valid for new observations")
	require.False(t, frozen(), "replacement cannot authorize the retained contributor")
}

func TestHunterSMSJoinsMappedInterfacesButSeparatesDomains(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	create := func(domain uint32) *VoIPPacketProcessor {
		buffers := NewBufferManager(time.Minute, 20)
		t.Cleanup(buffers.Close)
		p := NewVoIPPacketProcessor(TestCallTracker(t), forwarder, buffers)
		t.Cleanup(p.Close)
		p.SetApplicationFilter(&mutablePayloadFilter{needle: "alice"})
		require.NoError(t, p.SetSMSConfig(smsflow.Config{Keywords: []string{"secret"}}))
		p.SetSMSObservationDomain(domain)
		return p
	}
	first, other := create(7), create(8)
	fixture := &udpSelectionHarness{t: t, ip: "192.0.2.1", peer: "198.51.100.2", family: "ipv4"}
	send := func(p *VoIPPacketProcessor, iface, id, text string, part byte) {
		raw := hunterSMS(t, id, text, int(part), part)
		packet := fixture.packet(5060, 5060, raw)
		p.udpHandler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: iface, LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP))
	}
	send(first, "interface-a", "first", "sec", 1)
	send(other, "interface-b", "other-domain", "ret", 2)
	require.Eventually(t, func() bool {
		return first.udpHandler.SIPStats()[hunterSIPSinkName].Accepted == 1 && other.udpHandler.SIPStats()[hunterSIPSinkName].Accepted == 1
	}, time.Second, time.Millisecond)
	require.Zero(t, forwarder.count())
	send(first, "interface-b", "second", "ret", 2)
	require.Eventually(t, func() bool { return forwarder.count() == 2 }, time.Second, time.Millisecond)
	forwarder.mu.Lock()
	defer forwarder.mu.Unlock()
	for _, record := range forwarder.records {
		require.Equal(t, "secret", record.meta.Sip.Sms.Assembly.Text)
	}
}

func TestHunterSMSFilterRejectsInseparableTrailingSIP(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			forwarder := &recordingHunterForwarder{}
			buffers := NewBufferManager(time.Minute, 10)
			t.Cleanup(buffers.Close)
			p := NewVoIPPacketProcessor(TestCallTracker(t), forwarder, buffers)
			t.Cleanup(p.Close)
			p.SetApplicationFilter(&mutablePayloadFilter{needle: "alice"})
			config := smsflow.Config{}
			if enabled {
				config.Keywords = []string{"secret"}
			}
			require.NoError(t, p.SetSMSConfig(config))
			raw := append(hunterSMS(t, "first", "secret", 1, 0), hunterSMS(t, "trailing", "nonmatching", 2, 0)...)
			fixture := &udpSelectionHarness{t: t, ip: "192.0.2.1", peer: "198.51.100.2", family: "ipv4"}
			packet := fixture.packet(5060, 5060, raw)
			p.udpHandler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "test0", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP))
			require.Eventually(t, func() bool { return p.udpHandler.SIPStats()[hunterSIPSinkName].Accepted == 1 }, time.Second, time.Millisecond)
			if enabled {
				require.Zero(t, forwarder.count())
			} else {
				require.Equal(t, 1, forwarder.count())
				require.Equal(t, raw, forwarder.records[0].packet.TransportLayer().LayerPayload())
			}
		})
	}
}

func TestHunterSMSLegacyUDPIdentitySelection(t *testing.T) {
	sipusers.ClearAll()
	sipusers.AddSipUser("alice", &sipusers.SipUser{})
	t.Cleanup(sipusers.ClearAll)
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	h := NewUDPPacketHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(h.Close)
	raw := hunterSMS(t, "legacy", "hello", 1, 0)
	fixture := &udpSelectionHarness{t: t, ip: "192.0.2.1", peer: "198.51.100.2", family: "ipv4"}
	packet := fixture.packet(5060, 5060, raw)
	require.True(t, h.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "test0", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
	require.Eventually(t, func() bool { return forwarder.count() == 1 }, time.Second, time.Millisecond)
	require.Equal(t, raw, forwarder.records[0].packet.TransportLayer().LayerPayload())
}
