package callselection

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

func trackerFixture(t *testing.T, alter func(*Config)) (*Tracker, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Now()}
	config := Config{
		Domains: []mediaadmission.DomainID{1, 2}, Processor: voipprocessor.DefaultConfig(), Limits: mediaadmission.DefaultConfig(), TrailingGrace: 2 * time.Second, Now: clock.Now,
		Authorize: func(source Source) error {
			if source.NodeID != "hunter-a" && source.NodeID != "hunter-b" && !(source.Local && source.NodeID == "tap") {
				return ErrSource
			}
			return nil
		},
		Match: func(event sip.Event, _ *pipeline.PacketEnvelope, _ Source) (Selection, error) {
			return Selection{Selected: event.Method == "INVITE" && event.FromUser == "alice", FilterIDs: []string{"identity-filter"}, Revision: 4}, nil
		},
	}
	if alter != nil {
		alter(&config)
	}
	tracker, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, tracker.Close()) })
	return tracker, clock
}

func udpEnvelope(t *testing.T, clock *testClock, node string, domain mediaadmission.DomainID, payload []byte, media bool) (*pipeline.PacketEnvelope, Source) {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	if media {
		udp.SrcPort, udp.DstPort = 40000, 50000
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, gopacket.Payload(payload)))
	envelope := &pipeline.PacketEnvelope{Data: buffer.Bytes(), LinkType: layers.LinkTypeRaw, CaptureTime: clock.Now(), Source: pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: node, InterfaceName: "capture0"}}
	return envelope, Source{NodeID: node, InterfaceName: "capture0", Domain: domain}
}

func message(start, fromTag, toTag, branch string, cseq int, method, body string) []byte {
	to := "<sip:bob@example.invalid>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=%s\r\nFrom: <sip:alice@example.invalid>;tag=%s\r\nTo: %s\r\nCall-ID: call@example.invalid\r\nCSeq: %d %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", start, branch, fromTag, to, cseq, method, len(body), body))
}

func invite(fromTag string) []byte {
	return message("INVITE sip:bob@example.invalid SIP/2.0", fromTag, "", "z9hG4bK-invite", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
}
func response() []byte {
	return message("SIP/2.0 200 OK", "alice-tag", "bob-tag", "z9hG4bK-invite", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 50000 RTP/AVP 0\r\n")
}
func rtp() []byte { return []byte{0x80, 0, 0, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 2, 3} }

func process(t *testing.T, tracker *Tracker, clock *testClock, node string, payload []byte) Result {
	t.Helper()
	envelope, source := udpEnvelope(t, clock, node, 1, payload, false)
	result, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	return result
}

func TestSelectedCallMovesSourcesWithoutNewSignalling(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	first := process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	require.NotNil(t, first.Call)
	lifetime := first.Call.Info.Lifetime
	require.Equal(t, []string{"identity-filter"}, first.DirectFilterIDs)
	answer := process(t, tracker, clock, "hunter-b", response())
	require.Equal(t, lifetime, answer.Call.Info.Lifetime)
	require.Equal(t, "bob-tag", answer.Call.ToTag)
	media, source := udpEnvelope(t, clock, "hunter-b", 1, rtp(), true)
	result, err := tracker.Process(media, source)
	require.NoError(t, err)
	require.NotNil(t, result.Call)
	require.Equal(t, lifetime, result.Call.Info.Lifetime)
	require.Equal(t, callregistry.MediaResolved, result.Process.MediaResolution.Status)
	require.Equal(t, pipeline.SourceGRPC, media.Source.Kind)
	require.Equal(t, "hunter-b", media.Source.NodeID)
	bye := message("BYE sip:bob@example.invalid SIP/2.0", "alice-tag", "bob-tag", "z9hG4bK-bye", 2, "BYE", "")
	ending := process(t, tracker, clock, "hunter-b", bye)
	require.True(t, ending.Call.Completing)
	require.Equal(t, lifetime, ending.Call.Info.Lifetime)
	require.Equal(t, []string{"identity-filter"}, ending.InheritedFilterIDs)
	require.Len(t, tracker.Snapshot(), 1, "completion keeps exact attribution through configured trailing grace")
	clock.Advance(2 * time.Second)
	tracker.Sweep()
	require.Empty(t, tracker.Snapshot())
	result, err = tracker.Process(media, source)
	require.NoError(t, err)
	require.Nil(t, result.Call)
	require.Equal(t, callregistry.MediaUnresolved, result.Process.MediaResolution.Status)
}

func TestWrongTagsAndTransactionsCannotMutateOrEndCall(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	process(t, tracker, clock, "hunter-a", response())
	before := tracker.Snapshot()[0]
	for _, payload := range [][]byte{
		message("BYE sip:bob@example.invalid SIP/2.0", "forged", "bob-tag", "z9hG4bK-bye", 2, "BYE", ""),
		message("SIP/2.0 200 OK", "alice-tag", "bob-tag", "wrong-branch", 2, "BYE", ""),
		message("ACK sip:bob@example.invalid SIP/2.0", "alice-tag", "bob-tag", "z9hG4bK-ack", 77, "ACK", "v=0\r\nc=IN IP4 192.0.2.99\r\nm=audio 60000 RTP/AVP 0\r\n"),
		message("UPDATE sip:bob@example.invalid SIP/2.0", "alice-tag", "forged", "z9hG4bK-update", 3, "UPDATE", ""),
	} {
		envelope, source := udpEnvelope(t, clock, "hunter-b", 1, payload, false)
		_, err := tracker.Process(envelope, source)
		require.ErrorIs(t, err, ErrDialog)
		after := tracker.Snapshot()[0]
		require.False(t, after.Completing)
		require.Equal(t, before.Endpoints, after.Endpoints)
		require.Equal(t, before.Info.Lifetime, after.Info.Lifetime)
	}
}

func TestCallIDReuseHasNewLifetimeAndRejectsOldDialog(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	process(t, tracker, clock, "hunter-a", response())
	old := tracker.Snapshot()[0].Info.Lifetime
	process(t, tracker, clock, "hunter-b", message("BYE sip:bob@example.invalid SIP/2.0", "alice-tag", "bob-tag", "z9hG4bK-bye", 2, "BYE", ""))
	clock.Advance(2 * time.Second)
	tracker.Sweep()
	fresh := process(t, tracker, clock, "hunter-b", invite("new-alice-tag"))
	require.NotEqual(t, old, fresh.Call.Info.Lifetime)
	envelope, source := udpEnvelope(t, clock, "hunter-a", 1, response(), false)
	_, err := tracker.Process(envelope, source)
	require.ErrorIs(t, err, ErrDialog)
	require.Equal(t, "", tracker.Snapshot()[0].ToTag)
}

func TestObservationDomainsAndAuthenticatedSourceAreEnforced(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	envelope, source := udpEnvelope(t, clock, "hunter-a", 1, invite("alice-tag"), false)
	for _, bad := range []Source{{NodeID: "hunter-b", InterfaceName: source.InterfaceName, Domain: 1}, {NodeID: "hunter-a", InterfaceName: "different", Domain: 1}, {NodeID: "hunter-a", InterfaceName: source.InterfaceName, Domain: 3}, {NodeID: "hunter-a", InterfaceName: source.InterfaceName, Domain: 1, Local: true}} {
		_, err := tracker.Process(envelope, bad)
		require.ErrorIs(t, err, ErrSource)
	}
	untrusted, untrustedSource := udpEnvelope(t, clock, "forged", 1, invite("alice-tag"), false)
	_, err := tracker.Process(untrusted, untrustedSource)
	require.ErrorIs(t, err, ErrSource)
	require.Empty(t, tracker.Snapshot())
	first, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	source.Domain = 2
	second, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	require.NotEqual(t, first.Call.Info.Lifetime, second.Call.Info.Lifetime)
	require.Len(t, tracker.Snapshot(), 2)
	media, mediaSource := udpEnvelope(t, clock, "hunter-b", 1, rtp(), true)
	resolved, err := tracker.Process(media, mediaSource)
	require.NoError(t, err)
	require.Equal(t, first.Call.Info.Lifetime, resolved.Call.Info.Lifetime)
	mediaSource.Domain = 2
	resolved, err = tracker.Process(media, mediaSource)
	require.NoError(t, err)
	require.Equal(t, second.Call.Info.Lifetime, resolved.Call.Info.Lifetime)
}

func TestForwardedFilterClaimsDoNotSelectCalls(t *testing.T) {
	tracker, clock := trackerFixture(t, func(config *Config) {
		config.Match = func(sip.Event, *pipeline.PacketEnvelope, Source) (Selection, error) { return Selection{}, nil }
	})
	envelope, source := udpEnvelope(t, clock, "hunter-a", 1, invite("alice-tag"), false)
	envelope.MatchedFilterIDs = []string{"forged-target"}
	result, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	require.Nil(t, result.Call)
	require.Empty(t, tracker.Snapshot())
	media, source := udpEnvelope(t, clock, "hunter-b", 1, rtp(), true)
	result, err = tracker.Process(media, source)
	require.NoError(t, err)
	require.Nil(t, result.Call)
}

func TestTapLocalUsesSameTrackerAndRetainsItsProvenance(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	envelope, source := udpEnvelope(t, clock, "tap", 1, invite("alice-tag"), false)
	envelope.Source.Kind = pipeline.SourceLiveCapture
	source.Local = true
	result, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	require.NotNil(t, result.Call)
	require.Len(t, result.Call.Endpoints, 2)
	require.Equal(t, pipeline.SourceLiveCapture, envelope.Source.Kind)
	require.Equal(t, "tap", envelope.Source.NodeID)
}

func TestMetadataLimitsRejectBeforeRegistryMutation(t *testing.T) {
	tracker, clock := trackerFixture(t, func(config *Config) { config.MaxBytes = 128 })
	envelope, source := udpEnvelope(t, clock, "hunter-a", 1, invite("alice-tag"), false)
	_, err := tracker.Process(envelope, source)
	require.ErrorIs(t, err, ErrCapacity)
	require.Empty(t, tracker.Snapshot())
}

func TestSnapshotIsOwnedAndUnknownTrafficDoesNotFail(t *testing.T) {
	tracker, clock := trackerFixture(t, nil)
	process(t, tracker, clock, "hunter-a", invite("alice-tag"))
	process(t, tracker, clock, "hunter-a", response())
	snapshot := tracker.Snapshot()
	snapshot[0].FilterIDs[0] = "mutated"
	snapshot[0].Dialogs[0].ToTag = "mutated"
	snapshot[0].Endpoints[0].Port = 1
	current := tracker.Snapshot()[0]
	require.Equal(t, "identity-filter", current.FilterIDs[0])
	require.Equal(t, "bob-tag", current.Dialogs[0].ToTag)
	require.NotEqual(t, uint16(1), current.Endpoints[0].Port)
	envelope, source := udpEnvelope(t, clock, "hunter-a", 1, []byte("unrelated UDP protocol"), false)
	result, err := tracker.Process(envelope, source)
	require.NoError(t, err)
	require.Nil(t, result.Process)
}
