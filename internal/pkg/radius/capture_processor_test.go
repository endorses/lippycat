package radius

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func captureTestPacket(raw []byte, timestamp time.Time) gopacket.Packet {
	packet := gopacket.NewPacket(raw, layers.LinkTypeRaw, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(raw), Length: len(raw)}
	return packet
}

func TestCaptureProcessorCandidateCountersAndCustomPorts(t *testing.T) {
	p, err := NewCaptureProcessor(CaptureScope{OriginNodeID: "node"}, 19120)
	require.NoError(t, err)
	defer p.Close()
	now := time.Now()
	require.Nil(t, p.Process(captureTestPacket(testIPPacket(false, 53), now), layers.LinkTypeRaw, "eth0", nil))
	stats, _ := p.Stats()
	require.Equal(t, ValidationStats{}, stats)
	for _, v6 := range []bool{false, true} {
		observation := p.Process(captureTestPacket(testIPPacket(v6, 19120), now), layers.LinkTypeRaw, "eth0", nil)
		require.NotNil(t, observation)
		require.Equal(t, AssociationRequest, observation.Association.Status)
	}
	stats, _ = p.Stats()
	require.EqualValues(t, 2, stats.Valid)
}

func TestCaptureProcessorUsesCaptureTimeForExpiry(t *testing.T) {
	p, err := NewCaptureProcessor(CaptureScope{OriginNodeID: "node"})
	require.NoError(t, err)
	defer p.Close()
	raw := testIPPacket(false, 1812)
	timestamp := time.Unix(100, 0)
	request := p.Process(captureTestPacket(raw, timestamp), layers.LinkTypeRaw, "eth0", nil)
	require.Equal(t, timestamp, request.Association.RequestFirstSeen)
	response := append([]byte(nil), raw...)
	// Reverse IPv4 endpoints and UDP ports, and change Access-Request to Accept.
	copy(response[12:16], raw[16:20])
	copy(response[16:20], raw[12:16])
	copy(response[20:22], raw[22:24])
	copy(response[22:24], raw[20:22])
	response[28] = 2
	observation := p.Process(captureTestPacket(response, timestamp.Add(31*time.Second)), layers.LinkTypeRaw, "eth0", nil)
	require.Equal(t, AssociationExpired, observation.Association.Status)
	require.Empty(t, observation.Inherited)
}

func TestCaptureProcessorRejectedCandidateCannotAdvanceClock(t *testing.T) {
	p, err := NewCaptureProcessor(CaptureScope{OriginNodeID: "node"})
	require.NoError(t, err)
	defer p.Close()
	raw := testIPPacket(false, 1812)
	timestamp := time.Unix(100, 0)
	require.NotNil(t, p.Process(captureTestPacket(raw, timestamp), layers.LinkTypeRaw, "eth0", nil))
	malformed := append([]byte(nil), raw...)
	malformed[31] = 19 // RADIUS Length below header size.
	require.Nil(t, p.Process(captureTestPacket(malformed, timestamp.Add(time.Hour)), layers.LinkTypeRaw, "eth0", nil))
	unsupported := append([]byte(nil), raw...)
	unsupported[28] = 40
	require.Nil(t, p.Process(captureTestPacket(unsupported, timestamp.Add(2*time.Hour)), layers.LinkTypeRaw, "eth0", nil))
	response := append([]byte(nil), raw...)
	copy(response[12:16], raw[16:20])
	copy(response[16:20], raw[12:16])
	copy(response[20:22], raw[22:24])
	copy(response[22:24], raw[20:22])
	response[28] = 2
	observation := p.Process(captureTestPacket(response, timestamp.Add(time.Second)), layers.LinkTypeRaw, "eth0", nil)
	require.NotNil(t, observation)
	require.Equal(t, AssociationUnique, observation.Association.Status)
	stats, _ := p.Stats()
	require.EqualValues(t, 1, stats.Malformed)
	require.EqualValues(t, 1, stats.Unsupported)
}

func TestCaptureProcessorMissingInterfaceRemainsTransportable(t *testing.T) {
	p, err := NewCaptureProcessor(CaptureScope{OriginNodeID: "sniff"})
	require.NoError(t, err)
	defer p.Close()
	observation := p.Process(captureTestPacket(testIPPacket(false, 1812), time.Now()), layers.LinkTypeRaw, "", nil)
	require.NotNil(t, observation)
	require.Equal(t, "unknown", observation.Scope.SourceID)
	require.NoError(t, ValidateProvenance(observation))
}

func TestCaptureProcessorCustomBounds(t *testing.T) {
	_, err := NewCaptureProcessorWithConfig(CaptureScope{}, CorrelatorConfig{Lifetime: time.Millisecond})
	require.Error(t, err)
	p, err := NewCaptureProcessorWithConfig(CaptureScope{OriginNodeID: "node"}, CorrelatorConfig{Lifetime: 2 * time.Second, MaxCandidates: 1})
	require.NoError(t, err)
	defer p.Close()
	timestamp := time.Unix(100, 0)
	raw := testIPPacket(false, 1812)
	require.NotNil(t, p.Process(captureTestPacket(raw, timestamp), layers.LinkTypeRaw, "eth0", nil))
	other := append([]byte(nil), raw...)
	other[29]++
	require.Equal(t, AssociationCapacitySuppressed, p.Process(captureTestPacket(other, timestamp), layers.LinkTypeRaw, "eth0", nil).Association.Status)
	_, stats := p.Stats()
	require.EqualValues(t, 1, stats.CapacityLosses)
	require.NoError(t, p.AdvanceBoundary(timestamp.Add(time.Second)))
	require.Equal(t, 2*time.Second, p.correlator.config.Lifetime)
	require.Equal(t, 1, p.correlator.config.MaxCandidates)
}
