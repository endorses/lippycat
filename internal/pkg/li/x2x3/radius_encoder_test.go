package x2x3

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/radius"
)

// These complete PDU vectors were packed independently of the Go encoders,
// using the committed Phase 0 payloads and endpoint/timestamp expectations.
func TestRADIUSEncoderGoldenFixtures(t *testing.T) {
	root := "../../../../testdata/radius"
	data, err := os.ReadFile(filepath.Join(root, "expected.json"))
	require.NoError(t, err)
	var fixtures struct {
		Observations []struct {
			Name            string `json:"name"`
			Outcome         string `json:"outcome"`
			Timestamp       string `json:"timestamp"`
			IPFamily        uint8  `json:"ip_version"`
			SourceIP        string `json:"source_ip"`
			DestinationIP   string `json:"destination_ip"`
			SourcePort      uint16 `json:"source_port"`
			DestinationPort uint16 `json:"destination_port"`
			RawFile         string `json:"raw_radius_file"`
		} `json:"observations"`
	}
	require.NoError(t, json.Unmarshal(data, &fixtures))
	for _, fixture := range fixtures.Observations {
		if fixture.Outcome != "valid" {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, fixture.RawFile))
			require.NoError(t, err)
			message, err := radius.Decode(append(append([]byte(nil), raw...), 0xaa, 0xbb))
			require.NoError(t, err)
			// Revalidation must bound even manually supplied Raw storage by its
			// wire Length and never rebuild the message from decoded attributes.
			message.Raw = append(message.Raw, 0xaa, 0xbb)
			message.Attributes = nil
			parts := strings.Split(fixture.Timestamp, ".")
			seconds, err := strconv.ParseInt(parts[0], 10, 64)
			require.NoError(t, err)
			nanos, err := strconv.ParseInt(parts[1]+strings.Repeat("0", 9-len(parts[1])), 10, 64)
			require.NoError(t, err)
			observation := &radius.Observation{
				Capture:   radius.CaptureInfo{Timestamp: time.Unix(seconds, nanos)},
				Message:   message,
				Endpoints: radius.Endpoints{IPFamily: fixture.IPFamily, Source: netip.AddrPortFrom(netip.MustParseAddr(fixture.SourceIP), fixture.SourcePort), Destination: netip.AddrPortFrom(netip.MustParseAddr(fixture.DestinationIP), fixture.DestinationPort)},
			}
			encoder := NewRADIUSEncoder(nil, "radius-domain", "tap-nf", "poi-1")
			pdu, err := encoder.Encode(observation, goldenXID, 42)
			require.NoError(t, err)
			wire, err := pdu.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, loadVector(t, filepath.Join("radius", fixture.Name+".hex")), wire)
			var decoded PDU
			require.NoError(t, decoded.UnmarshalBinary(wire))
			require.Equal(t, raw, decoded.Payload)
			// Even mutations to the original message cannot corrupt queued product.
			observation.Message.Raw[0] = 0xff
			require.Equal(t, raw, pdu.Payload)
		})
	}
}

func radiusEncoderObservation(t *testing.T) *radius.Observation {
	t.Helper()
	raw := make([]byte, 20)
	raw[0], raw[1], raw[3] = 1, 7, 20
	message, err := radius.Decode(raw)
	require.NoError(t, err)
	return &radius.Observation{Message: message, Capture: radius.CaptureInfo{Timestamp: goldenTS}, Endpoints: radius.Endpoints{IPFamily: 4, Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("198.51.100.1:1812")}}
}

func TestRADIUSEncoderSharedSequencing(t *testing.T) {
	sequencer := NewSequencer(10)
	first := NewRADIUSEncoder(sequencer, "domain", "nf", "ip")
	second := NewRADIUSEncoder(sequencer, "domain", "nf", "ip")
	observation := radiusEncoderObservation(t)
	for index, encoder := range []*RADIUSEncoder{first, second, first} {
		pdu, err := encoder.Encode(observation, goldenXID, 1234)
		require.NoError(t, err)
		require.Equal(t, uint32(index), binary.BigEndian.Uint32(FindAttribute(pdu.Attributes, AttrSequenceNumber).Value))
	}
	for _, item := range []struct {
		xid uuid.UUID
		cid uint64
	}{{uuid.New(), 1234}, {goldenXID, 5678}} {
		pdu, err := first.Encode(observation, item.xid, item.cid)
		require.NoError(t, err)
		require.Equal(t, uint32(0), binary.BigEndian.Uint32(FindAttribute(pdu.Attributes, AttrSequenceNumber).Value))
	}
	var wg sync.WaitGroup
	results := make(chan uint32, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pdu, err := second.Encode(observation, goldenXID, 1234)
			if err != nil {
				t.Error(err)
				return
			}
			results <- binary.BigEndian.Uint32(FindAttribute(pdu.Attributes, AttrSequenceNumber).Value)
		}()
	}
	wg.Wait()
	close(results)
	seen := map[uint32]bool{}
	for seq := range results {
		require.False(t, seen[seq])
		seen[seq] = true
	}
	require.Len(t, seen, 50)
}

func TestRADIUSEncoderRejectsInvalidInputBeforeSequencing(t *testing.T) {
	sequencer := NewSequencer(1)
	encoder := NewRADIUSEncoder(sequencer, "", "nf", "ip")
	for _, mutate := range []func(*radius.Observation){
		func(o *radius.Observation) { o.Message = nil },
		func(o *radius.Observation) { o.Message.Raw[3] = 21 },
		func(o *radius.Observation) { o.Message.Raw[0] = 40 },
		func(o *radius.Observation) { o.Endpoints.Source = netip.AddrPort{} },
		func(o *radius.Observation) { o.Endpoints.IPFamily = 6 },
	} {
		observation := radiusEncoderObservation(t)
		mutate(observation)
		_, err := encoder.Encode(observation, goldenXID, 1)
		require.ErrorIs(t, err, ErrInvalidRADIUSObservation)
	}
	_, err := encoder.Encode(nil, goldenXID, 1)
	require.ErrorIs(t, err, ErrInvalidRADIUSObservation)
	_, err = encoder.Encode(radiusEncoderObservation(t), uuid.Nil, 1)
	require.ErrorIs(t, err, ErrInvalidRADIUSObservation)
	_, err = encoder.Encode(radiusEncoderObservation(t), goldenXID, 0)
	require.ErrorIs(t, err, ErrInvalidRADIUSObservation)
	require.Zero(t, sequencer.Len())
	_, err = encoder.Encode(radiusEncoderObservation(t), goldenXID, 1)
	require.NoError(t, err)
	_, err = encoder.Encode(radiusEncoderObservation(t), goldenXID, 2)
	require.ErrorIs(t, err, ErrSequenceCapacity)
}
