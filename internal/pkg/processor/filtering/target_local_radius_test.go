package filtering

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

type radiusBPFUpdater struct {
	mockBPFUpdater
	ports []uint16
}

func (*radiusBPFUpdater) SupportsRADIUS() bool       { return true }
func (u *radiusBPFUpdater) RADIUSCaptureBPF() string { return radius.CaptureBPF(u.ports...) }

type radiusAppUpdater struct{ mockAppFilterUpdater }

func (*radiusAppUpdater) SupportsRADIUS() bool { return true }

func TestLocalTargetRADIUSCapabilitiesAndPacketVisibility(t *testing.T) {
	root := radiusfixture.Write(t)
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "host 203.0.113.99"})
	source := &radiusBPFUpdater{ports: []uint16{19120}}
	matcher := &radiusAppUpdater{}
	ft := management.FilterType_FILTER_RADIUS_USERNAME
	require.False(t, target.SupportsFilterType(ft))
	target.SetBPFUpdater(source)
	require.False(t, target.SupportsFilterType(ft))
	target.SetApplicationFilter(matcher)
	require.True(t, target.SupportsFilterType(ft))
	filter := &management.Filter{Id: "radius", Type: ft, Pattern: "alice@example.test", Revision: 1, Enabled: true}
	count, err := target.ApplyFilter(filter)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Len(t, matcher.GetFilters(), 1)

	file, err := os.Open(filepath.Join(root, "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	program, err := pcap.NewBPF(reader.LinkType(), 65535, source.LastFilter())
	require.NoError(t, err)
	expected, err := os.ReadFile(filepath.Join(root, "expected.json"))
	require.NoError(t, err)
	var fixtures struct {
		Observations []struct {
			Name    string `json:"name"`
			Outcome string `json:"outcome"`
		}
	}
	require.NoError(t, json.Unmarshal(expected, &fixtures))
	seen := map[string]bool{}
	for _, fixture := range fixtures.Observations {
		packet, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		if fixture.Name == "access-request-v4" {
			// The generated custom-port fixtures are IPv6; its broad protochain
			// branch cannot prove configured IPv4 port visibility. Change only
			// the UDP destination port; BPF does not validate UDP checksums.
			custom := append([]byte(nil), packet...)
			require.Equal(t, byte(4), custom[14]>>4)
			portOffset := 14 + int(custom[14]&15)*4 + 2
			binary.BigEndian.PutUint16(custom[portOffset:portOffset+2], 19120)
			require.True(t, program.Matches(ci, custom), "configured IPv4 port")
			binary.BigEndian.PutUint16(custom[portOffset:portOffset+2], 19121)
			require.False(t, program.Matches(ci, custom), "unconfigured IPv4 port")
		}
		if fixture.Outcome == "valid" {
			require.True(t, program.Matches(ci, packet), fixture.Name)
			seen[fixture.Name] = true
		}
	}
	// Selection must retain the identity-free response, nonmatching client and custom port.
	for _, name := range []string{"access-accept-v4", "access-request-client2-v6", "access-challenge-custom-v6", "custom-request-v6"} {
		require.True(t, seen[name])
	}
	_, err = target.RemoveFilter(filter.Id)
	require.NoError(t, err)
	require.Equal(t, "host 203.0.113.99", source.LastFilter())
	require.Empty(t, matcher.GetFilters())
}

func TestLocalTargetConcurrentRADIUSBatchesConverge(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "tcp port 80"})
	source := &radiusBPFUpdater{ports: []uint16{19120}}
	matcher := &radiusAppUpdater{}
	target.SetBPFUpdater(source)
	target.SetApplicationFilter(matcher)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			id := string(rune('a' + index))
			for revision := uint64(1); revision <= 40; revision++ {
				_, err := target.ApplyFilterBatch([]*management.Filter{{Id: id, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Revision: revision, Enabled: true}})
				if err != nil {
					t.Errorf("apply batch: %v", err)
					return
				}
				_, err = target.RemoveFilter(id)
				if err != nil {
					t.Errorf("remove: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	require.Empty(t, target.GetActiveFilters())
	require.Empty(t, matcher.GetFilters())
	require.Equal(t, "tcp port 80", source.LastFilter())
}
