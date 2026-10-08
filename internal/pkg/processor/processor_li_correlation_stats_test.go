//go:build li

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/stretchr/testify/require"
)

func TestMapLICallCorrelationStats(t *testing.T) {
	source := li.CallCorrelationStats{
		Adopted: map[string]uint64{"H": 2}, Standalone: map[string]uint64{"blind": 3}, SDP: map[string]uint64{"suspended": 4},
		Records: 5, Candidates: 6, Transactions: 7, Origins: 8, SuspendedOrigins: 9, GroupsTwo: 10, GroupsThree: 11, GroupsFourOrMore: 12,
		MaxRecords: 100, MaxCandidates: 200, MaxOrigins: 300, Blind: true, BlindCause: "startup", BlindRemaining: 2 * time.Second,
		Persistence: true, UncertainWrites: 13, UnresolvedWrites: 14, SDPDisabled: true, UnrecordedDecisions: 15,
	}
	got := mapLICallCorrelationStats(source)
	require.Equal(t, &management.LICallCorrelationStats{Adopted: map[string]uint64{"H": 2}, Standalone: map[string]uint64{"blind": 3}, Sdp: map[string]uint64{"suspended": 4}, Records: 5, Candidates: 6, Transactions: 7, Origins: 8, SuspendedOrigins: 9, GroupsTwo: 10, GroupsThree: 11, GroupsFourOrMore: 12, MaxRecords: 100, MaxCandidates: 200, MaxOrigins: 300, Blind: true, BlindCause: "startup", BlindRemainingNs: int64(2 * time.Second), Persistence: true, UncertainWrites: 13, UnresolvedWrites: 14, SdpDisabled: true, UnrecordedDecisions: 15}, got)
	source.Adopted["H"] = 99
	source.Standalone["blind"] = 99
	source.SDP["suspended"] = 99
	require.EqualValues(t, 2, got.Adopted["H"])
	require.EqualValues(t, 3, got.Standalone["blind"])
	require.EqualValues(t, 4, got.Sdp["suspended"])
}
func TestPopulateLICallCorrelationStatsUnavailable(t *testing.T) {
	p := &Processor{}
	p.populateLICallCorrelationStats(nil)
	dst := &management.ProcessorStats{}
	p.populateLICallCorrelationStats(dst)
	require.Nil(t, dst.LiCallCorrelation)
	p.liStorage = &liStoragePreparation{}
	p.populateLICallCorrelationStats(dst)
	require.Nil(t, dst.LiCallCorrelation)
}

func TestPopulateLICallCorrelationStatsOwnedCorrelator(t *testing.T) {
	config := li.DefaultCallCorrelationConfig()
	config.SessionHeaders = []string{"Session-ID"}
	correlator, err := li.NewCallCorrelator(config, time.Hour, nil)
	require.NoError(t, err)
	p := &Processor{liStorage: &liStoragePreparation{correlation: correlator}}
	dst := &management.ProcessorStats{}
	p.populateLICallCorrelationStats(dst)
	require.NotNil(t, dst.LiCallCorrelation)
	require.EqualValues(t, config.MaxRecords, dst.LiCallCorrelation.MaxRecords)
	require.EqualValues(t, config.MaxCandidates, dst.LiCallCorrelation.MaxCandidates)
	require.EqualValues(t, config.SDPOriginMaxTracked, dst.LiCallCorrelation.MaxOrigins)
	require.True(t, dst.LiCallCorrelation.Blind)
	require.False(t, dst.LiCallCorrelation.Persistence)
	require.Nil(t, dst.LiCallCorrelation.Storage)
	p.liStorage.correlationStore = &li.CallCorrelationStore{}
	p.populateLICallCorrelationStats(dst)
	require.NotNil(t, dst.LiCallCorrelation.Storage)
	require.Equal(t, "unopened", dst.LiCallCorrelation.Storage.State)
}
