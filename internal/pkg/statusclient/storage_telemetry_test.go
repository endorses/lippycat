package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestStorageTelemetryWireAndJSON(t *testing.T) {
	filter := &management.StorageStatus{Mode: "yaml", State: "ready", LastOutcome: "committed", Commits: 2}
	state := &management.StorageStatus{Mode: "encrypted", State: "faulted", AdmissionBlocked: true, FaultCode: "usage_ledger_fault", PolicyFaultCode: "reconciliation_required", LastOutcome: "not_committed", DefiniteFailures: 1, ActiveKeyId: "current", PriorKeyIds: []string{"old"}, KeyUsage: &management.EncryptionUsageStats{ReservedInvocations: 4096, ReservedBlocks: 1 << 20, AccountingFaulted: true, ReservationOutcome: "uncertain", InvocationLimit: 1 << 32, BlockLimit: 1 << 40}}
	original := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{Storage: &management.ProcessorStorageStats{Filters: filter, LiState: state}, LiDelivery: &management.LIDeliveryStats{X2Journal: &management.LIJournalStats{Storage: state, Uncertain: 3}, UncertainWrites: 4}}}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)
	decoded := &management.StatusResponse{}
	require.NoError(t, proto.Unmarshal(wire, decoded))
	data, err := StatusResponseToJSON(decoded, false)
	require.NoError(t, err)
	var public map[string]any
	require.NoError(t, json.Unmarshal(data, &public))
	stores := public["storage"].(map[string]any)
	require.Equal(t, "yaml", stores["filters"].(map[string]any)["mode"])
	liState := stores["li_state"].(map[string]any)
	require.Equal(t, "not_committed", liState["last_outcome"])
	require.Equal(t, "uncertain", liState["key_usage"].(map[string]any)["reservation_outcome"])
	delivery := public["li_delivery"].(map[string]any)
	require.EqualValues(t, 4, delivery["uncertain_writes"])
	require.EqualValues(t, 3, delivery["x2_journal"].(map[string]any)["uncertain"])
	require.NotContains(t, delivery, "x3_journal")
	// Existing field numbers and the deliberately additive slots are frozen here.
	require.EqualValues(t, 14, decoded.ProcessorStats.ProtoReflect().Descriptor().Fields().ByName("storage").Number())
	require.EqualValues(t, 10, decoded.ProcessorStats.LiDelivery.X2Journal.ProtoReflect().Descriptor().Fields().ByName("storage").Number())
}
