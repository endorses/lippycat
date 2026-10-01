//go:build (processor || tap || all) && li

package processor

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestLICompleteTaskContractManagerConfiguration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		p := &Processor{config: Config{LIEnabled: true, LIADMFCompleteTaskContract: enabled}}
		p.initLIManager()
		require.Equal(t, enabled, p.liManager.Config().ADMFCompleteTaskContract)
		p.config.LIADMFCompleteTaskContract = !enabled
		require.Equal(t, enabled, p.liManager.Config().ADMFCompleteTaskContract, "live manager keeps its startup policy")
	}
}

func TestLITaskDeactivationLogsNamedActualCause(t *testing.T) {
	var output bytes.Buffer
	logger.UseFile(&output)
	t.Cleanup(logger.UseStderr)
	task := &li.InterceptTask{
		XID:            uuid.New(),
		EndTime:        time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Targets:        []li.TargetIdentity{{Type: li.TargetTypeSIPURI, Value: "private-target@example.invalid"}},
		DestinationIDs: []uuid.UUID{uuid.New()},
	}
	for _, test := range []struct {
		reason li.DeactivationReason
		name   string
		expiry bool
	}{
		{li.DeactivationReasonADMF, "admf", false},
		{li.DeactivationReasonExpired, "expired", true},
		{li.DeactivationReasonFault, "fault", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			logLITaskDeactivation(task, test.reason)
			var record map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			require.Equal(t, "LI task deactivated", record["msg"])
			require.Equal(t, test.name, record["reason"])
			require.Equal(t, task.XID.String(), record["xid"])
			if test.expiry {
				require.Equal(t, task.EndTime.Format(time.RFC3339), record["end_time"])
			} else {
				require.NotContains(t, record, "end_time")
			}
			require.NotContains(t, output.String(), task.Targets[0].Value)
			require.NotContains(t, output.String(), task.DestinationIDs[0].String())
		})
	}
}

func TestLIDefinitionTelemetryPopulatesFromManager(t *testing.T) {
	manager := li.NewManager(li.ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, manager.CreateDestination(&li.Destination{DID: did, Address: "mdf.example.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	require.NoError(t, manager.ActivateTask(&li.InterceptTask{
		XID: uuid.New(), DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{did},
		Targets: []li.TargetIdentity{{Type: li.TargetTypeSIPURI, Value: "synthetic@example.invalid"}},
	}))
	p := &Processor{liManager: manager}
	dst := &management.ProcessorStats{}
	p.populateLIEncodingStats(dst)
	require.NotNil(t, dst.LiDefinitions)
	require.NotNil(t, dst.LiStartupSync)
	require.Equal(t, string(manager.Stats().StartupSync.State), dst.LiStartupSync.State)
	require.Equal(t, manager.Stats().StartupSync.Attempts, dst.LiStartupSync.Attempts)
	require.Empty(t, dst.LiStartupSync.LastAttempt)
	require.Empty(t, dst.LiStartupSync.RecoveredAt)
	stats := manager.Stats().Definitions
	require.Equal(t, stats.Incomplete, dst.LiDefinitions.Incomplete)
	require.Equal(t, stats.PullOnly, dst.LiDefinitions.PullOnly)
	require.Equal(t, stats.Conflicts, dst.LiDefinitions.Conflicts)
	require.Equal(t, stats.UnknownWindows, dst.LiDefinitions.UnknownWindows)
	require.EqualValues(t, 1, dst.LiDefinitions.OpenEnded)
	require.Equal(t, stats.Repairs, dst.LiDefinitions.Repairs)
	disabled := &management.ProcessorStats{}
	(&Processor{}).populateLIEncodingStats(disabled)
	require.Nil(t, disabled.LiDefinitions)
	require.Nil(t, disabled.LiStartupSync)
}
