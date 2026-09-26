//go:build (processor || tap || all) && li

package processor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRADIUSDeliveryPreservesPinnedAllocatorAcrossStatePathChange(t *testing.T) {
	stateFile := newTestFilterFile(t)
	oldAllocator := filepath.Join(filepath.Dir(newTestFilterFile(t)), "original-state.json.radius-correlation")
	keys := newTestFilterKeys(t)
	_, err := li.InitializeEncryptedStateStore(stateFile, keys, li.StateOfflineOptions{RADIUSStateFile: oldAllocator})
	require.NoError(t, err)
	p, err := newTestProcessor(t, Config{
		ListenAddr: "127.0.0.1:0", ProcessorID: "allocator-pin", LIEnabled: true,
		LIStateFile: stateFile, LIStateKeys: keys, LIRADIUSCorrelationLifetime: time.Minute,
	})
	require.NoError(t, err)
	packets := radiusOutputFixtures(t)
	p.normalizeRADIUS("hunter", packets)
	observation, err := grpcadapter.RADIUSFromProto(packets[0])
	require.NoError(t, err)
	observation.Scope.OperatorScope, observation.Scope.ProfileRevision = "operator", "v1"
	observation.Capture.Timestamp = time.Now()
	observation.Association.RequestFirstSeen = observation.Capture.Timestamp
	before, err := li.NewRADIUSCorrelationAllocator(li.RADIUSCorrelationConfig{Path: oldAllocator, NFID: "allocator-pin", IPID: "allocator-pin", RequestLifetime: time.Minute})
	require.NoError(t, err)
	first, err := before.Allocate(observation)
	require.NoError(t, err)
	require.NoError(t, before.Close())

	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	task := &li.InterceptTask{
		XID: uuid.New(), Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "user@example.test"}},
		DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{did},
		RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"},
	}
	require.NoError(t, p.liManager.ActivateTask(task))
	task, err = p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	p.deliverLIRADIUS(task, observation)
	require.NotNil(t, p.radiusLIAllocator, "delivery must use the encrypted state's allocator pin")
	second, err := p.radiusLIAllocator.Allocate(observation)
	require.NoError(t, err)
	require.Greater(t, second, first, "reopening must retain the previous reservation highwater")
	_, err = os.Stat(stateFile + ".radius-correlation")
	require.ErrorIs(t, err, os.ErrNotExist, "new administrative path must not create a fresh allocator")
	require.NoError(t, p.Shutdown())
}
