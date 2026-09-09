//go:build li

package li

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/stretchr/testify/require"
)

func correlationFixture(t *testing.T) (RADIUSCorrelationConfig, *radius.Observation) {
	t.Helper()
	now := time.Now()
	c := RADIUSCorrelationConfig{Path: filepath.Join(t.TempDir(), "counter"), NFID: t.Name(), IPID: "poi", Now: func() time.Time { return now }}
	id := radius.Identity{Epoch: [16]byte{1}, Sequence: 1}
	o := &radius.Observation{Capture: radius.CaptureInfo{Timestamp: now, ID: id}, Scope: radius.CaptureScope{Epoch: id.Epoch, OriginNodeID: "tap", SourceID: "eth0", OperatorScope: "op", ProfileRevision: "v1"}, Message: &radius.Message{}, Association: radius.Association{Status: radius.AssociationRequest, RequestInstanceID: id, RequestFirstSeen: now}}
	return c, o
}

func TestRADIUSCorrelationDurableRestartAndIdentity(t *testing.T) {
	c, o := correlationFixture(t)
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	id, err := a.Allocate(o)
	require.NoError(t, err)
	require.Equal(t, uint64(1), id)
	duplicate := c
	duplicate.Path = filepath.Join(t.TempDir(), "another")
	_, err = NewRADIUSCorrelationAllocator(duplicate)
	require.Error(t, err)
	require.NoError(t, a.Close())
	a, err = NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	next, err := a.Allocate(o)
	require.NoError(t, err)
	require.Greater(t, next, id)
	require.NoError(t, a.Close())
	c.NFID = "different"
	_, err = NewRADIUSCorrelationAllocator(c)
	require.Error(t, err)
}

func TestRADIUSCorrelationExchangeOrphansAndBounds(t *testing.T) {
	c, o := correlationFixture(t)
	c.MaxEntries = 2
	now := o.Capture.Timestamp
	c.Now = func() time.Time { return now }
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	defer func() { require.NoError(t, a.Close()) }()
	request, err := a.Allocate(o)
	require.NoError(t, err)
	response := o.Clone()
	response.Capture.ID.Sequence++
	response.Capture.Timestamp = now.Add(time.Second)
	response.Association.Status = radius.AssociationUnique
	got, err := a.Allocate(response)
	require.NoError(t, err)
	require.Equal(t, request, got)
	orphan := response.Clone()
	orphan.Association = radius.Association{Status: radius.AssociationAmbiguous}
	other, err := a.Allocate(orphan)
	require.NoError(t, err)
	require.NotEqual(t, request, other)
	same, err := a.Allocate(orphan)
	require.NoError(t, err)
	require.Equal(t, other, same)
	fresh := orphan.Clone()
	fresh.Capture.ID.Sequence++
	_, err = a.Allocate(fresh)
	require.ErrorContains(t, err, "capacity")
	got, err = a.Allocate(o)
	require.NoError(t, err)
	require.Equal(t, request, got)
	now = now.Add(30 * time.Second)
	_, err = a.Allocate(response)
	require.ErrorContains(t, err, "expired")
	fresh.Capture.Timestamp = now
	_, err = a.Allocate(fresh)
	require.NoError(t, err)
	require.LessOrEqual(t, a.bytes, a.config.MaxBytes)
}

func TestRADIUSCorrelationConcurrentAndNoWrap(t *testing.T) {
	c, o := correlationFixture(t)
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	var wg sync.WaitGroup
	values := make(chan uint64, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, e := a.Allocate(o)
			if e != nil {
				t.Error(e)
			}
			values <- n
		}()
	}
	wg.Wait()
	close(values)
	for value := range values {
		require.Equal(t, uint64(1), value)
	}
	require.NoError(t, a.Close())
	raw, err := json.Marshal(radiusCorrelationState{NFID: c.NFID, IPID: c.IPID, Reserved: math.MaxUint64})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(c.Path, raw, 0600))
	_, err = NewRADIUSCorrelationAllocator(c)
	require.ErrorContains(t, err, "exhausted")
}

func TestRADIUSCorrelationPersistenceFailureAndCorruptState(t *testing.T) {
	c, o := correlationFixture(t)
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	// Force a fresh reservation into a missing directory. Failure must never
	// issue even one ID, nor resume allocation using uncertain persistent state.
	a.next = a.reserved
	a.config.Path = filepath.Join(t.TempDir(), "missing", "state")
	_, err = a.Allocate(o)
	require.Error(t, err)
	a.config.Path = c.Path
	_, err = a.Allocate(o)
	require.Error(t, err)
	require.NoError(t, a.Close())
	require.NoError(t, os.WriteFile(c.Path, []byte("partial"), 0600))
	_, err = NewRADIUSCorrelationAllocator(c)
	require.Error(t, err)
}

func TestRADIUSCorrelationByteBudgetAndScopeIsolation(t *testing.T) {
	c, o := correlationFixture(t)
	c.MaxBytes = 1 << 20
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	defer func() { require.NoError(t, a.Close()) }()
	first, err := a.Allocate(o)
	require.NoError(t, err)
	other := o.Clone()
	other.Scope.SourceID = "other"
	second, err := a.Allocate(other)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	huge := o.Clone()
	huge.Scope.OperatorScope = strings.Repeat("x", 1<<20)
	_, err = a.Allocate(huge)
	require.ErrorContains(t, err, "capacity")
	require.LessOrEqual(t, a.bytes, c.MaxBytes)
	require.Len(t, a.entries, 2)
}

func TestRADIUSCorrelationCrossProcessLock(t *testing.T) {
	if path := os.Getenv("LIPPYCAT_TEST_RADIUS_LOCK"); path != "" {
		_, err := NewRADIUSCorrelationAllocator(RADIUSCorrelationConfig{Path: path, NFID: "child", IPID: "poi"})
		if err == nil {
			t.Fatal("child acquired parent's state lock")
		}
		require.ErrorContains(t, err, "lock RADIUS correlation state")
		return
	}
	c, _ := correlationFixture(t)
	a, err := NewRADIUSCorrelationAllocator(c)
	require.NoError(t, err)
	defer func() { require.NoError(t, a.Close()) }()
	child := exec.Command(os.Args[0], "-test.run=^TestRADIUSCorrelationCrossProcessLock$")
	child.Env = append(os.Environ(), "LIPPYCAT_TEST_RADIUS_LOCK="+c.Path)
	output, err := child.CombinedOutput()
	require.NoError(t, err, string(output))
}
