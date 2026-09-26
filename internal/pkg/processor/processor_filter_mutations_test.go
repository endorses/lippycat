//go:build processor || tap || all

package processor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type mutationTestStore struct {
	stored map[string]*management.Filter
	fail   error
	saves  int
}

func (s *mutationTestStore) Load(string) (map[string]*management.Filter, error) { return s.stored, nil }
func (s *mutationTestStore) Save(_ string, filters map[string]*management.Filter) error {
	s.saves++
	if securestore.OutcomeOf(s.fail) != securestore.NotCommitted {
		s.stored = make(map[string]*management.Filter, len(filters))
		for id, f := range filters {
			s.stored[id] = proto.Clone(f).(*management.Filter)
		}
	}
	return s.fail
}

type mutationTestTarget struct {
	updates, deletes        int
	validationErr, applyErr error
	accepted                *management.Filter
}

func (t *mutationTestTarget) ApplyFilter(f *management.Filter) (uint32, error) {
	t.updates++
	t.accepted = proto.Clone(f).(*management.Filter)
	return 1, t.applyErr
}
func (t *mutationTestTarget) RemoveFilter(string) (uint32, error)           { t.deletes++; return 1, t.applyErr }
func (t *mutationTestTarget) FilterCount() int                              { return 0 }
func (t *mutationTestTarget) GetActiveFilters() []*management.Filter        { return nil }
func (t *mutationTestTarget) SupportsFilterType(management.FilterType) bool { return true }
func (t *mutationTestTarget) ValidateFilter(*management.Filter) error       { return t.validationErr }

func mutationTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "filter-store")
	require.NoError(t, os.Mkdir(path, 0700))
	return path
}

func mutationProcessor(t *testing.T) (*Processor, *mutationTestStore, *mutationTestTarget) {
	t.Helper()
	p, err := New(Config{ProcessorID: "filter-transactions", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(mutationTestDir(t), "filters.yaml")})
	require.NoError(t, err)
	require.NoError(t, p.filterManager.Close())
	store := &mutationTestStore{stored: make(map[string]*management.Filter)}
	p.filterManager = filtering.NewManager("unused", store, nil, nil, nil)
	target := &mutationTestTarget{}
	p.SetFilterTarget(target)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	return p, store, target
}

func TestManagedMutationRPCParity(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "scoped"}[scoped], func(t *testing.T) {
			p, store, target := mutationProcessor(t)
			update := func(f *management.Filter) error {
				if scoped {
					_, err := p.UpdateFilterOnProcessor(context.Background(), &management.ProcessorFilterRequest{ProcessorId: p.config.ProcessorID, Filter: f})
					return err
				}
				_, err := p.UpdateFilter(context.Background(), f)
				return err
			}
			remove := func(id string) error {
				if scoped {
					_, err := p.DeleteFilterOnProcessor(context.Background(), &management.ProcessorFilterDeleteRequest{ProcessorId: p.config.ProcessorID, FilterId: id})
					return err
				}
				_, err := p.DeleteFilter(context.Background(), &management.FilterDeleteRequest{FilterId: id})
				return err
			}
			f := &management.Filter{Id: "sensitive-identifier", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}
			target.validationErr = filtering.ErrFilterInvalid
			require.Equal(t, codes.InvalidArgument, status.Code(update(f)))
			require.Zero(t, store.saves)
			target.validationErr = nil
			store.fail = errors.New("sensitive selector and storage path")
			err := update(f)
			require.Equal(t, codes.Internal, status.Code(err))
			require.NotContains(t, err.Error(), "sensitive")
			require.Zero(t, target.updates)
			require.Empty(t, p.filterManager.GetAll())
			store.fail = nil
			require.NoError(t, update(f))
			require.Equal(t, 1, target.updates)
			store.fail = errors.New("save failed")
			require.Equal(t, codes.Internal, status.Code(remove(f.Id)))
			require.Zero(t, target.deletes)
			require.Len(t, p.filterManager.GetAll(), 1)
			store.fail = nil
			require.NoError(t, remove(f.Id))
			require.Equal(t, 1, target.deletes)
			require.Equal(t, codes.NotFound, status.Code(remove(f.Id)))
		})
	}
}

func TestManagedMutationUsesCommittedClone(t *testing.T) {
	p, _, target := mutationProcessor(t)
	f := &management.Filter{Type: management.FilterType_FILTER_PHONE_NUMBER, Pattern: "+1 (555) 010-0123", Enabled: true}
	before := proto.Clone(f)
	_, err := p.updateManagedFilter(f)
	require.NoError(t, err)
	require.True(t, proto.Equal(before, f))
	require.NotEmpty(t, target.accepted.Id)
	require.NotEqual(t, f.Pattern, target.accepted.Pattern)
	require.True(t, proto.Equal(target.accepted, p.filterManager.GetAll()[0]))
}

func TestManagedMutationFaultGatesProcessing(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "reconciliation", true: "commit-uncertain"}[uncertain], func(t *testing.T) {
			p, store, target := mutationProcessor(t)
			if uncertain {
				store.fail = &securestore.CommitError{Outcome: securestore.Uncertain, Op: "sync", Err: errors.New("fault")}
			} else {
				target.applyErr = errors.New("sensitive BPF error")
			}
			_, err := p.updateManagedFilter(&management.Filter{Id: "candidate", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
			require.Error(t, err)
			require.True(t, p.filterPolicyBlocked.Load())
			require.Len(t, store.stored, 1)
			if uncertain {
				require.Empty(t, p.filterManager.GetAll())
				require.Zero(t, target.updates)
				require.Equal(t, codes.Aborted, status.Code(filterMutationStatus(err)))
			} else {
				require.Len(t, p.filterManager.GetAll(), 1)
				require.ErrorIs(t, err, ErrFilterReconciliation)
				require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
				require.NotContains(t, err.Error(), "sensitive")
			}
			require.False(t, p.eventIngress.authorize(nil), "fault must close event ingress admission")
			p.processBatch(&source.PacketBatch{})
			require.Zero(t, p.packetsReceived.Load())
			stream := &mockStreamPacketsServer{ctx: context.Background(), recvBatches: []*data.PacketBatch{{HunterId: "hunter", Sequence: 1}}}
			require.Equal(t, codes.Unavailable, status.Code(p.StreamPackets(stream)))
			require.Empty(t, stream.sentControls, "blocked ingress cannot acknowledge a discarded batch")
			store.fail = nil
			target.applyErr = nil
			_, err = p.deleteManagedFilter("candidate")
			require.Error(t, err)
			require.Equal(t, 1, store.saves, "fault must prevent further persistence")
		})
	}
}

func TestManagedMutationCommittedCleanupStillApplies(t *testing.T) {
	p, store, target := mutationProcessor(t)
	store.fail = &securestore.CommitError{Outcome: securestore.Committed, Op: "cleanup", Err: errors.New("fault")}
	_, err := p.updateManagedFilter(&management.Filter{Id: "candidate", Type: management.FilterType_FILTER_BPF, Pattern: "udp"})
	require.Error(t, err)
	require.Equal(t, 1, target.updates)
	require.Len(t, p.filterManager.GetAll(), 1)
	require.False(t, p.filterPolicyBlocked.Load())
}

func TestManagedMutationDefaultHunterTargetIsNotAppliedTwice(t *testing.T) {
	p, store, _ := mutationProcessor(t)
	p.SetFilterTarget(filtering.NewHunterTarget(p.filterManager))
	_, err := p.updateManagedFilter(&management.Filter{Id: "candidate", Type: management.FilterType_FILTER_BPF, Pattern: "udp"})
	require.NoError(t, err)
	require.Equal(t, 1, store.saves)
	_, err = p.deleteManagedFilter("candidate")
	require.NoError(t, err)
	require.Equal(t, 2, store.saves)
}

func TestManagedFilterStartupFailureReleasesOwnership(t *testing.T) {
	path := filepath.Join(mutationTestDir(t), "filters.yaml")
	require.NoError(t, os.WriteFile(path, []byte("filters: [invalid]\n"), 0600))
	p, err := New(Config{ProcessorID: "filter-startup", ListenAddr: "127.0.0.1:0", FilterFile: path})
	require.Error(t, err)
	require.Nil(t, p, "invalid stored policy must fail before runtime construction")
	require.NoError(t, os.WriteFile(path, []byte("filters: []\n"), 0600))
	restarted := filtering.NewYAMLPersistence()
	_, err = restarted.Load(path)
	require.NoError(t, err)
	require.NoError(t, restarted.Close())
}

type mutationLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *mutationLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *mutationLogBuffer) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.Buffer.String() }

func TestManagedMutationDiagnosticsRedactSelectors(t *testing.T) {
	var logs mutationLogBuffer
	logger.UseFile(&logs)
	t.Cleanup(logger.UseStderr)
	p, store, target := mutationProcessor(t)
	marker := "unique-sensitive-selector@example.invalid"
	f := &management.Filter{Id: "unique-sensitive-li-filter-id", Type: management.FilterType_FILTER_SIP_USER, Pattern: marker, Enabled: true}
	_, err := p.UpdateFilterOnProcessor(context.Background(), &management.ProcessorFilterRequest{ProcessorId: p.config.ProcessorID, Filter: f})
	require.NoError(t, err)
	store.fail = errors.New(marker)
	f.Pattern = "replacement@example.invalid"
	_, err = p.UpdateFilter(context.Background(), f)
	require.Error(t, err)
	require.NotContains(t, err.Error(), marker)
	store.fail = nil
	target.applyErr = errors.New(marker)
	_, err = p.DeleteFilterOnProcessor(context.Background(), &management.ProcessorFilterDeleteRequest{ProcessorId: p.config.ProcessorID, FilterId: f.Id})
	require.Error(t, err)
	require.NotContains(t, err.Error(), marker)
	require.NoError(t, p.Shutdown())
	require.NotContains(t, logs.text(), marker)
	require.NotContains(t, logs.text(), f.Id)
}

func TestManagedLocalCaptureFailureStopsProcessor(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "failed-local-filter", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	local := source.NewLocalSource(source.LocalSourceConfig{Interfaces: []string{"lc-no-such-interface"}, BPFFilter: "udp", ProcessorID: "failed-local-filter"})
	target := filtering.NewLocalTarget(filtering.LocalTargetConfig{BaseBPF: "udp"})
	target.SetBPFUpdater(local)
	p.SetPacketSource(local)
	p.SetFilterTarget(target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = p.Start(ctx)
	require.ErrorContains(t, err, "local capture startup or runtime failed")
	require.NoError(t, p.Shutdown())
}
