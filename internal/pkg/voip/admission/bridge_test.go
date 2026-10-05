package admission

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

type backend struct {
	failControl bool
	control     mediaadmission.Control
	mu          sync.Mutex
	keys        map[mediaadmission.EndpointKey]bool
}

func (b *backend) PutEndpoint(_ context.Context, key mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[key] = true
	return nil
}
func (b *backend) DeleteEndpoint(_ context.Context, key mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.keys, key)
	return nil
}
func (b *backend) ListEndpoints(_ context.Context, domain mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []mediaadmission.EndpointKey
	for key := range b.keys {
		if key.Domain == domain {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
func (b *backend) SetControl(_ context.Context, _ mediaadmission.DomainID, control mediaadmission.Control) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failControl {
		return errors.New("synthetic control failure")
	}
	b.control = control
	return nil
}
func (b *backend) count() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.keys) }
func fixture(t *testing.T) (*Bridge, *callregistry.Core, *backend) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	if err != nil {
		t.Fatal(err)
	}
	store, err := mediaadmission.NewMetadataStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	registry := callregistry.New(callregistry.Config{MaxCalls: cfg.OwnerCapacity, MaxEndpointsPerCall: cfg.MaxEndpointsPerOwner, MaxEndpointAssociations: cfg.EndpointCapacity})
	bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		registry.Close()
		if err := bridge.Close(); err != nil {
			t.Error(err)
		}
		if err := controller.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return bridge, registry, maps
}
func offer(callID string) pipeline.SIPResult {
	return pipeline.SIPResult{CallID: callID, Method: "INVITE", CSeqMethod: "INVITE", CSeqNumber: 1, FromTag: "from", ViaBranch: "branch", SDP: []byte("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"), Packet: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth0"}}}
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLateSelectionPromotesOfferWithoutPrematchMedia(t *testing.T) {
	bridge, registry, maps := fixture(t)
	invite := offer("call")
	check(t, bridge.ObserveValidated(invite))
	if maps.count() != 0 || registry.ActiveCallCount() != 0 {
		t.Fatal("unselected SDP caused admission")
	}
	answer := invite
	answer.Method = "200"
	answer.ResponseCode = 200
	answer.ToTag = "to"
	answer.SDP = nil
	check(t, bridge.ObserveValidated(answer))
	registry.Upsert(callregistry.Call{CallID: "call"})
	check(t, bridge.Selected(answer))
	if maps.count() != 2 || registry.EndpointAssociationCount() != 2 {
		t.Fatal("late selection did not promote RTP and RTCP")
	}
	registry.Remove("call", callregistry.EndCompleted)
	if maps.count() != 0 {
		t.Fatal("finalization retained admission")
	}
}
func TestEstablishedDialogAliasAllowsLaterReverseDirectionSelection(t *testing.T) {
	bridge, registry, maps := fixture(t)
	invite := offer("call")
	check(t, bridge.ObserveValidated(invite))
	response := invite
	response.SDP = nil
	response.ResponseCode = 183
	response.ToTag = "to"
	check(t, bridge.ObserveValidated(response))
	later := response
	later.ResponseCode = 0
	later.Method = "INFO"
	later.CSeqMethod = "INFO"
	later.CSeqNumber = 9
	later.ViaBranch = "later"
	later.FromTag = "to"
	later.ToTag = "from"
	check(t, bridge.ObserveValidated(later))
	registry.Upsert(callregistry.Call{CallID: "call"})
	check(t, bridge.Selected(later))
	if maps.count() != 2 {
		t.Fatal("known dialog tags did not promote earlier offer")
	}
}
func TestUnrelatedForkOrTransactionCannotPromote(t *testing.T) {
	for _, which := range []string{"fork", "transaction"} {
		t.Run(which, func(t *testing.T) {
			bridge, registry, maps := fixture(t)
			original := offer("same-call")
			if which == "fork" {
				original.ToTag = "fork-a"
			}
			check(t, bridge.ObserveValidated(original))
			selected := original
			selected.SDP = nil
			if which == "fork" {
				selected.ToTag = "fork-b"
			} else {
				selected.CSeqNumber++
				selected.ViaBranch = "other"
			}
			registry.Upsert(callregistry.Call{CallID: "same-call"})
			if bridge.Selected(selected) == nil {
				t.Fatal("missing compatible offer was acknowledged as complete empty media")
			}
			if maps.count() != 0 {
				t.Fatal("unrelated SIP identity inherited SDP")
			}
		})
	}
}
func TestStaleEndpointAndCompletionCallbacksCannotChangeReusedCall(t *testing.T) {
	bridge, registry, maps := fixture(t)
	message := offer("reused")
	registry.Upsert(callregistry.Call{CallID: "reused"})
	check(t, bridge.ObserveValidated(message))
	check(t, bridge.Selected(message))
	old, _ := registry.EndpointSnapshot("reused")
	registry.Remove("reused", callregistry.EndCompleted)
	registry.Upsert(callregistry.Call{CallID: "reused"})
	fresh := offer("reused")
	fresh.FromTag = "new"
	fresh.ViaBranch = "new"
	fresh.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
	check(t, bridge.ObserveValidated(fresh))
	check(t, bridge.Selected(fresh))
	bridge.OnEndpointsChanged(old)
	bridge.OnCallEnded(old.Call, callregistry.EndCompleted)
	if maps.count() != 2 {
		t.Fatal("stale callbacks changed replacement admission")
	}
	for endpoint := range maps.keys {
		if endpoint.Port < 20000 {
			t.Fatal("old SDP resurrected")
		}
	}
}
func TestOnlySelectedLocalAcceptedAssociationsArePublished(t *testing.T) {
	bridge, registry, maps := fixture(t)
	message := offer("local")
	remote := message
	remote.Packet = &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceGRPC}}
	check(t, bridge.ObserveValidated(remote))
	registry.Upsert(callregistry.Call{CallID: "local"})
	check(t, bridge.Selected(remote))
	registry.TryAssociateEndpoint("local", "192.0.2.1:10000")
	if maps.count() != 0 {
		t.Fatal("remote or merely existing registry call installed local admission")
	}
	message.SDP = []byte("m=audio 0 RTP/AVP 0")
	check(t, bridge.Selected(message))
	if maps.count() != 1 {
		t.Fatal("accepted local registry association missing")
	}
	registry.DissociateEndpoints("local")
	if maps.count() != 0 {
		t.Fatal("accepted endpoint removal not published")
	}
}
func TestOutOfOrderEndpointRevisionCannotResurrectRemovedEndpoint(t *testing.T) {
	bridge, registry, maps := fixture(t)
	message := offer("call")
	registry.Upsert(callregistry.Call{CallID: "call"})
	check(t, bridge.ObserveValidated(message))
	check(t, bridge.Selected(message))
	old, _ := registry.EndpointSnapshot("call")
	registry.DissociateEndpoints("call")
	bridge.OnEndpointsChanged(old)
	if maps.count() != 0 {
		t.Fatal("stale endpoint snapshot restored old admission")
	}
}
func TestConcurrentObserverReentryAndFinalization(t *testing.T) {
	bridge, registry, maps := fixture(t)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				id := fmt.Sprintf("%d-%d", n, i)
				message := offer(id)
				registry.Upsert(callregistry.Call{CallID: id})
				if err := bridge.ObserveValidated(message); err != nil {
					t.Error(err)
				}
				if err := bridge.Selected(message); err != nil {
					t.Error(err)
				}
				registry.Remove(id, callregistry.EndCompleted)
			}
		}(n)
	}
	wg.Wait()
	if maps.count() != 0 || bridge.Stats().SelectedLifetimes != 0 {
		t.Fatal("concurrent finalization leaked owners")
	}
}

type recordedSelection struct {
	answered, active bool
	at               time.Time
}
type diagnosticRecorder struct {
	selections map[mediaadmission.OwnerID]recordedSelection
	attributed int
}

func (d *diagnosticRecorder) RecordSelection(owner mediaadmission.OwnerID, _ mediaadmission.DomainID, answered, active bool, at time.Time) {
	d.selections[owner] = recordedSelection{answered, active, at}
}
func (d *diagnosticRecorder) RecordAttributedMedia(mediaadmission.OwnerID) { d.attributed++ }
func (d *diagnosticRecorder) RecordFinalized(owner mediaadmission.OwnerID) {
	delete(d.selections, owner)
}
func TestDiagnosticAnswerAndHoldStateSurvivesAbsentSDP(t *testing.T) {
	bridge, registry, _ := fixture(t)
	recorder := &diagnosticRecorder{selections: make(map[mediaadmission.OwnerID]recordedSelection)}
	bridge.cfg.Diagnostics = recorder
	message := offer("call")
	registry.Upsert(callregistry.Call{CallID: "call"})
	check(t, bridge.ObserveValidated(message))
	check(t, bridge.Selected(message))
	answer := message
	answer.SDP = nil
	answer.ResponseCode = 200
	answer.ToTag = "to"
	check(t, bridge.Selected(answer))
	var selectedAt time.Time
	for _, state := range recorder.selections {
		if !state.answered || !state.active {
			t.Fatal("answer lost active offer state")
		}
		selectedAt = state.at
	}
	later := answer
	later.ResponseCode = 0
	later.Method = "BYE"
	later.CSeqMethod = "BYE"
	check(t, bridge.Selected(later))
	for _, state := range recorder.selections {
		if !state.answered || !state.active || state.at != selectedAt {
			t.Fatal("SDP-absent message reset diagnostic state")
		}
	}
	hold := answer
	hold.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n")
	check(t, bridge.Selected(hold))
	for _, state := range recorder.selections {
		if state.active {
			t.Fatal("explicit disabled SDP did not update hold diagnostic")
		}
	}
	diagnosticCall, _ := registry.Call("call")
	diagnosticLifetime := diagnosticCall.Lifetime
	bridge.RecordAttributedMedia("call", diagnosticLifetime)
	if recorder.attributed != 1 {
		t.Fatal("attributed media not recorded")
	}
	registry.Remove("call", callregistry.EndCompleted)
	bridge.RecordAttributedMedia("call", diagnosticLifetime)
	if recorder.attributed != 1 || len(recorder.selections) != 0 {
		t.Fatal("retired owner retained diagnostics")
	}
}

func TestRetryCurrentEligibleSnapshotAfterCapacityFrees(t *testing.T) {
	for _, owners := range []int{1, 10} {
		t.Run(fmt.Sprint(owners), func(t *testing.T) {
			bridge, registry, maps, controller := retryFixture(t, owners, 10, nil)
			first := offer("first")
			registry.Upsert(callregistry.Call{CallID: first.CallID})
			check(t, bridge.ObserveValidated(first))
			check(t, bridge.Selected(first))
			second := offer("second")
			second.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
			registry.Upsert(callregistry.Call{CallID: second.CallID})
			check(t, bridge.ObserveValidated(second))
			if bridge.Selected(second) == nil {
				t.Fatal("capacity exceeded without error")
			}
			registry.Remove(first.CallID, callregistry.EndCompleted)
			check(t, bridge.retrySelected())
			if maps.count() != 2 {
				t.Fatalf("eligible endpoints not restored: %d", maps.count())
			}
			bridge.mu.Lock()
			pending := bridge.selected[second.CallID].retry
			bridge.mu.Unlock()
			if pending {
				t.Fatal("recovery remained pending")
			}
			status := controller.Status()[0]
			if status.State != mediaadmission.StateEnforcing || status.PendingUpdates != 0 || status.DesiredGeneration != status.InstalledGeneration {
				t.Fatalf("incomplete recovered status: %+v", status)
			}
		})
	}
}

func retryFixture(t *testing.T, owners, pending int, wrap func(*callregistry.Core) Registry, retryInterval ...time.Duration) (*Bridge, *callregistry.Core, *backend, *mediaadmission.Controller) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.OwnerCapacity = owners
	cfg.PendingDialogCapacity = pending
	cfg.EndpointCapacity = 2
	cfg.MaxEndpointsPerOwner = 2
	cfg.RetryInterval = time.Hour
	if len(retryInterval) > 0 {
		cfg.RetryInterval = retryInterval[0]
	}
	maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	check(t, err)
	store, err := mediaadmission.NewMetadataStore(cfg)
	check(t, err)
	registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 2, MaxEndpointAssociations: 20})
	var source Registry = registry
	if wrap != nil {
		source = wrap(registry)
	}
	bridge, err := New(Config{Limits: cfg, Registry: source, Controller: controller, Metadata: store})
	check(t, err)
	t.Cleanup(func() { registry.Close(); check(t, bridge.Close()); check(t, controller.Close(context.Background())) })
	return bridge, registry, maps, controller
}

type pausedSnapshotRegistry struct {
	*callregistry.Core
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (r *pausedSnapshotRegistry) EndpointSnapshot(id string) (callregistry.EndpointObservation, bool) {
	observation, ok := r.Core.EndpointSnapshot(id)
	if r.armed.CompareAndSwap(true, false) {
		close(r.entered)
		<-r.release
	}
	return observation, ok
}

func TestRetryCannotRestoreSnapshotOlderThanConcurrentRegistryMutation(t *testing.T) {
	var source *pausedSnapshotRegistry
	bridge, registry, maps, _ := retryFixture(t, 10, 10, func(core *callregistry.Core) Registry {
		source = &pausedSnapshotRegistry{Core: core, entered: make(chan struct{}), release: make(chan struct{})}
		return source
	})
	for _, id := range []string{"first", "second"} {
		msg := offer(id)
		if id == "second" {
			msg.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
		}
		registry.Upsert(callregistry.Call{CallID: id})
		check(t, bridge.ObserveValidated(msg))
		err := bridge.Selected(msg)
		if id == "first" {
			check(t, err)
		} else if err == nil {
			t.Fatal("missing capacity failure")
		}
	}
	registry.Remove("first", callregistry.EndCompleted)
	source.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- bridge.retrySelected() }()
	<-source.entered
	registry.DissociateEndpoints("second")
	if !registry.TryAssociateEndpoint("second", "192.0.2.3:30000") {
		t.Fatal("new endpoint was rejected")
	}
	close(source.release)
	check(t, <-done)
	want, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.3"), 30000)
	check(t, err)
	maps.mu.Lock()
	defer maps.mu.Unlock()
	if len(maps.keys) != 1 || !maps.keys[want] {
		t.Fatalf("stale retry restored old endpoint set: %+v", maps.keys)
	}
}

func TestPendingPoolOverflowNeverCreatesZeroOwnerOrClearsLostSelection(t *testing.T) {
	bridge, registry, _, controller := retryFixture(t, 1, 1, nil)
	for _, id := range []string{"active", "pending", "lost"} {
		registry.Upsert(callregistry.Call{CallID: id})
		err := bridge.Selected(offer(id))
		if id == "active" {
			check(t, err)
		} else if err == nil {
			t.Fatal("missing capacity failure")
		}
	}
	bridge.mu.Lock()
	if len(bridge.selected) != 2 {
		t.Fatalf("pending bridge state unbounded: %d", len(bridge.selected))
	}
	for _, state := range bridge.selected {
		if state.owner.Session == 0 {
			t.Fatal("zero owner retained")
		}
	}
	bridge.mu.Unlock()
	registry.Remove("active", callregistry.EndCompleted)
	if bridge.retrySelected() == nil {
		t.Fatal("lost selection recovered without complete evidence")
	}
	if controller.Status()[0].State == mediaadmission.StateEnforcing {
		t.Fatal("lost selection enabled enforcement")
	}
	registry.Remove("pending", callregistry.EndCompleted)
	registry.Remove("lost", callregistry.EndCompleted)
	if bridge.Stats().SelectedLifetimes != 0 {
		t.Fatal("pending lifetime survived finalization")
	}
	check(t, bridge.retrySelected())
	if controller.Status()[0].State != mediaadmission.StateEnforcing {
		t.Fatal("retired lost selections prevented complete empty-snapshot recovery")
	}
}

func TestForegroundErrorCallbackCanCloseRetryWorker(t *testing.T) {
	bridge, registry, _, _ := retryFixture(t, 1, 1, nil)
	registry.Upsert(callregistry.Call{CallID: "active"})
	check(t, bridge.Selected(offer("active")))
	closed := make(chan error, 1)
	bridge.cfg.OnError = func(error) { closed <- bridge.Close() }
	registry.Upsert(callregistry.Call{CallID: "pending"})
	returned := make(chan error, 1)
	go func() { returned <- bridge.Selected(offer("pending")) }()
	select {
	case err := <-closed:
		check(t, err)
	case <-time.After(time.Second):
		t.Fatal("OnError Close deadlocked retry shutdown")
	}
	if <-returned == nil {
		t.Fatal("missing capacity failure")
	}
	check(t, bridge.Close())
}

func TestRetryFailureDoesNotReenterErrorCallback(t *testing.T) {
	bridge, registry, _, _ := retryFixture(t, 1, 1, nil)
	for _, id := range []string{"active", "pending"} {
		registry.Upsert(callregistry.Call{CallID: id})
		err := bridge.Selected(offer(id))
		if id == "active" {
			check(t, err)
		} else if err == nil {
			t.Fatal("missing capacity failure")
		}
	}
	callbacks := 0
	bridge.cfg.OnError = func(error) { callbacks++ }
	if bridge.retrySelected() == nil {
		t.Fatal("expected retry to remain incomplete")
	}
	if callbacks != 0 {
		t.Fatal("retry invoked a user callback that can synchronously Close its worker")
	}
}

func TestBackgroundRetryRecoversWithoutMoreSIPAndStopsOnClose(t *testing.T) {
	bridge, registry, maps, controller := retryFixture(t, 1, 1, nil, time.Millisecond)
	for _, id := range []string{"active", "pending"} {
		message := offer(id)
		if id == "pending" {
			message.SDP = []byte("v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n")
		}
		registry.Upsert(callregistry.Call{CallID: id})
		check(t, bridge.ObserveValidated(message))
		err := bridge.Selected(message)
		if id == "active" {
			check(t, err)
		} else if err == nil {
			t.Fatal("missing capacity failure")
		}
	}
	registry.Remove("active", callregistry.EndCompleted)
	deadline := time.Now().Add(time.Second)
	for maps.count() != 2 || controller.Status()[0].State != mediaadmission.StateEnforcing {
		if time.Now().After(deadline) {
			t.Fatal("retry did not restore selected endpoints without another SIP message")
		}
		time.Sleep(time.Millisecond)
	}
	check(t, bridge.Close())
	select {
	case <-bridge.done:
	default:
		t.Fatal("Close returned before retry worker stopped")
	}
	if maps.count() != 0 {
		t.Fatal("Close retained selected or pending endpoints")
	}
	check(t, bridge.retrySelected())
}

// Pause notification after the registry accepts an endpoint, before the bridge
// consumes its immutable observation. Another call may mutate during delivery.
type pausedCallEndpointObserver struct {
	callID  string
	entered chan struct{}
	release chan struct{}
	armed   atomic.Bool
}

func (o *pausedCallEndpointObserver) OnEndpointsChanged(observation callregistry.EndpointObservation) {
	if observation.Call.CallID == o.callID && o.armed.CompareAndSwap(true, false) {
		close(o.entered)
		<-o.release
	}
}

func TestUnrelatedCallMutationCannotLoseSelectedEndpointPublication(t *testing.T) {
	pause := &pausedCallEndpointObserver{callID: "selected-a", entered: make(chan struct{}), release: make(chan struct{})}
	bridge, registry, maps, controller := retryFixture(t, 10, 10, func(core *callregistry.Core) Registry {
		core.AddEndpointObserver(pause) // Runs before the bridge observer.
		return core
	})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(pause.release) }) })
	registry.Upsert(callregistry.Call{CallID: "selected-a"})
	registry.Upsert(callregistry.Call{CallID: "unrelated-b"})
	selected := offer("selected-a")
	selected.SDP = []byte("m=audio 0 RTP/AVP 0")
	check(t, bridge.Selected(selected))
	if maps.count() != 0 {
		t.Fatal("fixture unexpectedly installed endpoints before association")
	}
	pause.armed.Store(true)
	accepted := make(chan bool, 1)
	go func() { accepted <- registry.TryAssociateEndpoint("selected-a", "192.0.2.1:10000") }()
	<-pause.entered
	// A is already selected, and this is its last endpoint observation. B's
	// mutation only advances the global revision; no later A SIP/retry is sent.
	if !registry.TryAssociateEndpoint("unrelated-b", "192.0.2.2:20000") {
		t.Fatal("B endpoint was rejected")
	}
	release.Do(func() { close(pause.release) })
	if !<-accepted {
		t.Fatal("A endpoint was rejected")
	}
	want, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.1"), 10000)
	check(t, err)
	maps.mu.Lock()
	installed := len(maps.keys) == 1 && maps.keys[want]
	maps.mu.Unlock()
	if !installed {
		t.Fatal("unrelated registry revision lost A's final admitted endpoint")
	}
	status := controller.Status()[0]
	if status.DesiredEndpoints != 1 || status.InstalledEndpoints != 1 || status.PendingUpdates != 0 || status.State != mediaadmission.StateEnforcing {
		t.Fatalf("published state is inconsistent: %+v", status)
	}
	current, ok := registry.EndpointSnapshot("selected-a")
	if !ok {
		t.Fatal("selected lifetime disappeared")
	}
	bridge.mu.Lock()
	state := bridge.selected["selected-a"]
	consistent := state != nil && !state.retry && state.revision == current.Revision
	bridge.mu.Unlock()
	if !consistent {
		t.Fatal("bridge did not consume the fresh exact-lifetime snapshot")
	}
}

func recoveryFixture(t *testing.T, policy mediaadmission.FailurePolicy, wrap func(*callregistry.Core) Registry) (*Bridge, *callregistry.Core, *backend, *mediaadmission.Controller) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.FailurePolicy = policy
	cfg.RetryInterval = time.Hour
	maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	check(t, err)
	store, err := mediaadmission.NewMetadataStore(cfg)
	check(t, err)
	registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
	var source Registry = registry
	if wrap != nil {
		source = wrap(registry)
	}
	bridge, err := New(Config{Limits: cfg, Registry: source, Controller: controller, Metadata: store})
	check(t, err)
	t.Cleanup(func() { registry.Close(); check(t, bridge.Close()); check(t, controller.Close(context.Background())) })
	return bridge, registry, maps, controller
}

func TestIncompleteSelectedDerivationRetainsSafeAttributionAndRequiresCompleteRecovery(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, maps, controller := recoveryFixture(t, policy, nil)
			message := offer("partial")
			message.SDP = append(message.SDP, []byte("m=video invalid RTP/AVP 96\r\n")...)
			if bridge.ObserveValidated(message) == nil {
				t.Fatal("partial SDP accepted as complete")
			}
			registry.Upsert(callregistry.Call{CallID: message.CallID})
			if bridge.Selected(message) == nil {
				t.Fatal("unknown selected media was not reported")
			}
			if bridge.Stats().UnknownDerivations != 1 || registry.EndpointAssociationCount() != 2 || maps.count() != 2 {
				t.Fatal("safe partial endpoints or unknown state lost")
			}
			if got := registry.ResolveMediaEndpoints("192.0.2.1:10000", ""); got.CallID != message.CallID {
				t.Fatal("opening policy did not preserve userspace attribution")
			}
			wantState := mediaadmission.StateDegradedOpen
			if policy == mediaadmission.FailureClosed {
				wantState = mediaadmission.StateDegradedClosed
			}
			if controller.Status()[0].State != wantState {
				t.Fatal("wrong failure policy")
			}
			if bridge.retrySelected() == nil || controller.Status()[0].State != wantState {
				t.Fatal("known partial snapshot falsely restored enforcement")
			}
			repaired := offer(message.CallID)
			repaired.CSeqNumber++
			check(t, bridge.ObserveValidated(repaired))
			check(t, bridge.Selected(repaired))
			status := controller.Status()[0]
			if status.State != mediaadmission.StateEnforcing || status.PendingUpdates != 0 || bridge.Stats().UnknownDerivations != 0 {
				t.Fatalf("complete SDP did not recover: %+v", status)
			}
		})
	}
}

func TestUnknownPendingSDPDoesNotDisappearWhenLateSelectionHasNoBody(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	bad := offer("pending")
	bad.SDP = []byte("m=audio invalid RTP/AVP 0\r\n")
	if bridge.ObserveValidated(bad) == nil {
		t.Fatal("missing pending parse error")
	}
	answer := bad
	answer.SDP = nil
	answer.ToTag = "to"
	answer.ResponseCode = 200
	check(t, bridge.ObserveValidated(answer))
	registry.Upsert(callregistry.Call{CallID: answer.CallID})
	if bridge.Selected(answer) == nil || bridge.Stats().UnknownDerivations != 1 {
		t.Fatal("empty unknown staging disappeared")
	}
	if controller.Status()[0].State != mediaadmission.StateDegradedOpen {
		t.Fatal("unknown selected staging did not apply policy")
	}
	registry.Remove(answer.CallID, callregistry.EndCompleted)
	check(t, bridge.retrySelected())
	if controller.Status()[0].State != mediaadmission.StateEnforcing {
		t.Fatal("retired unknown lifetime prevented recovery")
	}
	registry.Upsert(callregistry.Call{CallID: answer.CallID})
	reused := offer(answer.CallID)
	reused.FromTag, reused.ViaBranch = "replacement", "replacement"
	reused.SDP = []byte("c=IN IP4 192.0.2.2\r\nm=audio 0 RTP/AVP 0\r\n")
	check(t, bridge.ObserveValidated(reused))
	check(t, bridge.Selected(reused))
	if bridge.Stats().UnknownDerivations != 0 {
		t.Fatal("intentional empty replacement inherited unknown derivation")
	}
}

func TestFailedControlRemainsUncertainUntilConfirmedSnapshotRecovery(t *testing.T) {
	bridge, registry, maps, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	message := offer("control")
	registry.Upsert(callregistry.Call{CallID: message.CallID})
	check(t, bridge.Selected(message))
	maps.mu.Lock()
	maps.failControl = true
	maps.mu.Unlock()
	bad := message
	bad.SDP = []byte("m=audio invalid RTP/AVP 0")
	if bridge.Selected(bad) == nil {
		t.Fatal("failed control was not reported")
	}
	status := controller.Status()[0]
	if status.State != mediaadmission.StateControlFailed || !status.ControlUncertain || status.LastConfirmed.Mode == mediaadmission.KernelOpen {
		t.Fatalf("unconfirmed open mode claimed: %+v", status)
	}
	if bridge.Selected(message) == nil {
		t.Fatal("repair ignored failed control operation")
	}
	maps.mu.Lock()
	maps.failControl = false
	maps.mu.Unlock()
	check(t, bridge.retrySelected())
	status = controller.Status()[0]
	if status.State != mediaadmission.StateEnforcing || status.ControlUncertain {
		t.Fatalf("confirmed retry failed to recover: %+v", status)
	}
}

type rejectionRegistry struct {
	*callregistry.Core
	reject atomic.Bool
	retire atomic.Bool
}

func (r *rejectionRegistry) TryAssociateEndpointForLifetime(id string, lifetime callregistry.Lifetime, endpoint string) bool {
	if r.retire.CompareAndSwap(true, false) {
		r.Core.Remove(id, callregistry.EndCompleted)
		return false
	}
	if r.reject.Load() {
		return false
	}
	return r.Core.TryAssociateEndpointForLifetime(id, lifetime, endpoint)
}

func TestSelectedAssociationLossRetriesButRetirementIsNotSynchronizationLoss(t *testing.T) {
	var source *rejectionRegistry
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, func(core *callregistry.Core) Registry {
		source = &rejectionRegistry{Core: core}
		return source
	})
	message := offer("rejected")
	registry.Upsert(callregistry.Call{CallID: message.CallID})
	source.reject.Store(true)
	if bridge.Selected(message) == nil || controller.Status()[0].State != mediaadmission.StateDegradedOpen {
		t.Fatal("live selected association loss did not apply failure policy")
	}
	source.reject.Store(false)
	check(t, bridge.retrySelected())
	if registry.EndpointAssociationCount() != 2 || controller.Status()[0].State != mediaadmission.StateEnforcing {
		t.Fatal("current lifetime association retry failed")
	}
	registry.Remove(message.CallID, callregistry.EndCompleted)
	registry.Upsert(callregistry.Call{CallID: "retiring"})
	message = offer("retiring")
	source.retire.Store(true)
	_ = bridge.Selected(message) // finalization legitimately races promotion
	if controller.Status()[0].State != mediaadmission.StateEnforcing || bridge.Stats().SelectedLifetimes != 0 {
		t.Fatal("stale promotion changed failure policy or retained lifetime")
	}
}

type lifetimeDiagnosticRecorder struct {
	*diagnosticRecorder
	selectionBeforeLifetime bool
	created, selected       time.Time
	expectationKnown        bool
}

func (d *lifetimeDiagnosticRecorder) RecordSelectionLifetime(owner mediaadmission.OwnerID, _ mediaadmission.DomainID, created, selected time.Time) {
	_, d.selectionBeforeLifetime = d.selections[owner]
	d.created, d.selected = created, selected
}
func (d *lifetimeDiagnosticRecorder) RecordMediaExpectation(_ mediaadmission.OwnerID, _ mediaadmission.DomainID, known, _ bool, _ uint64, _ time.Time) {
	d.expectationKnown = known
}

func TestLifecycleDiagnosticsReceiveSelectionBeforeAuthoritativeLifetimeBoundary(t *testing.T) {
	bridge, registry, _, _ := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	diagnostics := &lifetimeDiagnosticRecorder{diagnosticRecorder: &diagnosticRecorder{selections: make(map[mediaadmission.OwnerID]recordedSelection)}}
	bridge.mu.Lock()
	bridge.cfg.Diagnostics = diagnostics
	bridge.mu.Unlock()
	message := offer("synthetic-lifetime")
	registry.Upsert(callregistry.Call{CallID: message.CallID})
	check(t, bridge.Selected(message))
	call, ok := registry.Call(message.CallID)
	if !ok || !diagnostics.selectionBeforeLifetime || diagnostics.created != call.Created || diagnostics.selected.IsZero() || diagnostics.selected.Before(diagnostics.created) {
		t.Fatal("diagnostic lifetime boundary was unavailable or preceded selection registration")
	}
	if !diagnostics.expectationKnown {
		t.Fatal("confirmed endpoints did not establish known media expectation")
	}
}

func TestExpiredPendingOfferKeepsInitialSelectedInviteUnknownUntilCompleteSDP(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	message := offer("expired-offer")
	check(t, bridge.ObserveValidated(message))
	bridge.cfg.Metadata.Expire(time.Now().Add(bridge.cfg.Limits.PendingTTL))
	selected := message
	selected.SDP = nil
	selected.ResponseCode = 200
	selected.ToTag = "destination"
	registry.Upsert(callregistry.Call{CallID: selected.CallID})
	if bridge.Selected(selected) == nil || bridge.Stats().UnknownDerivations != 1 || controller.Status()[0].State != mediaadmission.StateDegradedOpen {
		t.Fatal("lost offer was synchronized as empty media")
	}
	if bridge.retrySelected() == nil {
		t.Fatal("empty accepted registry snapshot cleared missing derivation")
	}
	check(t, bridge.Selected(message))
	if controller.Status()[0].State != mediaadmission.StateEnforcing {
		t.Fatal("complete selected SDP did not recover missing offer")
	}
}

type nonblockingAttributionRecorder struct {
	*diagnosticRecorder
	unavailable, packets int
}

func (d *nonblockingAttributionRecorder) RecordAttributionUnavailable() { d.unavailable++ }
func (d *nonblockingAttributionRecorder) RecordAttributedPacket(mediaadmission.OwnerID, mediaadmission.DomainID, []byte) {
	d.packets++
}

func TestAttributionDiagnosticsReturnImmediatelyWhenReconciliationOwnsBridge(t *testing.T) {
	bridge, registry, _, _ := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	diagnostics := &nonblockingAttributionRecorder{diagnosticRecorder: &diagnosticRecorder{selections: make(map[mediaadmission.OwnerID]recordedSelection)}}
	bridge.mu.Lock()
	bridge.cfg.Diagnostics = diagnostics
	bridge.mu.Unlock()
	message := offer("synthetic-attribution")
	registry.Upsert(callregistry.Call{CallID: message.CallID})
	check(t, bridge.Selected(message))
	call, ok := registry.Call(message.CallID)
	if !ok {
		t.Fatal("selected lifetime missing")
	}
	// The same goroutine owns the lock: a blocking diagnostic call would
	// deadlock, whereas TryLock must record unavailable evidence and return.
	bridge.mu.Lock()
	bridge.RecordAttributedMedia(message.CallID, call.Lifetime)
	bridge.RecordAttributedPacket(message.CallID, call.Lifetime, []byte("synthetic frame"))
	bridge.mu.Unlock()
	if diagnostics.unavailable != 2 || diagnostics.attributed != 0 || diagnostics.packets != 0 {
		t.Fatal("unavailable evidence was not conservatively accounted")
	}
	bridge.RecordAttributedMedia(message.CallID, call.Lifetime)
	bridge.RecordAttributedPacket(message.CallID, call.Lifetime, []byte("synthetic frame"))
	if diagnostics.attributed != 1 || diagnostics.packets != 1 {
		t.Fatal("uncontended current lifetime attribution stopped working")
	}
}
