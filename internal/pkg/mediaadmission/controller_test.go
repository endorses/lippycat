package mediaadmission

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

type fakeBackend struct {
	prefixes      map[DomainID][]netip.Prefix
	noFilters     map[DomainID]bool
	mu            sync.Mutex
	endpoints     map[EndpointKey]struct{}
	controls      map[DomainID]Control
	failures      map[string]int
	puts, deletes int
	afterWrite    bool
}

func newFake() *fakeBackend {
	return &fakeBackend{endpoints: make(map[EndpointKey]struct{}), controls: make(map[DomainID]Control), failures: make(map[string]int)}
}
func (f *fakeBackend) fail(op string) error {
	if f.failures[op] > 0 {
		f.failures[op]--
		return errors.New("injected " + op)
	}
	return nil
}
func (f *fakeBackend) PutEndpoint(ctx context.Context, key EndpointKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := f.fail("put")
	if err == nil || f.afterWrite {
		f.endpoints[key] = struct{}{}
		f.puts++
	}
	return err
}
func (f *fakeBackend) DeleteEndpoint(ctx context.Context, key EndpointKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := f.fail("delete")
	if err == nil || f.afterWrite {
		delete(f.endpoints, key)
		f.deletes++
	}
	return err
}
func (f *fakeBackend) ListEndpoints(ctx context.Context, domain DomainID) ([]EndpointKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.fail("list"); err != nil {
		return nil, err
	}
	var out []EndpointKey
	for key := range f.endpoints {
		if key.Domain == domain {
			out = append(out, key)
		}
	}
	return out, nil
}
func (f *fakeBackend) SetControl(ctx context.Context, domain DomainID, state Control) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := f.fail("control")
	if err == nil || f.afterWrite {
		f.controls[domain] = state
	}
	return err
}
func ep(domain DomainID, port uint16) EndpointKey {
	return EndpointKey{Domain: domain, Addr: netip.MustParseAddr("192.0.2.1"), Port: port}
}
func testController(t *testing.T, modify func(*Config)) (*Controller, *fakeBackend) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	if modify != nil {
		modify(&cfg)
	}
	backend := newFake()
	c, err := NewController(context.Background(), cfg, backend)
	if err != nil {
		t.Fatal(err)
	}
	return c, backend
}
func begin(t *testing.T, c *Controller, domain DomainID, call string) OwnerID {
	t.Helper()
	id, err := c.BeginOwner(domain, call)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharedOwnershipAndRetiredLifetime(t *testing.T) {
	c, b := testController(t, nil)
	ctx := context.Background()
	a := begin(t, c, 0, "same-call")
	leg := begin(t, c, 0, "same-call")
	must(t, c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000), ep(0, 10000)}))
	must(t, c.UpdateOwner(ctx, 0, leg, []EndpointKey{ep(0, 10000)}))
	must(t, c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000)}))
	if b.puts != 1 {
		t.Fatalf("duplicate/shared ownership wrote %d times", b.puts)
	}
	must(t, c.EndOwner(ctx, 0, a))
	if b.deletes != 0 {
		t.Fatal("first owner removed shared endpoint")
	}
	replacement := begin(t, c, 0, "same-call")
	must(t, c.UpdateOwner(ctx, 0, replacement, []EndpointKey{ep(0, 10000)}))
	if !errors.Is(c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10002)}), ErrStaleOwner) {
		t.Fatal("retired lifetime resurrected")
	}
	if !errors.Is(c.EndOwner(ctx, 0, a), ErrStaleOwner) {
		t.Fatal("stale delete accepted")
	}
	must(t, c.EndOwner(ctx, 0, leg))
	if b.deletes != 0 {
		t.Fatal("fork removed replacement ownership")
	}
	must(t, c.EndOwner(ctx, 0, replacement))
	if b.deletes != 1 || len(b.endpoints) != 0 {
		t.Fatal("last owner did not remove endpoint")
	}
}

func TestScopedFailureAndCompleteReconciliation(t *testing.T) {
	c, b := testController(t, func(cfg *Config) { cfg.InterfaceDomains = map[string]DomainID{"other": 1} })
	ctx := context.Background()
	a := begin(t, c, 0, "a")
	other := begin(t, c, 1, "a")
	must(t, c.UpdateOwner(ctx, 1, other, []EndpointKey{ep(1, 10000)}))
	b.failures["put"] = 1
	if c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000), ep(0, 10002)}) == nil {
		t.Fatal("injected failure hidden")
	}
	status := c.Status()
	if status[0].State != StateDegradedOpen || status[1].State != StateEnforcing || status[0].PendingUpdates == 0 {
		t.Fatalf("bad scoped state: %+v", status)
	}
	// An unknown stale endpoint must also be deleted; fixing only the failed add
	// is insufficient to establish recovery.
	stale := ep(0, 20000)
	b.endpoints[stale] = struct{}{}
	must(t, c.Reconcile(ctx, 0))
	if _, ok := b.endpoints[stale]; ok {
		t.Fatal("recovery retained stale entry")
	}
	status = c.Status()
	if status[0].State != StateEnforcing || status[0].PendingUpdates != 0 || status[0].InstalledGeneration != status[0].DesiredGeneration || status[0].Recoveries != 1 {
		t.Fatalf("bad recovered state %+v", status[0])
	}
}

func TestFailedControlDoesNotClaimOpen(t *testing.T) {
	c, b := testController(t, nil)
	a := begin(t, c, 0, "a")
	b.failures["put"] = 1
	b.failures["control"] = 1
	if c.UpdateOwner(context.Background(), 0, a, []EndpointKey{ep(0, 10000)}) == nil {
		t.Fatal("expected error")
	}
	st := c.Status()[0]
	if st.State != StateControlFailed || st.LastConfirmed.Mode != KernelEnforce || !st.ControlUncertain || st.OpenDuration != 0 {
		t.Fatalf("claimed unconfirmed open: %+v", st)
	}
	must(t, c.Reconcile(context.Background(), 0))
	if c.Status()[0].State != StateEnforcing {
		t.Fatal("did not recover")
	}
}

func TestAmbiguousWriteFailureAndClosedPolicy(t *testing.T) {
	c, b := testController(t, func(cfg *Config) { cfg.FailurePolicy = FailureClosed })
	ctx := context.Background()
	a := begin(t, c, 0, "a")
	b.afterWrite = true
	b.failures["put"] = 1
	if c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000)}) == nil {
		t.Fatal("expected failure")
	}
	if c.Status()[0].State != StateDegradedClosed || b.controls[0].Mode != KernelEnforce {
		t.Fatal("closed policy widened admission")
	}
	must(t, c.EndOwner(ctx, 0, a))
	if len(b.endpoints) != 0 {
		t.Fatal("retired uncertain write survived reconciliation")
	}
}

func TestCapacityCannotRecoverByIgnoringRejectedDesired(t *testing.T) {
	c, _ := testController(t, func(cfg *Config) { cfg.EndpointCapacity = 1; cfg.MaxEndpointsPerOwner = 1 })
	ctx := context.Background()
	a := begin(t, c, 0, "a")
	b := begin(t, c, 0, "b")
	must(t, c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000)}))
	if !errors.Is(c.UpdateOwner(ctx, 0, b, []EndpointKey{ep(0, 10002)}), ErrCapacity) {
		t.Fatal("capacity not enforced")
	}
	if c.Reconcile(ctx, 0) == nil || c.Status()[0].State == StateEnforcing {
		t.Fatal("incomplete desired set enabled enforcement")
	}
	// Authoritative retirement of the rejected owner establishes a complete set.
	must(t, c.EndOwner(ctx, 0, b))
	if c.Status()[0].State != StateEnforcing {
		t.Fatal("retired rejected owner did not permit recovery")
	}
}

func TestLostObservationRequiresCompleteSnapshot(t *testing.T) {
	c, _ := testController(t, nil)
	ctx := context.Background()
	a := begin(t, c, 0, "a")
	must(t, c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000)}))
	if c.MarkUnsynchronized(0, errors.New("dropped lifecycle event")) == nil {
		t.Fatal("expected error")
	}
	if c.Reconcile(ctx, 0) == nil {
		t.Fatal("lost desired state silently recovered")
	}
	must(t, c.ReplaceDesired(ctx, 0, []OwnerEndpoints{{Owner: a, Endpoints: []EndpointKey{ep(0, 10002)}}}))
	if c.Status()[0].State != StateEnforcing || c.Status()[0].PendingUpdates != 0 {
		t.Fatal("complete snapshot failed recovery")
	}
}

func TestCanceledUpdateEstablishesBoundedFailurePolicy(t *testing.T) {
	c, b := testController(t, nil)
	a := begin(t, c, 0, "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.UpdateOwner(ctx, 0, a, []EndpointKey{ep(0, 10000)}) == nil {
		t.Fatal("expected cancellation")
	}
	if b.controls[0].Mode != KernelOpen || c.Status()[0].State != StateDegradedOpen {
		t.Fatal("canceled update prevented failure control")
	}
	must(t, c.Reconcile(context.Background(), 0))
}

func TestConcurrentLifetimeChangesAndReconciliation(t *testing.T) {
	c, b := testController(t, nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				id, err := c.BeginOwner(0, "reused-call")
				if err != nil {
					t.Error(err)
					return
				}
				if err = c.UpdateOwner(ctx, 0, id, []EndpointKey{ep(0, 10000)}); err != nil {
					t.Error(err)
				}
				if err = c.Reconcile(ctx, 0); err != nil {
					t.Error(err)
				}
				if err = c.EndOwner(ctx, 0, id); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	must(t, c.Reconcile(ctx, 0))
	if len(b.endpoints) != 0 || c.Status()[0].Owners != 0 {
		t.Fatal("concurrent finalization left admission")
	}
	must(t, c.Close(ctx))
	if _, err := c.BeginOwner(0, "late"); !errors.Is(err, ErrClosed) {
		t.Fatal("closed controller accepted owner")
	}
}

func TestInitializationFailureAndDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	b := newFake()
	b.failures["control"] = 1
	if _, err := NewController(context.Background(), cfg, b); err == nil {
		t.Fatal("startup silently ignored attachment control failure")
	}
	cfg.Enabled = false
	c, err := NewController(context.Background(), cfg, nil)
	must(t, err)
	if c.Status()[0].State != StateDisabled {
		t.Fatal("disabled allocated active state")
	}
}

func (f *fakeBackend) ReplaceSelectors(ctx context.Context, domain DomainID, prefixes []netip.Prefix, noFilters bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.fail("selectors"); err != nil {
		return err
	}
	if f.prefixes == nil {
		f.prefixes = make(map[DomainID][]netip.Prefix)
		f.noFilters = make(map[DomainID]bool)
	}
	f.prefixes[domain] = append([]netip.Prefix(nil), prefixes...)
	f.noFilters[domain] = noFilters
	return nil
}
func TestSelectorFailureIsRetriedBeforeEndpointRecovery(t *testing.T) {
	c, b := testController(t, nil)
	ctx := context.Background()
	b.failures["selectors"] = 2
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.99/24")}
	if c.ReplaceSelectors(ctx, 0, prefixes, true) == nil {
		t.Fatal("selector failure ignored")
	}
	prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	owner := begin(t, c, 0, "call")
	if c.UpdateOwner(ctx, 0, owner, []EndpointKey{ep(0, 10000)}) == nil {
		t.Fatal("endpoint sync bypassed failed selectors")
	}
	if c.Status()[0].State != StateDegradedOpen {
		t.Fatal("incomplete selectors restored enforcement")
	}
	must(t, c.Reconcile(ctx, 0))
	if got := b.prefixes[0]; len(got) != 1 || got[0].String() != "192.0.2.0/24" || !b.noFilters[0] {
		t.Fatal("desired selector snapshot not preserved")
	}
	if c.Status()[0].State != StateEnforcing || c.Status()[0].PendingUpdates != 0 {
		t.Fatal("selector recovery failed")
	}
}
func TestRejectedSelectorSnapshotBlocksFalseRecovery(t *testing.T) {
	c, _ := testController(t, nil)
	ctx := context.Background()
	if c.ReplaceSelectors(ctx, 0, []netip.Prefix{{}}, false) == nil {
		t.Fatal("invalid selector accepted")
	}
	if c.Reconcile(ctx, 0) == nil {
		t.Fatal("recovered despite unknown desired selectors")
	}
	must(t, c.ReplaceSelectors(ctx, 0, nil, false))
	if c.Status()[0].State != StateEnforcing {
		t.Fatal("valid selector replacement did not clear rejected snapshot")
	}
}
