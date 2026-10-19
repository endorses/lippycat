package mediarules

import (
	"errors"

	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
)

// Store is a compatibility view over one shared lifecycle registry. It retains
// neither a second rule map nor independent authority or expiry bookkeeping.
type Store struct {
	core   *core.Store
	config Config
}

func EngineConfig(config Config, additional ...core.Adapter) (core.Config, error) {
	if err := config.validate(); err != nil {
		return core.Config{}, err
	}
	adapters := append([]core.Adapter{voiprules.Adapter(config.MaxRules)}, additional...)
	registry, err := core.NewRegistry(adapters...)
	if err != nil {
		return core.Config{}, err
	}
	domains := make([]core.DomainID, len(config.Domains))
	for i, d := range config.Domains {
		domains[i] = core.DomainID(d)
	}
	shared := core.Config{ProcessorID: config.ProcessorID, HunterID: config.HunterID, Domains: domains, MaxRules: config.MaxRules, MaxBytes: config.MaxBytes, MaxEndpoints: config.MaxEndpoints, MaxEndpointsPerRule: config.MaxEndpointsPerRule, MaxSubscribers: config.MaxSubscribers, SubscriptionBuffer: config.SubscriptionBuffer, MaxLifetime: config.MaxLifetime, ClockUncertainty: config.ClockUncertainty, Clock: config.Clock, Registry: registry}
	if config.Observer != nil {
		shared.Observer = observer{config.Observer}
	}
	return shared, nil
}

func New(config Config) (*Store, error) { return NewWithAdapters(config) }

func NewWithAdapters(config Config, additional ...core.Adapter) (*Store, error) {
	shared, err := EngineConfig(config, additional...)
	if err != nil {
		return nil, err
	}
	store, err := core.New(shared)
	if err != nil {
		return nil, err
	}
	return Wrap(store, config), nil
}

// Wrap views an already configured shared engine. The caller registers the VoIP
// adapter before constructing that engine; all mutations use its single state.
func Wrap(store *core.Store, config Config) *Store {
	return &Store{core: store, config: config}
}
func (s *Store) Core() *core.Store { return s.core }
func (s *Store) StartSession(authenticatedProcessorID string, session Session) (Control, error) {
	return s.core.StartSession(authenticatedProcessorID, session)
}
func (s *Store) ApplySnapshot(control Control, revision Revision, rules []Rule) error {
	// The historical media contract binds per-rule revisions to the stream's
	// watermark; generic bindings deliberately do not have that restriction.
	for _, r := range rules {
		for _, endpoint := range r.Endpoints {
			if endpoint.Kind > RTPAndRTCP {
				return ErrInvalid
			}
		}
		if r.Revision > revision {
			return ErrInvalid
		}
	}
	return s.core.ApplySnapshot(control, revision, toBindings(rules))
}
func (s *Store) ApplyDelta(control Control, revision Revision, rules []Rule, removals []string) error {
	for _, r := range rules {
		for _, endpoint := range r.Endpoints {
			if endpoint.Kind > RTPAndRTCP {
				return ErrInvalid
			}
		}
		if r.Revision != revision {
			return ErrRevision
		}
	}
	return s.core.ApplyDelta(control, revision, toBindings(rules), removals)
}
func (s *Store) Sweep() error        { return s.core.Sweep() }
func (s *Store) Close() error        { return s.core.Close() }
func (s *Store) Snapshot() Snapshot  { return fromSnapshot(s.core.Snapshot()) }
func (s *Store) ActiveRules() []Rule { return fromBindings(s.core.ActiveRules()) }
func (s *Store) Status() Status {
	v := s.core.StatusForAdapter(voiprules.AdapterID)
	return Status{Session: v.Session, Revision: v.Revision, Sequence: v.Sequence, Ready: v.Ready, Rules: v.Rules, Bytes: v.Bytes, Endpoints: v.Endpoints, Subscribers: v.Subscribers, Expired: v.Expired, StaleUpdates: v.StaleUpdates, Resyncs: v.Resyncs}
}
func (s *Store) Resolve(source, destination mediaadmission.EndpointKey) Resolution {
	var eligible []core.Binding
	for _, binding := range s.core.ActiveRules() {
		if s.core.InScope(binding, core.DomainID(source.Domain)) {
			eligible = append(eligible, binding)
		}
	}
	return voiprules.Resolve(fromBindings(eligible), source, destination)
}
func (s *Store) ResolveDialog(callID, fromTag, toTag string) Resolution {
	return voiprules.ResolveDialog(s.ActiveRules(), s.config.HunterID, callID, fromTag, toTag)
}
func (s *Store) ResolveDialogInDomain(domain mediaadmission.DomainID, callID, fromTag, toTag string) Resolution {
	return voiprules.ResolveDialogInDomain(s.ActiveRules(), s.config.HunterID, domain, callID, fromTag, toTag)
}

func ToBinding(rule Rule) core.Binding               { return voiprules.ToBinding(rule) }
func FromBinding(binding core.Binding) (Rule, error) { return voiprules.FromBinding(binding) }
func toBindings(rules []Rule) []core.Binding {
	var bindings []core.Binding
	for _, rule := range rules {
		bindings = append(bindings, ToBinding(rule))
	}
	return bindings
}
func fromBindings(bindings []core.Binding) []Rule {
	var rules []Rule
	for _, binding := range bindings {
		// A multi-adapter registry's legacy view exposes only exactly representable
		// VoIP state. Invalid VoIP state cannot have passed adapter publication.
		rule, err := FromBinding(binding)
		if err == nil {
			rules = append(rules, rule)
		}
	}
	return rules
}
func fromSnapshot(s core.Snapshot) Snapshot {
	return Snapshot{Session: s.Session, Revision: s.Revision, Sequence: s.Sequence, Ready: s.Ready, Rules: fromBindings(s.Rules)}
}
func fromChange(c core.Change) Change {
	converted := Change{Snapshot: fromSnapshot(c.Snapshot), Active: fromBindings(c.Active), ResyncRequired: c.ResyncRequired}
	for _, r := range c.Removed {
		rule, err := FromBinding(r.Rule)
		if err == nil {
			converted.Removed = append(converted.Removed, Removal{Rule: rule, Reason: RemovalReason(r.Reason)})
		}
	}
	return converted
}

type observer struct{ Observer }

func (o observer) OnLearnedRulesChanged(c core.Change) { o.OnMediaRulesChanged(fromChange(c)) }

// Subscription is a typed queue projection, registered and bounded by the shared
// store itself. Projection callbacks perform no I/O and never reenter the store.
type Subscription struct {
	Initial Change
	Events  <-chan Change
	shared  *core.Subscription
}

func (s *Store) Subscribe() (*Subscription, error) {
	events := make(chan Change, s.subscriptionBuffer())
	shared, err := s.core.SubscribeSink(func(c core.Change) bool {
		select {
		case events <- fromChange(c):
			return true
		default:
			return false
		}
	}, func(c core.Change) {
		for {
			select {
			case <-events:
			default:
				events <- fromChange(c)
				return
			}
		}
	}, func() { close(events) })
	if err != nil {
		return nil, err
	}
	return &Subscription{Initial: fromChange(shared.Initial), Events: events, shared: shared}, nil
}
func (s *Store) subscriptionBuffer() int {
	if s.config.SubscriptionBuffer > 0 {
		return s.config.SubscriptionBuffer
	}
	return 1
}
func (s *Subscription) Close() { s.shared.Close() }
func cloneRule(rule Rule) Rule { return voiprules.CloneRule(rule) }
func equalRule(a, b Rule) bool { return voiprules.EqualRule(a, b) }
func sameOwner(a, b Rule) bool {
	return a.Session == b.Session && a.Call.Lifetime == b.Call.Lifetime && a.Call.CallID == b.Call.CallID
}
func ruleBytes(rule Rule) int { return core.BindingBytes(ToBinding(rule)) }
func IsResyncError(err error) bool {
	return errors.Is(err, ErrRevision) || errors.Is(err, ErrNotReady) || errors.Is(err, ErrSession)
}
