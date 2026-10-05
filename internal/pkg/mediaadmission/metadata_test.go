package mediaadmission

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func dialog(generation uint64) DialogKey {
	return DialogKey{Session: 1, Generation: generation, CallID: "same-call", FromTag: "a", ToTag: "b", Branch: "branch", CSeq: 1}
}
func TestMetadataPromotionIsolationAndCopies(t *testing.T) {
	s, err := NewMetadataStore(DefaultConfig())
	must(t, err)
	now := time.Now()
	key := dialog(1)
	must(t, s.Observe(key, []EndpointKey{ep(0, 10000)}, now))
	must(t, s.Observe(key, []EndpointKey{ep(0, 10002), ep(0, 10000)}, now))
	if _, ok := s.Take(dialog(2), now); ok {
		t.Fatal("promoted reused Call-ID generation")
	}
	fork := key
	fork.ToTag = "other"
	if _, ok := s.Take(fork, now); ok {
		t.Fatal("promoted different fork")
	}
	endpoints, ok := s.Peek(key, now)
	if !ok || len(endpoints) != 2 {
		t.Fatal("SDP accumulation failed")
	}
	endpoints[0] = ep(0, 20000)
	endpoints, ok = s.Take(key, now)
	if !ok || len(endpoints) != 2 {
		t.Fatal("promotion failed")
	}
	for _, endpoint := range endpoints {
		if endpoint.Port == 20000 {
			t.Fatal("caller mutated store")
		}
	}
	if _, ok = s.Take(key, now); ok {
		t.Fatal("metadata promoted twice")
	}
	if stats := s.Stats(); stats.Dialogs != 0 || stats.Bytes != 0 || stats.Promotions != 1 || stats.PromotionMisses != 3 {
		t.Fatalf("incorrect metadata stats %+v", stats)
	}
}
func TestMetadataBoundsAndExpirationWork(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PendingDialogCapacity = 3
	cfg.ExpirationBatch = 1
	s, err := NewMetadataStore(cfg)
	must(t, err)
	now := time.Now()
	for i := uint64(1); i <= 4; i++ {
		must(t, s.Observe(dialog(i), []EndpointKey{ep(0, 10000)}, now))
	}
	if s.Stats().Evicted != 1 || s.Stats().Dialogs != 3 {
		t.Fatal("dialog bound not enforced")
	}
	if _, ok := s.Take(dialog(1), now); ok {
		t.Fatal("evicted metadata promoted")
	}
	later := now.Add(cfg.PendingTTL)
	if n := s.Expire(later); n != 1 || s.Stats().Dialogs != 2 {
		t.Fatal("expiry sweep was not bounded")
	}
	if _, ok := s.Take(dialog(4), later); ok {
		t.Fatal("expired entry beyond sweep budget promoted")
	}
	s.Clear()
	if s.Stats().Bytes != 0 || s.Stats().Endpoints != 0 {
		t.Fatal("clear retained charged metadata")
	}
}
func TestMetadataOversizeKeepsPreviousValidRecord(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEndpointsPerOwner = 1
	s, err := NewMetadataStore(cfg)
	must(t, err)
	now := time.Now()
	key := dialog(1)
	must(t, s.Observe(key, []EndpointKey{ep(0, 10000)}, now))
	if !errors.Is(s.Observe(key, []EndpointKey{ep(0, 10002)}, now), ErrCapacity) {
		t.Fatal("accumulation exceeded bound")
	}
	got, ok := s.Take(key, now)
	if !ok || len(got) != 1 || got[0].Port != 10000 {
		t.Fatal("rejected record destroyed retained valid metadata")
	}
}
func TestMetadataConcurrentAccess(t *testing.T) {
	s, err := NewMetadataStore(DefaultConfig())
	must(t, err)
	var wg sync.WaitGroup
	for i := uint64(1); i <= 8; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			for n := 0; n < 40; n++ {
				now := time.Now()
				if err := s.Observe(dialog(id), []EndpointKey{ep(0, 10000)}, now); err != nil {
					t.Error(err)
				}
				s.Peek(dialog(id), now)
				s.Take(dialog(id), now)
				s.Expire(now)
				s.Stats()
			}
		}(i)
	}
	wg.Wait()
}
func TestConfigAndEndpointNormalization(t *testing.T) {
	cfg := DefaultConfig()
	must(t, cfg.Validate())
	cfg.Mode = "invalid"
	if cfg.Validate() == nil {
		t.Fatal("invalid mode accepted")
	}
	cfg = DefaultConfig()
	cfg.PendingBytes = 0
	if cfg.Validate() == nil {
		t.Fatal("explicit zero limit silently defaulted")
	}
	key, err := NewEndpoint(0, netip.MustParseAddr("::ffff:192.0.2.1"), 10000)
	must(t, err)
	if !key.Addr.Is4() {
		t.Fatal("IPv4 mapped address not normalized")
	}
	if _, err := NewEndpoint(0, netip.MustParseAddr("239.1.1.1"), 10000); err != nil {
		t.Fatal("multicast endpoint rejected")
	}
	if _, err := NewEndpoint(0, netip.MustParseAddr("::"), 10000); err == nil {
		t.Fatal("disabled unspecified stream admitted")
	}
}

func TestMetadataEmptyDerivationRetainsCompletenessAndBounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PendingDialogCapacity = 2
	s, err := NewMetadataStore(cfg)
	must(t, err)
	now := time.Now()
	must(t, s.ObserveDerived(dialog(1), nil, false, now))
	must(t, s.ObserveDerived(dialog(2), nil, true, now))
	stats := s.Stats()
	if stats.Dialogs != 2 || stats.Endpoints != 0 || stats.Bytes <= 0 {
		t.Fatalf("empty derivation was not charged: %+v", stats)
	}
	first, ok := s.TakeRecord(dialog(1), now)
	if !ok || first.Complete {
		t.Fatal("unknown derivation became intentional empty media")
	}
	second, ok := s.TakeRecord(dialog(2), now)
	if !ok || !second.Complete {
		t.Fatal("intentional empty media lost completeness")
	}
	must(t, s.ObserveDerived(dialog(3), nil, false, now))
	must(t, s.ObserveDerived(dialog(4), nil, false, now))
	must(t, s.ObserveDerived(dialog(5), nil, false, now))
	if s.Stats().Dialogs != 2 || s.Stats().Evicted != 1 {
		t.Fatal("empty unknown records bypassed capacity")
	}
	if _, ok := s.TakeRecord(dialog(5), now.Add(cfg.PendingTTL)); ok {
		t.Fatal("unknown empty record bypassed expiry")
	}
}
