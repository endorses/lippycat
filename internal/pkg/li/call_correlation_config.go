package li

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// CallCorrelationConfig configures optional LI call-leg grouping. It is shared
// with non-LI command configuration; the correlator itself is LI-tagged.
type CallCorrelationConfig struct {
	StoreKeys                securestore.KeyConfig `mapstructure:"-"`
	SessionHeaders           []string              `mapstructure:"session_headers"`
	ParentCallIDHeaders      []string              `mapstructure:"parent_call_id_headers"`
	SDPOriginMatching        bool                  `mapstructure:"sdp_origin_matching"`
	SDPOriginReuseWindow     time.Duration         `mapstructure:"sdp_origin_reuse_window"`
	SDPOriginObservationTTL  time.Duration         `mapstructure:"sdp_origin_observation_ttl"`
	SDPOriginSuspend         time.Duration         `mapstructure:"sdp_origin_suspend"`
	SDPOriginMaxTracked      int                   `mapstructure:"sdp_origin_max_tracked"`
	AddressChaining          bool                  `mapstructure:"address_chaining"`
	AddressChainingRewritten bool                  `mapstructure:"address_chaining_rewritten"`
	NumberChaining           bool                  `mapstructure:"number_chaining"`
	AddressWindow            time.Duration         `mapstructure:"address_window"`
	NumberWindow             time.Duration         `mapstructure:"number_window"`
	NodeAliases              [][]string            `mapstructure:"node_aliases"`
	DecisionHorizon          time.Duration         `mapstructure:"decision_horizon"`
	TerminalGrace            time.Duration         `mapstructure:"terminal_grace"`
	WaitTimeout              time.Duration         `mapstructure:"wait_timeout"`
	ShutdownTimeout          time.Duration         `mapstructure:"shutdown_timeout"`
	StoreFile                string                `mapstructure:"store_file"`
	MaxCandidates            int                   `mapstructure:"max_candidates"`
	MaxRecords               int                   `mapstructure:"max_records"`
}

func DefaultCallCorrelationConfig() CallCorrelationConfig {
	return CallCorrelationConfig{
		SDPOriginReuseWindow: 30 * time.Second, SDPOriginObservationTTL: 10 * time.Minute,
		SDPOriginSuspend: 10 * time.Minute, SDPOriginMaxTracked: 10000,
		AddressWindow: 2 * time.Second, NumberWindow: 500 * time.Millisecond,
		DecisionHorizon: 5 * time.Minute, TerminalGrace: 30 * time.Second,
		WaitTimeout: 5 * time.Second, ShutdownTimeout: 10 * time.Second,
		MaxCandidates: 10000, MaxRecords: 100000,
	}
}

// Normalized supplies defaults for omitted values. Negative values remain
// invalid; disabling a matching method does not discard its configuration.
func (c CallCorrelationConfig) Normalized() CallCorrelationConfig {
	d := DefaultCallCorrelationConfig()
	for _, p := range []struct {
		v *time.Duration
		d time.Duration
	}{
		{&c.SDPOriginReuseWindow, d.SDPOriginReuseWindow}, {&c.SDPOriginObservationTTL, d.SDPOriginObservationTTL},
		{&c.SDPOriginSuspend, d.SDPOriginSuspend}, {&c.AddressWindow, d.AddressWindow},
		{&c.NumberWindow, d.NumberWindow}, {&c.DecisionHorizon, d.DecisionHorizon}, {&c.TerminalGrace, d.TerminalGrace},
		{&c.WaitTimeout, d.WaitTimeout}, {&c.ShutdownTimeout, d.ShutdownTimeout},
	} {
		if *p.v == 0 {
			*p.v = p.d
		}
	}
	if c.SDPOriginMaxTracked == 0 {
		c.SDPOriginMaxTracked = d.SDPOriginMaxTracked
	}
	if c.MaxCandidates == 0 {
		c.MaxCandidates = d.MaxCandidates
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = d.MaxRecords
	}
	return c
}

func (c CallCorrelationConfig) Enabled() bool {
	return len(c.SessionHeaders) > 0 || len(c.ParentCallIDHeaders) > 0 || c.SDPOriginMatching || c.AddressChaining || c.AddressChainingRewritten || c.NumberChaining
}

func validCorrelationHeader(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-.!%*_+`'~", r)) {
			return false
		}
	}
	return true
}

func (c CallCorrelationConfig) Validate() error {
	c = c.Normalized()
	for _, d := range []time.Duration{c.SDPOriginReuseWindow, c.SDPOriginObservationTTL, c.SDPOriginSuspend, c.AddressWindow, c.NumberWindow, c.DecisionHorizon, c.TerminalGrace, c.WaitTimeout, c.ShutdownTimeout} {
		if d <= 0 {
			return fmt.Errorf("LI call correlation durations must be positive")
		}
	}
	if c.MaxCandidates < 1 || c.MaxRecords < 1 || c.SDPOriginMaxTracked < 1 {
		return fmt.Errorf("LI call correlation limits must be positive")
	}
	if c.MaxCandidates > 1000000 || c.MaxRecords > 1000000 || c.SDPOriginMaxTracked > 1000000 {
		return fmt.Errorf("LI call correlation limits exceed the supported ceiling of 1000000")
	}
	if c.SDPOriginMatching && c.SDPOriginObservationTTL <= c.SDPOriginReuseWindow {
		return fmt.Errorf("LI SDP origin observation TTL must exceed its reuse window")
	}
	if len(c.SessionHeaders)+len(c.ParentCallIDHeaders) > 32 {
		return fmt.Errorf("LI call correlation supports at most 32 configured headers")
	}
	seen := map[string]bool{}
	for _, names := range [][]string{c.SessionHeaders, c.ParentCallIDHeaders} {
		for _, n := range names {
			if !validCorrelationHeader(n) {
				return fmt.Errorf("invalid LI correlation header name")
			}
			key := strings.ToLower(n)
			if seen[key] {
				return fmt.Errorf("duplicate LI correlation header name")
			}
			seen[key] = true
		}
	}
	aliases := map[netip.Addr]bool{}
	if len(c.NodeAliases) > c.MaxCandidates {
		return fmt.Errorf("LI correlation alias sets exceed candidate limit")
	}
	for _, set := range c.NodeAliases {
		if len(set) < 2 || len(set) > 256 {
			return fmt.Errorf("LI correlation alias sets require 2 to 256 addresses")
		}
		for _, value := range set {
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.Zone() != "" {
				return fmt.Errorf("invalid LI correlation alias address")
			}
			addr = addr.Unmap()
			if aliases[addr] {
				return fmt.Errorf("LI correlation alias address belongs to multiple entries")
			}
			aliases[addr] = true
		}
	}
	if strings.ContainsRune(c.StoreFile, 0) {
		return fmt.Errorf("invalid LI correlation store path")
	}
	if c.StoreFile != "" || c.StoreKeys.Active.ID != "" || c.StoreKeys.Active.File != "" || len(c.StoreKeys.Prior) > 0 || c.StoreKeys.LegacyID != "" {
		if len(c.StoreKeys.Prior) > securestore.MaxPriorKeys {
			return fmt.Errorf("LI correlation store supports at most four prior keys")
		}
		refs := append([]securestore.KeyRef{c.StoreKeys.Active}, c.StoreKeys.Prior...)
		ids := map[string]bool{}
		for _, ref := range refs {
			if _, err := securestore.ParseReadKey(ref.ID + "=" + ref.File); err != nil || strings.ContainsRune(ref.File, 0) {
				return fmt.Errorf("LI correlation store requires valid encryption key IDs and paths")
			}
			if ids[ref.ID] {
				return fmt.Errorf("duplicate LI correlation encryption key ID")
			}
			ids[ref.ID] = true
		}
		if c.StoreKeys.LegacyID != "" && !ids[c.StoreKeys.LegacyID] {
			return fmt.Errorf("LI correlation legacy key ID is not configured")
		}
	}

	return nil
}
