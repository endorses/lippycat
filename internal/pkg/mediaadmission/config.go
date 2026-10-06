package mediaadmission

import (
	"fmt"
	"sort"
	"time"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeShadow  Mode = "shadow"
)

type FailurePolicy string

const (
	FailureOpen   FailurePolicy = "open"
	FailureClosed FailurePolicy = "closed"
)

// Config defaults are bounded resource settings, not performance targets.
// InterfaceDomains overrides the shared default domain (zero) per interface.
type Config struct {
	Enabled                 bool                `mapstructure:"enabled" yaml:"enabled"`
	Mode                    Mode                `mapstructure:"mode" yaml:"mode"`
	FailurePolicy           FailurePolicy       `mapstructure:"failure_policy" yaml:"failure_policy"`
	InterfaceDomains        map[string]DomainID `mapstructure:"interface_domains" yaml:"interface_domains"`
	EndpointCapacity        int                 `mapstructure:"endpoint_capacity" yaml:"endpoint_capacity"`
	OwnerCapacity           int                 `mapstructure:"owner_capacity" yaml:"owner_capacity"`
	MaxEndpointsPerOwner    int                 `mapstructure:"max_endpoints_per_owner" yaml:"max_endpoints_per_owner"`
	PendingDialogCapacity   int                 `mapstructure:"pending_dialog_capacity" yaml:"pending_dialog_capacity"`
	PendingEndpointCapacity int                 `mapstructure:"pending_endpoint_capacity" yaml:"pending_endpoint_capacity"`
	PendingBytes            int                 `mapstructure:"pending_bytes" yaml:"pending_bytes"`
	PendingTTL              time.Duration       `mapstructure:"pending_ttl" yaml:"pending_ttl"`
	ReplayWindow            time.Duration       `mapstructure:"replay_window" yaml:"replay_window"`
	ReplayGuardCapacity     int                 `mapstructure:"replay_guard_capacity" yaml:"replay_guard_capacity"`
	ReplayGuardBytes        int                 `mapstructure:"replay_guard_bytes" yaml:"replay_guard_bytes"`
	ExpirationBatch         int                 `mapstructure:"expiration_batch" yaml:"expiration_batch"`
	RetryInterval           time.Duration       `mapstructure:"retry_interval" yaml:"retry_interval"`
	ShadowEvidenceCapacity  int                 `mapstructure:"shadow_evidence_capacity" yaml:"shadow_evidence_capacity"`
	ShadowSampleEvery       uint32              `mapstructure:"shadow_sample_every" yaml:"shadow_sample_every"`
	MissingMediaInterval    time.Duration       `mapstructure:"missing_media_interval" yaml:"missing_media_interval"`
}

func DefaultConfig() Config {
	return Config{Mode: ModeEnforce, FailurePolicy: FailureOpen,
		EndpointCapacity: 40000, OwnerCapacity: 10000, MaxEndpointsPerOwner: 32,
		PendingDialogCapacity: 10000, PendingEndpointCapacity: 40000, PendingBytes: 8 << 20,
		PendingTTL: 30 * time.Second, ReplayWindow: 2 * time.Minute, ReplayGuardCapacity: 10000, ReplayGuardBytes: 2 << 20,
		ExpirationBatch: 256, RetryInterval: time.Second,
		ShadowEvidenceCapacity: 1024, ShadowSampleEvery: 1, MissingMediaInterval: 30 * time.Second}
}

// Validate does not silently substitute defaults for explicitly invalid limits.
// Callers decode user settings over DefaultConfig before calling this method.
func (c Config) Validate() error {
	if c.Mode != ModeEnforce && c.Mode != ModeShadow {
		return fmt.Errorf("invalid RTP eBPF mode %q", c.Mode)
	}
	if c.FailurePolicy != FailureOpen && c.FailurePolicy != FailureClosed {
		return fmt.Errorf("invalid RTP eBPF failure policy %q", c.FailurePolicy)
	}
	for name, value := range map[string]int{"endpoint_capacity": c.EndpointCapacity, "owner_capacity": c.OwnerCapacity,
		"max_endpoints_per_owner": c.MaxEndpointsPerOwner, "pending_dialog_capacity": c.PendingDialogCapacity,
		"pending_endpoint_capacity": c.PendingEndpointCapacity, "pending_bytes": c.PendingBytes,
		"expiration_batch": c.ExpirationBatch, "shadow_evidence_capacity": c.ShadowEvidenceCapacity,
		"replay_guard_capacity": c.ReplayGuardCapacity, "replay_guard_bytes": c.ReplayGuardBytes} {
		if value <= 0 {
			return fmt.Errorf("RTP eBPF %s must be positive", name)
		}
	}
	if c.PendingTTL <= 0 || c.ReplayWindow <= 0 || c.RetryInterval <= 0 || c.MissingMediaInterval <= 0 {
		return fmt.Errorf("RTP eBPF durations must be positive")
	}
	if c.ShadowSampleEvery == 0 {
		return fmt.Errorf("RTP eBPF shadow_sample_every must be positive")
	}
	if c.MaxEndpointsPerOwner > c.EndpointCapacity {
		return fmt.Errorf("RTP eBPF per-owner endpoints exceed endpoint capacity")
	}
	for name := range c.InterfaceDomains {
		if name == "" {
			return fmt.Errorf("RTP eBPF interface domain requires an interface name")
		}
	}
	return nil
}

func (c Config) DomainForInterface(name string) DomainID { return c.InterfaceDomains[name] }
func (c Config) Domains() []DomainID {
	set := map[DomainID]struct{}{0: {}}
	for _, domain := range c.InterfaceDomains {
		set[domain] = struct{}{}
	}
	domains := make([]DomainID, 0, len(set))
	for domain := range set {
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })
	return domains
}
