package mediarules

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// Settings is shared by processor publication and hunter/tap subscriptions.
// Defaults are configurable operational bounds, not performance requirements.
type Settings struct {
	Enabled             bool          `mapstructure:"enabled"`
	ProcessorID         string        `mapstructure:"processor_id"`
	RuleTTL             time.Duration `mapstructure:"rule_ttl"`
	MaxLifetime         time.Duration `mapstructure:"max_lifetime"`
	MaxRules            int           `mapstructure:"max_rules"`
	MaxBytes            int           `mapstructure:"max_bytes"`
	MaxEndpoints        int           `mapstructure:"max_endpoints"`
	MaxEndpointsPerRule int           `mapstructure:"max_endpoints_per_rule"`
	MaxSubscribers      int           `mapstructure:"max_subscribers"`
	SubscriptionBuffer  int           `mapstructure:"subscription_buffer"`
	MaxMessageBytes     int           `mapstructure:"max_message_bytes"`
	MaxSnapshotBytes    int           `mapstructure:"max_snapshot_bytes"`
	ClockUncertainty    time.Duration `mapstructure:"clock_uncertainty"`
}

func (s Settings) Normalize() (Settings, error) {
	if s.RuleTTL == 0 {
		s.RuleTTL = 30 * time.Second
	}
	if s.MaxLifetime == 0 {
		s.MaxLifetime = 5 * time.Minute
	}
	if s.MaxRules == 0 {
		s.MaxRules = 10000
	}
	if s.MaxBytes == 0 {
		s.MaxBytes = 32 << 20
	}
	if s.MaxEndpoints == 0 {
		s.MaxEndpoints = 40000
	}
	if s.MaxEndpointsPerRule == 0 {
		s.MaxEndpointsPerRule = 32
	}
	if s.MaxSubscribers == 0 {
		s.MaxSubscribers = 256
	}
	if s.SubscriptionBuffer == 0 {
		s.SubscriptionBuffer = 64
	}
	if s.MaxMessageBytes == 0 {
		s.MaxMessageBytes = 1 << 20
	}
	if s.MaxSnapshotBytes == 0 {
		s.MaxSnapshotBytes = 32 << 20
	}
	if s.RuleTTL < time.Millisecond || s.RuleTTL > s.MaxLifetime || s.MaxMessageBytes < 128 || s.MaxMessageBytes > 4<<20 || s.MaxSnapshotBytes < s.MaxMessageBytes || s.MaxRules <= 0 || s.MaxBytes <= 0 || s.MaxEndpoints <= 0 || s.MaxEndpointsPerRule <= 0 || s.MaxSubscribers <= 0 || s.SubscriptionBuffer <= 0 || s.ClockUncertainty < 0 || s.ClockUncertainty >= s.RuleTTL/2 {
		return s, fmt.Errorf("invalid temporary media-rule bounds or lifetime")
	}
	return s, nil
}

func (s Settings) StoreConfig(processorID, hunterID string, domains []mediaadmission.DomainID, observer Observer) Config {
	return Config{ProcessorID: processorID, HunterID: hunterID, Domains: domains,
		MaxRules: s.MaxRules, MaxBytes: s.MaxBytes, MaxEndpoints: s.MaxEndpoints,
		MaxEndpointsPerRule: s.MaxEndpointsPerRule, MaxSubscribers: s.MaxSubscribers,
		SubscriptionBuffer: s.SubscriptionBuffer, MaxLifetime: s.MaxLifetime,
		ClockUncertainty: s.ClockUncertainty, Observer: observer}
}
