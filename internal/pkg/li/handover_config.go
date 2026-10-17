package li

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// HandoverConfig is an explicit deployment contract for signed LI capture
// policy. It does not change task expiry or authorize historical delivery.
type HandoverConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	LeaseDuration    time.Duration `mapstructure:"lease_duration"`
	AllowOffline     bool          `mapstructure:"allow_offline"`
	ClockUncertainty time.Duration `mapstructure:"clock_uncertainty"`
	SourceIDs        []string      `mapstructure:"source_ids"`
}

func (c HandoverConfig) Normalize() (HandoverConfig, error) {
	if !c.Enabled {
		if c.LeaseDuration != 0 || c.AllowOffline || c.ClockUncertainty != 0 || len(c.SourceIDs) != 0 {
			return HandoverConfig{}, fmt.Errorf("LI handover settings require enabled")
		}
		return c, nil
	}
	if c.LeaseDuration <= 0 || c.ClockUncertainty < 0 || c.ClockUncertainty >= c.LeaseDuration/2 || len(c.SourceIDs) == 0 || len(c.SourceIDs) > 65536 {
		return HandoverConfig{}, fmt.Errorf("LI handover requires a positive lease_duration, bounded clock_uncertainty and explicit source_ids")
	}
	c.SourceIDs = append([]string(nil), c.SourceIDs...)
	sort.Strings(c.SourceIDs)
	for i, source := range c.SourceIDs {
		if source == "" || len(source) > 256 || strings.TrimSpace(source) != source || strings.ContainsAny(source, "\x00\r\n") || (i > 0 && source == c.SourceIDs[i-1]) {
			return HandoverConfig{}, fmt.Errorf("LI handover source IDs must be bounded, nonempty and unique")
		}
	}
	return c, nil
}
