//go:build processor || tap || all

package processor

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
)

// MediaSourceMapping explicitly joins a captured interface to a processor
// observation domain and maps that domain back to the hunter's local numbering.
// HunterID "*" enables the profile for all authenticated registered hunters.
type MediaSourceMapping struct {
	HunterID     string                  `mapstructure:"hunter_id"`
	Interface    string                  `mapstructure:"interface"`
	Domain       mediaadmission.DomainID `mapstructure:"domain"`
	HunterDomain mediaadmission.DomainID `mapstructure:"hunter_domain"`
}

type MediaRulesConfig struct {
	mediarules.Settings `mapstructure:",squash"`
	Sources             []MediaSourceMapping `mapstructure:"sources"`
	TrailingGrace       time.Duration        `mapstructure:"trailing_grace"`
	CallTimeout         time.Duration        `mapstructure:"call_timeout"`
}

func (c MediaRulesConfig) normalize(processorID string) (MediaRulesConfig, error) {
	var err error
	c.Settings, err = c.Settings.Normalize()
	if err != nil {
		return c, err
	}
	if c.Enabled && (processorID == "" || (c.ProcessorID != "" && c.ProcessorID != processorID)) {
		return c, fmt.Errorf("temporary media-rule processor_id must match the configured processor")
	}
	c.ProcessorID = processorID
	if c.TrailingGrace == 0 {
		c.TrailingGrace = 5 * time.Second
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = 30 * time.Minute
	}
	if c.TrailingGrace < 0 || c.CallTimeout <= 0 || (c.Enabled && len(c.Sources) == 0) || len(c.Sources) > c.MaxEndpoints {
		return c, fmt.Errorf("media rules require explicit bounded source mappings and valid call lifetimes")
	}
	seen := make(map[string]bool, len(c.Sources))
	for _, m := range c.Sources {
		key := m.HunterID + "\x00" + m.Interface
		if m.HunterID == "" || m.Interface == "" || seen[key] {
			return c, fmt.Errorf("media source mappings require unique hunter/interface pairs")
		}
		seen[key] = true
	}
	for i, left := range c.Sources {
		for _, right := range c.Sources[i+1:] {
			if (left.HunterID == right.HunterID || left.HunterID == "*" || right.HunterID == "*") && left.HunterDomain == right.HunterDomain && left.Domain != right.Domain {
				return c, fmt.Errorf("one hunter observation domain cannot represent separate processor domains")
			}
		}
	}
	c.Sources = append([]MediaSourceMapping(nil), c.Sources...)
	return c, nil
}
