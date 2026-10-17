//go:build hunter || all

package packetforwarding

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

type Config struct {
	DeliveryProfile string      `mapstructure:"delivery_profile"`
	AckScope        string      `mapstructure:"ack_scope"`
	DestinationID   string      `mapstructure:"destination_id"`
	TrustedCert     string      `mapstructure:"trusted_cert"`
	Spool           SpoolConfig `mapstructure:"spool"`
}
type SpoolConfig struct {
	Directory        string                `mapstructure:"dir"`
	Protection       string                `mapstructure:"protection"`
	MaxBytes         uint64                `mapstructure:"max_bytes"`
	MaxRecordBytes   uint64                `mapstructure:"max_record_bytes"`
	MaxReadBytes     uint64                `mapstructure:"max_read_bytes"`
	MaxAge           time.Duration         `mapstructure:"max_age"`
	MaxRecords       int                   `mapstructure:"max_records"`
	MaxLossRanges    int                   `mapstructure:"max_loss_ranges"`
	ExhaustionPolicy string                `mapstructure:"exhaustion_policy"`
	Keys             securestore.KeyConfig `mapstructure:"keys"`
}

func (c Config) Normalize() (Config, error) {
	c.DeliveryProfile = strings.ReplaceAll(strings.ToLower(c.DeliveryProfile), "-", "_")
	if c.DeliveryProfile == "" {
		c.DeliveryProfile = "best_effort"
	}
	if c.DeliveryProfile != "best_effort" && c.DeliveryProfile != "reliable" {
		return Config{}, errors.New("packet delivery profile must be best_effort or reliable")
	}
	if c.DeliveryProfile == "best_effort" {
		if c.AckScope != "" || c.DestinationID != "" || c.TrustedCert != "" || c.Spool.Directory != "" || c.Spool.Protection != "" {
			return Config{}, errors.New("raw receipt and spool settings require reliable packet delivery")
		}
		return c, nil
	}
	if c.AckScope == "" {
		c.AckScope = "receiver"
	}
	if c.AckScope != "receiver" && c.AckScope != "central" {
		return Config{}, errors.New("packet ack scope must be receiver or central")
	}
	if c.DestinationID == "" || c.TrustedCert == "" {
		return Config{}, errors.New("reliable packets require destination_id and a pinned trusted receipt certificate")
	}
	if c.Spool.Directory == "" || c.Spool.Protection == "" {
		return Config{}, errors.New("reliable packets require explicit spool directory and protection")
	}
	return c, nil
}

func (c Config) SpoolConfig(source string) (packetspool.Config, error) {
	var keys *securestore.Keyring
	if c.Spool.Protection == packetspool.Encrypted {
		var err error
		keys, err = securestore.LoadKeyring(c.Spool.Keys)
		if err != nil {
			return packetspool.Config{}, err
		}
	} else if c.Spool.Keys.Active.ID != "" || c.Spool.Keys.Active.File != "" || len(c.Spool.Keys.Prior) > 0 {
		return packetspool.Config{}, errors.New("private packet storage forbids encryption keys")
	}
	config, err := (packetspool.Config{Directory: c.Spool.Directory, SourceID: source, DestinationID: c.DestinationID, AckScope: c.AckScope, Protection: c.Spool.Protection, Keys: keys, MaxBytes: c.Spool.MaxBytes, MaxRecordBytes: c.Spool.MaxRecordBytes, MaxReadBytes: c.Spool.MaxReadBytes, MaxAge: c.Spool.MaxAge, MaxRecords: c.Spool.MaxRecords, MaxLossRanges: c.Spool.MaxLossRanges, Policy: packetspool.ExhaustionPolicy(c.Spool.ExhaustionPolicy)}).Validate()
	if err != nil {
		return packetspool.Config{}, fmt.Errorf("raw packet spool: %w", err)
	}
	return config, nil
}
