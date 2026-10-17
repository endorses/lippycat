// Package filterpolicy implements authenticated, route-independent full filter
// snapshots. It does not interpret LI tasks or grant offline interception rights.
package filterpolicy

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/viper"
)

type Config struct {
	Owner             string                `mapstructure:"owner"`
	Mode              string                `mapstructure:"mode"`
	Domain            string                `mapstructure:"domain"`
	AuthorityID       string                `mapstructure:"authority"`
	TrustedCertFile   string                `mapstructure:"trusted_cert"`
	SigningKeyFile    string                `mapstructure:"signing_key"`
	StateFile         string                `mapstructure:"state_file"`
	Startup           string                `mapstructure:"startup"`
	Replicas          []failover.Endpoint   `mapstructure:"replicas"`
	SyncInterval      time.Duration         `mapstructure:"sync_interval"`
	StorageProtection string                `mapstructure:"storage_protection"`
	StorageKeys       securestore.KeyConfig `mapstructure:"storage_keys"`
}

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func Namespace(domain string) string { return "shared/" + domain + "/" }
func (c Config) Namespace() string {
	if c.Owner == "li" {
		return "li-"
	}
	return Namespace(c.Domain)
}

func Normalize(c Config) (Config, error) {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = "processor"
	}
	if c.Mode != "processor" && c.Mode != "shared" {
		return Config{}, fmt.Errorf("filter_policy.mode must be processor or shared")
	}
	if c.Mode == "processor" {
		if c.Owner != "" || c.Domain != "" || c.AuthorityID != "" || c.TrustedCertFile != "" || c.SigningKeyFile != "" || c.StateFile != "" || len(c.Replicas) > 0 || c.Startup != "" || c.SyncInterval != 0 || c.StorageProtection != "" || hasStorageKeys(c.StorageKeys) {
			return Config{}, fmt.Errorf("shared filter policy settings require mode shared")
		}
		return c, nil
	}
	if c.Owner == "" {
		c.Owner = "shared"
	}
	if c.Owner != "shared" && c.Owner != "li" {
		return Config{}, fmt.Errorf("filter_policy.owner must be shared or li")
	}
	if c.StorageProtection == "" {
		if c.Owner == "li" {
			return Config{}, fmt.Errorf("LI capture policy requires explicit encrypted storage_protection")
		}
		c.StorageProtection = "private"
	}
	if c.StorageProtection != "private" && c.StorageProtection != "encrypted" {
		return Config{}, fmt.Errorf("filter_policy.storage_protection must be private or encrypted")
	}
	if c.Owner == "li" && c.StorageProtection != "encrypted" {
		return Config{}, fmt.Errorf("LI capture policy requires encrypted state storage")
	}
	if c.StorageProtection == "private" && hasStorageKeys(c.StorageKeys) {
		return Config{}, fmt.Errorf("private policy storage forbids encryption key references")
	}
	if c.StorageProtection == "encrypted" && (c.StorageKeys.Active.ID == "" || c.StorageKeys.Active.File == "") {
		return Config{}, fmt.Errorf("encrypted policy storage requires active storage_keys")
	}
	if !identityPattern.MatchString(c.Domain) || !identityPattern.MatchString(c.AuthorityID) || c.TrustedCertFile == "" || c.StateFile == "" {
		return Config{}, fmt.Errorf("shared filter policy requires bounded domain, authority, trusted_cert and state_file")
	}
	if c.Startup == "" {
		c.Startup = "wait"
	}
	if c.Startup != "wait" && c.Startup != "cached" && c.Startup != "local" {
		return Config{}, fmt.Errorf("filter_policy.startup must be wait, cached or local")
	}
	if c.SyncInterval == 0 {
		c.SyncInterval = 5 * time.Second
	}
	if c.SyncInterval < 0 {
		return Config{}, fmt.Errorf("filter_policy.sync_interval must be positive")
	}
	endpoints, err := failover.NormalizeEndpoints("", c.Replicas)
	if err != nil {
		return Config{}, fmt.Errorf("filter policy replicas: %w", err)
	}
	c.Replicas = endpoints
	return c, nil
}

// FromViper decodes and validates a complete optional policy profile. Signing and
// replicas are processor-side settings; hunters additionally reject those fields.
func FromViper(v *viper.Viper, prefix string) (Config, error) {
	var c Config
	if err := v.UnmarshalKey(prefix+".filter_policy", &c); err != nil {
		return Config{}, fmt.Errorf("decode %s.filter_policy: %w", prefix, err)
	}
	return Normalize(c)
}

func hasStorageKeys(keys securestore.KeyConfig) bool {
	return keys.Active.ID != "" || keys.Active.File != "" || len(keys.Prior) > 0 || keys.LegacyID != ""
}
