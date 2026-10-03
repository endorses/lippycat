// Package eventconfig owns the shared observation policy independently of logs.
package eventconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/endorses/lippycat/internal/pkg/dhcp"
	"github.com/endorses/lippycat/internal/pkg/ntp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const AnalysisRevision = "network-observations-v3"

type Inventory struct {
	Enabled                        bool
	LocalCIDRs                     []string
	MaxEntries, MaxEntriesPerScope int
	MaxBytes, MaxBytesPerScope     int64
	Retention                      time.Duration
}
type Config struct {
	DHCP      dhcp.Config
	NTP       ntp.Config
	Inventory Inventory
}

func Default() Config {
	return Config{DHCP: dhcp.DefaultConfig(), NTP: ntp.DefaultConfig(), Inventory: Inventory{Enabled: true, MaxEntries: 16384, MaxEntriesPerScope: 4096, MaxBytes: 8 << 20, MaxBytesPerScope: 2 << 20, Retention: 24 * time.Hour}}
}
func (c Config) Clone() Config {
	c.Inventory.LocalCIDRs = append([]string(nil), c.Inventory.LocalCIDRs...)
	return c
}
func (c Config) Validate() error {
	if err := c.DHCP.Validate(); err != nil {
		return err
	}
	if c.NTP.MaxEntries <= 0 || c.NTP.MaxBytes <= 0 || c.NTP.Timeout <= 0 {
		return fmt.Errorf("NTP association limits and timeout must be positive")
	}
	i := c.Inventory
	if i.MaxEntries <= 0 || i.MaxEntriesPerScope <= 0 || i.MaxBytes <= 0 || i.MaxBytesPerScope <= 0 || i.Retention <= 0 {
		return fmt.Errorf("inventory limits and retention must be positive")
	}
	if i.MaxEntriesPerScope > i.MaxEntries || i.MaxBytesPerScope > i.MaxBytes {
		return fmt.Errorf("inventory per-scope limits cannot exceed global limits")
	}
	for _, cidr := range i.LocalCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("inventory local CIDR %q: %w", cidr, err)
		}
		if p.Addr().Is4In6() && p.Bits() < 96 {
			return fmt.Errorf("inventory mapped IPv4 prefix %q is wider than IPv4", cidr)
		}
	}
	return nil
}

// Fingerprint binds offline sessions to effective policy and analysis revision.
// Equivalent ordering and host bits in CIDRs do not change the identity.
func (c Config) Fingerprint() string {
	c = c.Clone()
	for i, value := range c.Inventory.LocalCIDRs {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		} // Validate rejects malformed policy before runtime use.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		c.Inventory.LocalCIDRs[i] = p.Masked().String()
	}
	sort.Strings(c.Inventory.LocalCIDRs)
	unique := c.Inventory.LocalCIDRs[:0]
	for _, value := range c.Inventory.LocalCIDRs {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	c.Inventory.LocalCIDRs = unique
	// This concrete struct contains only JSON-supported scalar/slice fields.
	encoded, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Sprintf("encode event configuration: %v", err))
	}
	digest := sha256.Sum256(append([]byte(AnalysisRevision+"\x00"), encoded...))
	return AnalysisRevision + ":" + hex.EncodeToString(digest[:])
}

// FromViper takes an owned snapshot. Absent values use finite defaults; explicit
// zero/negative values survive to Validate instead of silently becoming defaults.
func FromViper(v *viper.Viper) *Config {
	c := Default()
	setInt := func(key string, dst *int) {
		if v.IsSet(key) {
			*dst = v.GetInt(key)
		}
	}
	setBytes := func(key string, dst *int64) {
		if v.IsSet(key) {
			*dst = v.GetInt64(key)
		}
	}
	setDuration := func(key string, dst *time.Duration) {
		if v.IsSet(key) {
			*dst = v.GetDuration(key)
		}
	}
	if v.IsSet("events.inventory.enabled") {
		c.Inventory.Enabled = v.GetBool("events.inventory.enabled")
	}
	c.Inventory.LocalCIDRs = append([]string(nil), v.GetStringSlice("events.inventory.local_cidrs")...)
	setInt("events.inventory.max_entries", &c.Inventory.MaxEntries)
	setInt("events.inventory.max_entries_per_scope", &c.Inventory.MaxEntriesPerScope)
	setBytes("events.inventory.max_bytes", &c.Inventory.MaxBytes)
	setBytes("events.inventory.max_bytes_per_scope", &c.Inventory.MaxBytesPerScope)
	setDuration("events.inventory.retention", &c.Inventory.Retention)
	setInt("events.dhcp.max_entries", &c.DHCP.MaxEntries)
	setInt("events.dhcp.max_bytes", &c.DHCP.MaxBytes)
	setDuration("events.dhcp.timeout", &c.DHCP.Timeout)
	setInt("events.ntp.max_entries", &c.NTP.MaxEntries)
	setBytes("events.ntp.max_bytes", &c.NTP.MaxBytes)
	setDuration("events.ntp.timeout", &c.NTP.Timeout)
	return &c
}

var bindings = map[string]string{
	"inventory": "events.inventory.enabled", "inventory-local-cidrs": "events.inventory.local_cidrs",
	"inventory-max-entries": "events.inventory.max_entries", "inventory-max-bytes": "events.inventory.max_bytes",
	"inventory-scope-max-entries": "events.inventory.max_entries_per_scope", "inventory-scope-max-bytes": "events.inventory.max_bytes_per_scope",
	"inventory-retention": "events.inventory.retention", "dhcp-association-max-entries": "events.dhcp.max_entries",
	"dhcp-association-max-bytes": "events.dhcp.max_bytes", "dhcp-association-timeout": "events.dhcp.timeout",
	"ntp-association-max-entries": "events.ntp.max_entries", "ntp-association-max-bytes": "events.ntp.max_bytes",
	"ntp-association-timeout": "events.ntp.timeout",
}

func Register(flags *pflag.FlagSet) {
	c := Default()
	flags.Bool("inventory", c.Inventory.Enabled, "Produce bounded known-host/service observations")
	flags.StringSlice("inventory-local-cidrs", nil, "Optional IPv4/IPv6 CIDRs restricting inventory subjects (default: all observed unicast addresses)")
	flags.Int("inventory-max-entries", c.Inventory.MaxEntries, "Maximum retained inventory entries")
	flags.Int64("inventory-max-bytes", c.Inventory.MaxBytes, "Maximum accounted inventory state bytes")
	flags.Int("inventory-scope-max-entries", c.Inventory.MaxEntriesPerScope, "Maximum inventory entries per capture scope")
	flags.Int64("inventory-scope-max-bytes", c.Inventory.MaxBytesPerScope, "Maximum accounted inventory bytes per capture scope")
	flags.Duration("inventory-retention", c.Inventory.Retention, "Capture-time inventory deduplication window")
	flags.Int("dhcp-association-max-entries", c.DHCP.MaxEntries, "Maximum DHCP association entries")
	flags.Int("dhcp-association-max-bytes", c.DHCP.MaxBytes, "Maximum accounted DHCP association bytes")
	flags.Duration("dhcp-association-timeout", c.DHCP.Timeout, "DHCP capture-time association timeout")
	flags.Int("ntp-association-max-entries", c.NTP.MaxEntries, "Maximum NTP association entries")
	flags.Int64("ntp-association-max-bytes", c.NTP.MaxBytes, "Maximum accounted NTP association bytes")
	flags.Duration("ntp-association-timeout", c.NTP.Timeout, "NTP capture-time association timeout")
	Bind(flags)
}
func Bind(flags *pflag.FlagSet) {
	for name, key := range bindings {
		if flag := flags.Lookup(name); flag != nil {
			// The flag is nonnil; BindPFlag cannot fail in this branch.
			if err := viper.BindPFlag(key, flag); err != nil {
				panic(fmt.Sprintf("bind event configuration %s: %v", name, err))
			}
		}
	}
}
