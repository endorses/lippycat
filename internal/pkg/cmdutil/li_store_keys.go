//go:build li

package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// LIStoreKeys contains references only. The storage owners validate key files,
// initialized snapshots, and independence before enabling their runtimes.
type LIStoreKeys struct {
	StateFile string
	State     securestore.KeyConfig
	X2        securestore.KeyConfig
	X3        securestore.KeyConfig
}

var liStoreKeySettings = []struct {
	flag, key string
	prior     bool
}{
	{"li-state-file", "state_file", false},
	{"li-state-key-file", "state_key_file", false},
	{"li-state-key-id", "state_key_id", false},
	{"li-state-read-key", "state_read_keys", true},
	{"li-delivery-x2-spool-key-file", "delivery_x2_spool_key_file", false},
	{"li-delivery-x2-spool-key-id", "delivery_x2_spool_key_id", false},
	{"li-delivery-x2-spool-legacy-key-id", "delivery_x2_spool_legacy_key_id", false},
	{"li-delivery-x2-spool-read-key", "delivery_x2_spool_read_keys", true},
	{"li-delivery-x3-spool-key-file", "delivery_x3_spool_key_file", false},
	{"li-delivery-x3-spool-key-id", "delivery_x3_spool_key_id", false},
	{"li-delivery-x3-spool-read-key", "delivery_x3_spool_read_keys", true},
}

// RegisterLIStoreKeyFlags extends the existing state/X2 path flags without
// changing the original X2 raw-key-file meaning.
func RegisterLIStoreKeyFlags(flags *pflag.FlagSet, config *viper.Viper, role string) error {
	flags.String("li-state-key-file", "", "Private raw 32-byte key for the encrypted LI administrative snapshot")
	flags.String("li-state-key-id", "", "Active LI administrative-state key ID")
	flags.StringArray("li-state-read-key", nil, "Prior LI state key id=path (repeatable, at most four; empty clears configured keys)")
	flags.String("li-delivery-x2-spool-key-id", "", "Active X2 journal key ID (empty preserves key-file-only compatibility)")
	flags.String("li-delivery-x2-spool-legacy-key-id", "", "Explicit configured read-key ID for legacy LCX2 records")
	flags.StringArray("li-delivery-x2-spool-read-key", nil, "Prior X2 key id=path (repeatable, at most four; empty clears configured keys)")
	flags.String("li-delivery-x3-spool-key-id", "", "Active X3 journal key ID")
	flags.StringArray("li-delivery-x3-spool-read-key", nil, "Prior X3 key id=path (repeatable, at most four; empty clears configured keys)")
	for _, setting := range liStoreKeySettings {
		flag := flags.Lookup(setting.flag)
		if flag == nil {
			return errors.New("LI store path flags must be registered first")
		}
		key := role + ".li." + setting.key
		if err := config.BindPFlag(key, flag); err != nil {
			return fmt.Errorf("bind LI store key flag: %w", err)
		}
		if err := config.BindEnv(key, filterStoreEnv(role, "li."+setting.key)); err != nil {
			return fmt.Errorf("bind LI store key environment: %w", err)
		}
	}
	return nil
}

// ReadLIStoreKeys applies CLI > explicit environment > YAML > constructor
// defaults, preserving explicit empty values. Environment prior-key lists use
// one CSV record, with the same rules as the common managed filter key list.
func ReadLIStoreKeys(flags *pflag.FlagSet, config *viper.Viper, role string, base LIStoreKeys) (LIStoreKeys, error) {
	result := base
	result.State.Prior = append([]securestore.KeyRef(nil), base.State.Prior...)
	result.X2.Prior = append([]securestore.KeyRef(nil), base.X2.Prior...)
	result.X3.Prior = append([]securestore.KeyRef(nil), base.X3.Prior...)
	for _, setting := range liStoreKeySettings {
		flag := flags.Lookup(setting.flag)
		if flag == nil {
			return LIStoreKeys{}, errors.New("LI store key flag is not registered")
		}
		var raw any
		isCSV := false
		isX3 := strings.HasPrefix(setting.key, "delivery_x3_")
		switch {
		case flag.Changed:
			if setting.prior {
				values, err := flags.GetStringArray(setting.flag)
				if err != nil {
					return LIStoreKeys{}, errors.New("invalid LI store read-key flag")
				}
				raw = values
			} else {
				raw = flag.Value.String()
			}
		default:
			if value, present := os.LookupEnv(filterStoreEnv(role, "li."+setting.key)); present {
				raw, isCSV = value, true
			} else if isX3 {
				value, present := x3ConfiguredValue(config, role, setting.key)
				if !present {
					continue
				}
				raw = value
			} else if config.InConfig(role + ".li." + setting.key) {
				raw = config.Get(role + ".li." + setting.key)
			} else {
				continue
			}
		}
		if isX3 && raw == nil {
			return LIStoreKeys{}, fmt.Errorf("%s.li.%s must not be null", role, setting.key)
		}
		if setting.prior {
			refs, err := parseFilterReadKeys(raw, isCSV)
			if err != nil {
				return LIStoreKeys{}, errors.New("LI store read keys require at most four unique id=path entries")
			}
			if setting.key == "state_read_keys" {
				result.State.Prior = refs
			} else if setting.key == "delivery_x2_spool_read_keys" {
				result.X2.Prior = refs
			} else {
				result.X3.Prior = refs
			}
			continue
		}
		value, ok := raw.(string)
		if !ok && raw != nil {
			return LIStoreKeys{}, fmt.Errorf("%s.li.%s must be a string", role, setting.key)
		}
		switch setting.key {
		case "state_file":
			result.StateFile = value
		case "state_key_file":
			result.State.Active.File = value
		case "state_key_id":
			result.State.Active.ID = value
		case "delivery_x2_spool_key_file":
			result.X2.Active.File = value
		case "delivery_x2_spool_key_id":
			result.X2.Active.ID = value
		case "delivery_x2_spool_legacy_key_id":
			result.X2.LegacyID = value
		case "delivery_x3_spool_key_file":
			result.X3.Active.File = value
		case "delivery_x3_spool_key_id":
			result.X3.Active.ID = value
		}
	}
	for _, keys := range []securestore.KeyConfig{result.State, result.X2, result.X3} {
		seen := map[string]bool{keys.Active.ID: true}
		for _, ref := range keys.Prior {
			if seen[ref.ID] {
				return LIStoreKeys{}, errors.New("duplicate LI store key ID")
			}
			seen[ref.ID] = true
		}
	}
	return result, nil
}
