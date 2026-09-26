package cmdutil

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var filterStoreSettings = []struct{ flag, key string }{
	{"filter-file", "filter_file"},
	{"filter-store-mode", "filter_store.mode"},
	{"filter-store-key-file", "filter_store.key_file"},
	{"filter-store-key-id", "filter_store.key_id"},
	{"filter-store-read-key", "filter_store.read_keys"},
}

func filterStoreEnv(role, key string) string {
	return "LIPPYCAT_" + strings.ToUpper(role+"_"+strings.ReplaceAll(key, ".", "_"))
}

// RegisterFilterStoreFlags adds the common encrypted-store flags and binds them,
// together with the existing filter-file flag, to role-scoped configuration.
// YAML read_keys is a string list. Its environment equivalent is a CSV record;
// quote entries containing commas. Empty CLI/environment values clear YAML.
func RegisterFilterStoreFlags(flags *pflag.FlagSet, config *viper.Viper, role string) error {
	if flags.Lookup("filter-file") == nil {
		return errors.New("filter-file must be registered before filter-store flags")
	}
	flags.String("filter-store-mode", "auto", "Managed filter storage: auto, yaml, or encrypted (auto uses encrypted storage when LI is enabled)")
	flags.String("filter-store-key-file", "", "Raw 32-byte active encryption key file for the managed filter store")
	flags.String("filter-store-key-id", "", "Active encryption key ID for the managed filter store")
	flags.StringArray("filter-store-read-key", nil, "Prior filter key id=path (repeatable, at most four; empty clears configured keys; "+filterStoreEnv(role, "filter_store.read_keys")+" accepts CSV)")
	for _, setting := range filterStoreSettings {
		key := role + "." + setting.key
		if err := config.BindPFlag(key, flags.Lookup(setting.flag)); err != nil {
			return fmt.Errorf("bind filter-store flag: %w", err)
		}
		if err := config.BindEnv(key, filterStoreEnv(role, setting.key)); err != nil {
			return fmt.Errorf("bind filter-store environment: %w", err)
		}
	}
	return nil
}

// ReadFilterStoreConfig overlays explicit CLI, environment, then YAML settings
// on a constructor's configuration. It preserves unconfigured constructor fields
// and leaves path/mode selection to the core runtime resolver. In particular, an
// explicitly empty value overrides lower-priority input rather than falling back.
func ReadFilterStoreConfig(flags *pflag.FlagSet, config *viper.Viper, role string, base filtering.StoreConfig) (filtering.StoreConfig, error) {
	result := base
	result.Keys.Prior = append([]securestore.KeyRef(nil), base.Keys.Prior...)
	for _, setting := range filterStoreSettings {
		flag := flags.Lookup(setting.flag)
		if flag == nil {
			return filtering.StoreConfig{}, errors.New("filter-store flag is not registered")
		}
		var raw any
		isCSV := false
		switch {
		case flag.Changed:
			if setting.flag == "filter-store-read-key" {
				values, err := flags.GetStringArray(setting.flag)
				if err != nil {
					return filtering.StoreConfig{}, errors.New("invalid filter-store read-key flag")
				}
				raw = values
			} else {
				raw = flag.Value.String()
			}
		default:
			if value, present := os.LookupEnv(filterStoreEnv(role, setting.key)); present {
				raw, isCSV = value, true
			} else if config.InConfig(role + "." + setting.key) {
				raw = config.Get(role + "." + setting.key)
			} else {
				continue
			}
		}
		if setting.flag == "filter-store-read-key" {
			refs, err := parseFilterReadKeys(raw, isCSV)
			if err != nil {
				return filtering.StoreConfig{}, err
			}
			result.Keys.Prior = refs
			continue
		}
		value, ok := raw.(string)
		if !ok && raw != nil {
			return filtering.StoreConfig{}, fmt.Errorf("%s.%s must be a string", role, setting.key)
		}
		switch setting.flag {
		case "filter-file":
			result.File = value
		case "filter-store-mode":
			result.Mode = filtering.StoreMode(value)
		case "filter-store-key-file":
			result.Keys.Active.File = value
		case "filter-store-key-id":
			result.Keys.Active.ID = value
		}
	}
	if result.Mode == "" {
		result.Mode = filtering.StoreAuto
	}
	// Reject reference ambiguity before opening any store. Key material and file
	// identity validation remain the keyring's responsibility.
	seen := map[string]bool{result.Keys.Active.ID: true}
	for _, ref := range result.Keys.Prior {
		if seen[ref.ID] {
			return filtering.StoreConfig{}, errors.New("duplicate filter-store key ID")
		}
		seen[ref.ID] = true
	}
	return result, nil
}

func parseFilterReadKeys(raw any, isCSV bool) ([]securestore.KeyRef, error) {
	var values []string
	switch value := raw.(type) {
	case nil:
	case []string:
		values = value
	case []any:
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New("filter-store read_keys must contain strings")
			}
			values = append(values, text)
		}
	case string:
		if !isCSV {
			return nil, errors.New("filter-store read_keys must be a list")
		}
		if value != "" {
			reader := csv.NewReader(strings.NewReader(value))
			records, err := reader.ReadAll()
			if err != nil || len(records) != 1 {
				return nil, errors.New("filter-store read-key environment must be one CSV record")
			}
			values = records[0]
		}
	default:
		return nil, errors.New("filter-store read_keys must be a list")
	}
	if len(values) == 1 && values[0] == "" {
		return nil, nil
	}
	if len(values) > securestore.MaxPriorKeys {
		return nil, errors.New("at most four prior filter-store read keys are supported")
	}
	refs := make([]securestore.KeyRef, 0, len(values))
	for _, value := range values {
		ref, err := securestore.ParseReadKey(value)
		if err != nil {
			return nil, fmt.Errorf("filter-store read key: %w", err)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
