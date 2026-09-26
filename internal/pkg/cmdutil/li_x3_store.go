//go:build li

package cmdutil

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// LIX3StoreSettings contains references and limits, never encryption material.
// Runtime owners independently enforce the persistence prerequisites.
type LIX3StoreSettings struct {
	Dir, ReplayManifest, ExportManifest, ReplayPolicy string
	MaxBytes                                          int64
	MaxAge                                            time.Duration
}

// ReadLIX3StoreSettings preserves explicit CLI/environment values instead of
// allowing Viper's empty-value fallback or weak casts to select another source.
func ReadLIX3StoreSettings(flags *pflag.FlagSet, config *viper.Viper, role string, base LIX3StoreSettings) (LIX3StoreSettings, error) {
	result := base
	for _, suffix := range []string{"spool-dir", "spool-replay-policy", "spool-max-bytes", "spool-replay-manifest", "spool-export-manifest", "max-age"} {
		flagName := "li-delivery-x3-" + suffix
		flag := flags.Lookup(flagName)
		if flag == nil {
			return LIX3StoreSettings{}, fmt.Errorf("X3 store flag %s is not registered", flagName)
		}
		keySuffix := "delivery_x3_" + replaceConfigSeparators(suffix)
		var raw any
		text := false
		if flag.Changed {
			raw, text = flag.Value.String(), true
		} else if value, present := os.LookupEnv(filterStoreEnv(role, "li."+keySuffix)); present {
			raw, text = value, true
		} else if value, present := x3ConfiguredValue(config, role, keySuffix); present {
			raw = value
		} else {
			continue
		}
		invalid := func() (LIX3StoreSettings, error) {
			return LIX3StoreSettings{}, fmt.Errorf("invalid %s.li.%s type or value", role, keySuffix)
		}
		switch suffix {
		case "spool-dir", "spool-replay-manifest", "spool-export-manifest":
			value, ok := raw.(string)
			if !ok {
				return invalid()
			}
			switch suffix {
			case "spool-dir":
				result.Dir = value
			case "spool-replay-manifest":
				result.ReplayManifest = value
			default:
				result.ExportManifest = value
			}
		case "spool-replay-policy":
			value, ok := raw.(string)
			if !ok || (value != "hold" && value != "purge") {
				return invalid()
			}
			result.ReplayPolicy = value
		case "spool-max-bytes":
			var value int64
			var err error
			if text {
				value, err = strconv.ParseInt(raw.(string), 10, 64)
			} else {
				switch n := raw.(type) {
				case int:
					value = int64(n)
				case int64:
					value = n
				default:
					return invalid()
				}
			}
			if err != nil || value < 0 {
				return invalid()
			}
			result.MaxBytes = value
		case "max-age":
			value, ok := raw.(string)
			if !ok {
				return invalid()
			}
			duration, err := time.ParseDuration(value)
			if err != nil || duration < 0 {
				return invalid()
			}
			result.MaxAge = duration
		}
	}
	return result, nil
}

func x3ConfiguredValue(config *viper.Viper, role, key string) (any, bool) {
	// InConfig reports false for a present YAML null. Inspect the parent map
	// so null cannot silently select a constructor default.
	if settings, ok := config.Get(role + ".li").(map[string]any); ok {
		value, present := settings[key]
		return value, present
	}
	return nil, false
}

func replaceConfigSeparators(value string) string {
	bytes := []byte(value)
	for i := range bytes {
		if bytes[i] == '-' {
			bytes[i] = '_'
		}
	}
	return string(bytes)
}
