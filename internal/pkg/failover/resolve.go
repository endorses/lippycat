package failover

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Register adds shared destination selection flags and binds their config keys.
// The legacy scalar flag remains owned by the calling command.
func Register(flags *pflag.FlagSet, v *viper.Viper, prefix string) {
	defaults := DefaultConfig()
	flags.StringSlice("processors", nil, "Ordered processor addresses (comma-separated; one active connection)")
	flags.Duration("processor-attempt-timeout", defaults.AttemptTimeout, "Deadline for each processor connection setup attempt")
	flags.Int("processor-reconnect-attempts", defaults.ReconnectAttempts, "Retries of the active processor before trying another (0 = advance immediately)")
	// All names are fixed registered flags, so binding cannot fail.
	_ = v.BindPFlag(prefix+".processors", flags.Lookup("processors"))
	_ = v.BindPFlag(prefix+".failover.attempt_timeout", flags.Lookup("processor-attempt-timeout"))
	_ = v.BindPFlag(prefix+".failover.reconnect_attempts", flags.Lookup("processor-reconnect-attempts"))
}

// Resolve gives explicit command-line selectors priority over all configured
// selectors. Scalar and list selectors at the same priority are an error rather
// than an implicit merge. An absent selector is allowed for optional upstreams.
func Resolve(v *viper.Viper, flags *pflag.FlagSet, prefix, legacyKey, legacyFlag string) ([]Endpoint, Config, error) {
	listKey := prefix + ".processors"
	scalarCLI := changed(flags, legacyFlag)
	listCLI := changed(flags, "processors")
	if scalarCLI && listCLI {
		return nil, Config{}, fmt.Errorf("cannot use both --%s and --processors", legacyFlag)
	}
	var legacy string
	var endpoints []Endpoint
	var err error
	switch {
	case scalarCLI:
		legacy, err = flags.GetString(legacyFlag)
		if err == nil && strings.TrimSpace(legacy) == "" {
			err = fmt.Errorf("--%s must not be empty", legacyFlag)
		}
	case listCLI:
		var addresses []string
		addresses, err = flags.GetStringSlice("processors")
		if err == nil {
			endpoints, err = parseEndpoints(addresses)
		}
	default:
		scalarSet := configured(v, legacyKey)
		listSet := configured(v, listKey)
		if scalarSet && listSet {
			return nil, Config{}, fmt.Errorf("cannot configure both %s and %s", legacyKey, listKey)
		}
		if scalarSet {
			raw, ok := v.Get(legacyKey).(string)
			if !ok || strings.TrimSpace(raw) == "" {
				err = fmt.Errorf("%s must be a non-empty address string", legacyKey)
			} else {
				legacy = raw
			}
		}
		if listSet {
			endpoints, err = parseEndpoints(v.Get(listKey))
		}
	}
	if err != nil {
		return nil, Config{}, err
	}
	endpoints, err = NormalizeEndpoints(legacy, endpoints)
	if err != nil {
		return nil, Config{}, err
	}
	config, err := resolveConfig(v, prefix)
	if err != nil {
		return nil, Config{}, err
	}
	return endpoints, config, nil
}

func changed(flags *pflag.FlagSet, name string) bool {
	return flags != nil && flags.Lookup(name) != nil && flags.Lookup(name).Changed
}

func configured(v *viper.Viper, key string) bool {
	if v.InConfig(key) {
		return true
	}
	// IsSet alone includes bound flags. Empty selector defaults do not constitute
	// input, while nonempty programmatic/environment configuration still does.
	if !v.IsSet(key) {
		return false
	}
	switch value := v.Get(key).(type) {
	case nil:
		return false
	case string:
		return value != ""
	case []string:
		return len(value) != 0
	default:
		return true
	}
}

func parseEndpoints(raw any) ([]Endpoint, error) {
	var values []any
	switch value := raw.(type) {
	case []string:
		for _, item := range value {
			values = append(values, item)
		}
	case []any:
		values = value
	case []Endpoint:
		if len(value) == 0 {
			return nil, fmt.Errorf("processors must contain at least one address")
		}
		return append([]Endpoint(nil), value...), nil
	default:
		return nil, fmt.Errorf("processors must be a list of addresses or endpoint objects")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("processors must contain at least one address")
	}
	endpoints := make([]Endpoint, 0, len(values))
	for i, value := range values {
		switch entry := value.(type) {
		case string:
			endpoints = append(endpoints, Endpoint{Address: entry})
		case map[string]any:
			endpoint := Endpoint{}
			for key, rawField := range entry {
				field, ok := rawField.(string)
				if !ok {
					return nil, fmt.Errorf("processor candidate %d: %s must be a string", i+1, key)
				}
				switch key {
				case "address":
					endpoint.Address = field
				case "tls_server_name":
					endpoint.TLSServerName = field
				default:
					return nil, fmt.Errorf("processor candidate %d: unsupported setting %q", i+1, key)
				}
			}
			endpoints = append(endpoints, endpoint)
		default:
			return nil, fmt.Errorf("processor candidate %d must be an address string or endpoint object", i+1)
		}
	}
	return endpoints, nil
}

func resolveConfig(v *viper.Viper, prefix string) (Config, error) {
	config := DefaultConfig()
	durations := []struct {
		name   string
		target *time.Duration
	}{{"attempt_timeout", &config.AttemptTimeout}, {"retry_initial", &config.RetryInitial}, {"retry_max", &config.RetryMax}}
	for _, duration := range durations {
		key := prefix + ".failover." + duration.name
		if !v.IsSet(key) {
			continue
		}
		var value time.Duration
		var err error
		switch raw := v.Get(key).(type) {
		case time.Duration:
			value = raw
		case string:
			value, err = time.ParseDuration(raw)
		default:
			err = fmt.Errorf("expected a duration string with units")
		}
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive duration with units, got %v", key, v.Get(key))
		}
		*duration.target = value
	}
	key := prefix + ".failover.reconnect_attempts"
	if v.IsSet(key) {
		count, err := strconv.Atoi(fmt.Sprint(v.Get(key)))
		if err != nil || count < 0 {
			return Config{}, fmt.Errorf("%s must be a non-negative integer, got %v", key, v.Get(key))
		}
		config.ReconnectAttempts = count
	}
	return NormalizeConfig(config)
}
