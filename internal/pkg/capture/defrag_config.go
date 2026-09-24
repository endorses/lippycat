package capture

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// IPv4DefragConfigFromViper reads the common ipv4_defrag configuration used by
// hunt, tap, sniff, and watch-live. Durations are Go duration strings.
func IPv4DefragConfigFromViper() (IPv4DefragConfig, error) {
	config := IPv4DefragConfig{}
	for _, setting := range []struct {
		key string
		dst *int
	}{
		{"ipv4_defrag.max_datagrams", &config.MaxDatagrams},
		{"ipv4_defrag.max_fragments", &config.MaxFragments},
		{"ipv4_defrag.max_payload_bytes", &config.MaxPayloadBytes},
		{"ipv4_defrag.max_fragments_per_datagram", &config.MaxFragmentsPerDatagram},
	} {
		raw, present, err := ipv4ConfigValue(setting.key)
		if err != nil {
			return config, err
		}
		if !present {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return config, fmt.Errorf("%s must be an integer, got %q: %w", setting.key, raw, err)
		}
		*setting.dst = value
	}
	for _, setting := range []struct {
		key string
		dst *time.Duration
	}{
		{"ipv4_defrag.stale_age", &config.StaleAge},
		{"ipv4_defrag.sweep_interval", &config.SweepInterval},
	} {
		raw, present, err := ipv4ConfigValue(setting.key)
		if err != nil {
			return config, err
		}
		if !present {
			continue
		}
		value, err := time.ParseDuration(raw)
		if err != nil {
			return config, fmt.Errorf("%s: %w", setting.key, err)
		}
		*setting.dst = value
	}
	return config.Resolve()
}

// ipv4ConfigValue is read-only. Binding environment variables here would mutate
// Viper's global maps while concurrent capture sessions read configuration.
func ipv4ConfigValue(key string) (string, bool, error) {
	if raw, present := os.LookupEnv("LIPPYCAT_" + envKey(key)); present {
		if strings.TrimSpace(raw) == "" {
			return "", false, fmt.Errorf("%s must not be empty", key)
		}
		return raw, true, nil
	}
	if !viper.IsSet(key) {
		return "", false, nil
	}
	return viper.GetString(key), true, nil
}

func ValidateIPv4DefragConfig() error {
	_, err := IPv4DefragConfigFromViper()
	return err
}

func envKey(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
