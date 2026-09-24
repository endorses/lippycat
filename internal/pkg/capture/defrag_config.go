package capture

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
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
		if err := validateIPv4ConfigPresence(setting.key); err != nil {
			return config, err
		}
		if err := viper.BindEnv(setting.key, "LIPPYCAT_"+envKey(setting.key)); err != nil {
			return config, fmt.Errorf("bind %s: %w", setting.key, err)
		}
		value, err := cmdutil.GetIntConfigStrict(setting.key, 0)
		if err != nil {
			return config, err
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
		if err := validateIPv4ConfigPresence(setting.key); err != nil {
			return config, err
		}
		if err := viper.BindEnv(setting.key, "LIPPYCAT_"+envKey(setting.key)); err != nil {
			return config, fmt.Errorf("bind %s: %w", setting.key, err)
		}
		if !viper.IsSet(setting.key) {
			continue
		}
		value, err := time.ParseDuration(viper.GetString(setting.key))
		if err != nil {
			return config, fmt.Errorf("%s: %w", setting.key, err)
		}
		*setting.dst = value
	}
	return config.Resolve()
}

func validateIPv4ConfigPresence(key string) error {
	if raw, present := os.LookupEnv("LIPPYCAT_" + envKey(key)); present && strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s must not be empty", key)
	}
	return nil
}

func ValidateIPv4DefragConfig() error {
	_, err := IPv4DefragConfigFromViper()
	return err
}

func envKey(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
