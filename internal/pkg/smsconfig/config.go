package smsconfig

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/smsflow"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RegisterFlags installs opt-in keyword filtering and bounded assembly defaults.
// Prefixes identify the role, such as hunter.voip.sms or tap.voip.sms.
func RegisterFlags(cmd *cobra.Command, v *viper.Viper, prefix string) error {
	cmd.Flags().StringSlice("sms-keywords", nil, "Keep eligible SMS matching any literal keyword (case-insensitive; disabled when empty)")
	cmd.Flags().String("sms-keywords-file", "", "Read optional SMS keywords from a file, one per line")
	for flag, key := range map[string]string{"sms-keywords": "keywords", "sms-keywords-file": "keywords_file"} {
		if err := v.BindPFlag(prefix+"."+key, cmd.Flags().Lookup(flag)); err != nil {
			return fmt.Errorf("bind SMS flag %s: %w", flag, err)
		}
	}
	for key, value := range map[string]any{"max_assemblies": 1024, "max_bytes": 4 << 20, "max_segments": 255, "lifetime": "5m", "max_pending_messages": 4096, "max_pending_bytes": 16 << 20} {
		v.SetDefault(prefix+"."+key, value)
	}
	return nil
}

// ReadConfig resolves role-specific CLI/YAML settings before capture starts.
// Invalid budgets are rejected instead of silently selecting library defaults.
func ReadConfig(v *viper.Viper, prefix string) (smsflow.Config, error) {
	config := smsflow.Config{Assembly: sms.Config{MaxAssemblies: 1024, MaxBytes: 4 << 20, MaxSegments: 255, Lifetime: 5 * time.Minute}, MaxPendingMessages: 4096, MaxPendingBytes: 16 << 20}
	for key, destination := range map[string]*int{"max_assemblies": &config.Assembly.MaxAssemblies, "max_bytes": &config.Assembly.MaxBytes, "max_segments": &config.Assembly.MaxSegments, "max_pending_messages": &config.MaxPendingMessages, "max_pending_bytes": &config.MaxPendingBytes} {
		if !v.IsSet(prefix + "." + key) {
			continue
		}
		value, err := strconv.Atoi(fmt.Sprint(v.Get(prefix + "." + key)))
		if err != nil || value <= 0 {
			return config, fmt.Errorf("%s.%s must be a positive integer", prefix, key)
		}
		*destination = value
	}
	if config.Assembly.MaxSegments > 255 {
		return config, fmt.Errorf("%s.max_segments must not exceed 255", prefix)
	}
	if v.IsSet(prefix + ".lifetime") {
		switch value := v.Get(prefix + ".lifetime").(type) {
		case time.Duration:
			config.Assembly.Lifetime = value
		case string:
			duration, err := time.ParseDuration(value)
			if err != nil {
				return config, fmt.Errorf("%s.lifetime must be a positive duration", prefix)
			}
			config.Assembly.Lifetime = duration
		default:
			return config, fmt.Errorf("%s.lifetime must be a positive duration", prefix)
		}
		if config.Assembly.Lifetime <= 0 {
			return config, fmt.Errorf("%s.lifetime must be a positive duration", prefix)
		}
	}
	switch value := v.Get(prefix + ".keywords").(type) {
	case nil:
	case []string:
		config.Keywords = append([]string(nil), value...)
	case []any:
		for _, item := range value {
			keyword, ok := item.(string)
			if !ok {
				return config, fmt.Errorf("%s.keywords must contain strings", prefix)
			}
			config.Keywords = append(config.Keywords, keyword)
		}
	case string:
		if strings.TrimSpace(value) != "" {
			reader := csv.NewReader(strings.NewReader(value))
			reader.TrimLeadingSpace = true
			keywords, err := reader.Read()
			if err != nil {
				return config, fmt.Errorf("%s.keywords must be a CSV keyword list", prefix)
			}
			config.Keywords = keywords
		}
	default:
		return config, fmt.Errorf("%s.keywords must contain strings", prefix)
	}
	if filename := strings.TrimSpace(v.GetString(prefix + ".keywords_file")); filename != "" {
		keywords, err := sms.LoadKeywordsFromFile(filename)
		if err != nil {
			return config, fmt.Errorf("%s.keywords_file: %w", prefix, err)
		}
		config.Keywords = append(config.Keywords, keywords...)
	}
	normalized := config.Keywords[:0]
	for _, keyword := range config.Keywords {
		if keyword = strings.TrimSpace(keyword); keyword != "" {
			normalized = append(normalized, keyword)
		}
	}
	config.Keywords = normalized
	if _, err := sms.NewMatcher(config.Keywords); err != nil {
		return config, fmt.Errorf("%s.keywords: %w", prefix, err)
	}
	return config, nil
}
