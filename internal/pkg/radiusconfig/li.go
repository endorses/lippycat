//go:build li

package radiusconfig

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// LIConfig is the explicitly provisioned POI authorization domain. Ordinary
// capture configuration never implicitly authorizes this domain.
type LIConfig struct {
	Scope                radius.ScopeBinding
	MACProfile           string
	CorrelationStateFile string
	TransactionTimeout   time.Duration
}

var liOptions = []struct{ name, help string }{
	{"operator-scope", "Dedicated RADIUS LI operator domain"},
	{"profile-revision", "Verified operator mapping revision for RADIUS LI"},
	{"origin-node", "Restrict RADIUS LI to this authenticated origin node ID"},
	{"source", "Restrict RADIUS LI to this origin capture interface"},
	{"mac-profile", "Subscriber MAC convention: calling-station-id-uppercase-hyphen-v1"},
	{"correlation-state-file", "Durable RADIUS X2 correlation state (defaults to LI state path plus .radius-correlation)"},
}

func RegisterLIFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Duration("li-radius-transaction-timeout", 30*time.Second, "RADIUS X2 request correlation retention; must match capture timeout (1s–5m)")
	for _, option := range liOptions {
		cmd.PersistentFlags().String("li-radius-"+option.name, "", option.help)
	}
}

// ResolveLI binds the active command explicitly, avoiding cross-command Viper
// flag ownership in all builds. YAML and environment values remain byte exact.
func ResolveLI(cmd *cobra.Command, v *viper.Viper) (LIConfig, error) {
	var c LIConfig
	const timeoutKey = "li.radius.transaction_timeout"
	if err := v.BindPFlag(timeoutKey, cmd.PersistentFlags().Lookup("li-radius-transaction-timeout")); err != nil {
		return c, err
	}
	if err := v.BindEnv(timeoutKey, "LIPPYCAT_LI_RADIUS_TRANSACTION_TIMEOUT"); err != nil {
		return c, err
	}
	switch value := v.Get(timeoutKey).(type) {
	case time.Duration:
		c.TransactionTimeout = value
	case string:
		var err error
		c.TransactionTimeout, err = time.ParseDuration(value)
		if err != nil {
			return c, fmt.Errorf("invalid %s: %w", timeoutKey, err)
		}
	default:
		return c, fmt.Errorf("%s requires a duration with units", timeoutKey)
	}
	if c.TransactionTimeout < time.Second || c.TransactionTimeout > 5*time.Minute {
		return c, fmt.Errorf("RADIUS LI transaction timeout must be 1s–5m")
	}
	values := make(map[string]string, len(liOptions))
	for _, option := range liOptions {
		key := "li.radius." + strings.ReplaceAll(option.name, "-", "_")
		if err := v.BindPFlag(key, cmd.PersistentFlags().Lookup("li-radius-"+option.name)); err != nil {
			return c, err
		}
		if err := v.BindEnv(key, "LIPPYCAT_LI_RADIUS_"+strings.ToUpper(strings.ReplaceAll(option.name, "-", "_"))); err != nil {
			return c, err
		}
		value, ok := v.Get(key).(string)
		if !ok {
			return c, fmt.Errorf("%s must be a string", key)
		}
		if value != "" && strings.TrimSpace(value) == "" {
			return c, fmt.Errorf("%s must not be whitespace", key)
		}
		values[option.name] = value
	}
	c.Scope = radius.ScopeBinding{OperatorScope: values["operator-scope"], ProfileRevision: values["profile-revision"], OriginNodeID: values["origin-node"], SourceID: values["source"]}
	c.MACProfile, c.CorrelationStateFile = values["mac-profile"], values["correlation-state-file"]
	if c.MACProfile != "" && c.MACProfile != radius.MACProfileUppercaseHyphen {
		return c, fmt.Errorf("unsupported RADIUS LI MAC profile %q", c.MACProfile)
	}
	if c.Scope.OperatorScope != "" || c.Scope.ProfileRevision != "" || c.Scope.OriginNodeID != "" || c.Scope.SourceID != "" || c.MACProfile != "" {
		if c.Scope.OperatorScope == "" || c.Scope.ProfileRevision == "" {
			return c, fmt.Errorf("RADIUS LI requires both operator scope and profile revision")
		}
	}
	return c, nil
}
