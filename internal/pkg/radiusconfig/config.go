// Package radiusconfig shares ordinary RADIUS command configuration across capture topologies.
package radiusconfig

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	Ports       []uint16
	Scope       radius.CaptureScope
	Correlation radius.CorrelatorConfig
	Matcher     radius.ObservationMatcher
}

// RegisterFlags binds the same radius YAML and environment namespace for every command.
// Binding happens again at execution so the active command wins in all-command builds.
func RegisterFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("radius-port", "1812,1813", "RADIUS UDP ports; 1812 and 1813 are always included")
	for _, item := range []struct{ name, value, help string }{
		{"username", "", "Exact UTF-8 User-Name (case and realm preserved)"},
		{"mac", "", "Exact subscriber Calling-Station-Id MAC"},
		{"mac-profile", "", "MAC convention: calling-station-id-uppercase-hyphen-v1"},
		{"line-profile", "", "Concrete line attribute: nas-port-id or agent-circuit-id"},
		{"line-id", "", "Exact resolved line value; inventory lookup is not supported"},
		{"operator-scope", "local", "Dedicated operator capture domain"},
		{"profile-revision", "unconfigured", "Operator mapping revision"},
		{"protocol-scope", "auth-accounting-udp", "Supported scope: auth-accounting-udp only"},
	} {
		f.String("radius-"+item.name, item.value, item.help)
	}
	f.StringArray("radius-attribute", nil, "Complete hex AVP; repeat for conjunctive criteria (types 1, 87, vendor 3561/type 1)")
	f.Duration("radius-transaction-timeout", 30*time.Second, "Transaction retention (1s–5m)")
	f.Duration("radius-quiet-guard", 30*time.Second, "State loss guard; must be at least transaction timeout")
	f.Duration("radius-cleanup-interval", time.Second, "Association cleanup interval")
	f.Int("radius-max-candidates", 65536, "Maximum retained request candidates (1–1048576)")
	f.Int("radius-max-per-key", 4, "Maximum competing requests per tuple (1–16)")
	f.Int("radius-max-suppression-keys", 65536, "Maximum suppression keys (1–1048576)")
	f.Int64("radius-candidate-bytes", 64<<20, "Candidate storage limit in bytes (1–1024 MiB)")
	f.Int64("radius-total-bytes", 96<<20, "Total association storage in bytes (2–2048 MiB; above candidate limit)")
}

func Resolve(cmd *cobra.Command, v *viper.Viper) (Config, error) {
	var c Config
	keys := []string{"port", "username", "mac", "mac-profile", "attribute", "line-profile", "line-id", "operator-scope", "profile-revision", "protocol-scope", "transaction-timeout", "quiet-guard", "cleanup-interval", "max-candidates", "max-per-key", "max-suppression-keys", "candidate-bytes", "total-bytes"}
	for _, name := range keys {
		key := strings.ReplaceAll(name, "-", "_")
		if name == "port" {
			key = "ports"
		}
		if err := v.BindPFlag("radius."+key, cmd.Flags().Lookup("radius-"+name)); err != nil {
			return c, err
		}
		if err := v.BindEnv("radius."+key, "LIPPYCAT_RADIUS_"+strings.ToUpper(key)); err != nil {
			return c, err
		}
	}
	// Reject coercions that could silently remove an identity or truncate a bound.
	for _, name := range []string{"username", "mac", "mac_profile", "line_profile", "line_id", "operator_scope", "profile_revision", "protocol_scope"} {
		value := v.Get("radius." + name)
		text, ok := value.(string)
		if !ok {
			return c, fmt.Errorf("radius.%s must be a string", name)
		}
		flagName := "radius-" + strings.ReplaceAll(name, "_", "-")
		if text == "" && (cmd.Flags().Changed(flagName) || v.InConfig("radius."+name)) {
			return c, fmt.Errorf("radius.%s must not be empty when supplied", name)
		}
	}
	for _, name := range []string{"max_candidates", "max_per_key", "max_suppression_keys", "candidate_bytes", "total_bytes"} {
		if _, err := strconv.ParseInt(fmt.Sprint(v.Get("radius."+name)), 10, 64); err != nil {
			return c, fmt.Errorf("radius.%s must be an integer", name)
		}
	}
	for _, name := range []string{"transaction_timeout", "quiet_guard", "cleanup_interval"} {
		switch value := v.Get("radius." + name).(type) {
		case time.Duration:
		case string:
			if _, err := time.ParseDuration(value); err != nil {
				return c, fmt.Errorf("radius.%s: %w", name, err)
			}
		default:
			return c, fmt.Errorf("radius.%s requires a duration with units", name)
		}
	}
	if v.GetString("radius.protocol_scope") != "auth-accounting-udp" {
		return c, fmt.Errorf("unsupported RADIUS protocol scope; only auth-accounting-udp is supported")
	}
	portText := v.GetString("radius.ports")
	if values, ok := v.Get("radius.ports").([]string); ok {
		portText = strings.Join(values, ",")
	}
	// YAML sequences and environment comma lists both map to the same port set.
	if values, ok := v.Get("radius.ports").([]interface{}); ok {
		var ss []string
		for _, value := range values {
			ss = append(ss, fmt.Sprint(value))
		}
		portText = strings.Join(ss, ",")
	}
	for _, token := range strings.Split(portText, ",") {
		p, err := strconv.ParseUint(strings.TrimSpace(token), 10, 16)
		if err != nil || p == 0 {
			return c, fmt.Errorf("invalid RADIUS port %q", token)
		}
		c.Ports = append(c.Ports, uint16(p))
	}
	c.Scope = radius.CaptureScope{OperatorScope: v.GetString("radius.operator_scope"), ProfileRevision: v.GetString("radius.profile_revision")}
	if strings.TrimSpace(c.Scope.OperatorScope) == "" || strings.TrimSpace(c.Scope.ProfileRevision) == "" {
		return c, fmt.Errorf("RADIUS operator scope and profile revision must be nonempty")
	}
	c.Correlation = radius.CorrelatorConfig{Lifetime: v.GetDuration("radius.transaction_timeout"), QuietGuard: v.GetDuration("radius.quiet_guard"), CleanupInterval: v.GetDuration("radius.cleanup_interval"), MaxCandidates: v.GetInt("radius.max_candidates"), MaxPerKey: v.GetInt("radius.max_per_key"), MaxSuppressionKeys: v.GetInt("radius.max_suppression_keys"), CandidateBytes: v.GetInt64("radius.candidate_bytes"), TotalBytes: v.GetInt64("radius.total_bytes")}
	if c.Correlation.Lifetime <= 0 || c.Correlation.QuietGuard <= 0 || c.Correlation.CleanupInterval <= 0 || c.Correlation.MaxCandidates <= 0 || c.Correlation.MaxPerKey <= 0 || c.Correlation.MaxSuppressionKeys <= 0 || c.Correlation.CandidateBytes <= 0 || c.Correlation.TotalBytes <= 0 {
		return c, fmt.Errorf("RADIUS transaction limits must be positive")
	}
	correlator, err := radius.NewCorrelator(c.Correlation)
	if err != nil {
		return c, err
	}
	correlator.Close()
	var criteria []radius.PredicateSpec
	if username := v.GetString("radius.username"); username != "" {
		criteria = append(criteria, radius.PredicateSpec{Kind: radius.PredicateUserName, Value: username})
	}
	mac, macProfile := v.GetString("radius.mac"), v.GetString("radius.mac_profile")
	if macProfile != "" && macProfile != radius.MACProfileUppercaseHyphen {
		return c, fmt.Errorf("unsupported RADIUS MAC profile %q", macProfile)
	}
	if mac != "" {
		criteria = append(criteria, radius.PredicateSpec{Kind: radius.PredicateMAC, Value: mac, MACProfile: macProfile})
	}
	attributes, err := attributeValues(v.Get("radius.attribute"))
	if err != nil {
		return c, err
	}
	if len(attributes) == 0 && (cmd.Flags().Changed("radius-attribute") || v.InConfig("radius.attribute")) {
		return c, fmt.Errorf("radius.attribute must not be empty when supplied")
	}
	for _, avp := range attributes {
		criteria = append(criteria, radius.PredicateSpec{Kind: radius.PredicateAttribute, Value: avp})
	}
	profile, line := v.GetString("radius.line_profile"), v.GetString("radius.line_id")
	if (profile == "") != (line == "") {
		return c, fmt.Errorf("RADIUS line profile and resolved line ID must be supplied together")
	}
	if profile != "" {
		var raw []byte
		switch profile {
		case "nas-port-id":
			if len(line) > 253 {
				return c, fmt.Errorf("RADIUS line ID exceeds 253 bytes")
			}
			raw = append([]byte{87, byte(len(line) + 2)}, []byte(line)...)
		case "agent-circuit-id":
			if len(line) > 63 {
				return c, fmt.Errorf("RADIUS circuit ID exceeds 63 bytes")
			}
			raw = append([]byte{26, byte(len(line) + 8), 0, 0, 13, 233, 1, byte(len(line) + 2)}, []byte(line)...)
		default:
			return c, fmt.Errorf("unsupported RADIUS line profile %q; inventory resolution belongs upstream", profile)
		}
		criteria = append(criteria, radius.PredicateSpec{Kind: radius.PredicateAttribute, Value: hex.EncodeToString(raw)})
	}
	for i := range criteria {
		criteria[i].FilterID = fmt.Sprintf("ordinary-radius-command-%d", i)
		criteria[i].FilterRevision = 1
		predicate, err := radius.CompilePredicate(criteria[i])
		if err != nil {
			return c, err
		}
		if predicate.Spec().TargetKind == "line" && (c.Scope.OperatorScope == "local" || c.Scope.ProfileRevision == "unconfigured") {
			return c, fmt.Errorf("RADIUS line criteria require explicit operator scope and profile revision")
		}
	}
	if len(criteria) > 0 {
		group, err := radius.CompileGroup(radius.GroupSpec{ID: "ordinary-radius-command", Scope: radius.ScopeBinding{OperatorScope: c.Scope.OperatorScope, ProfileRevision: c.Scope.ProfileRevision}, Criteria: criteria})
		if err != nil {
			return c, err
		}
		c.Matcher = &matcher{group: group}
	}
	return c, nil
}

func (c Config) BPF(base string) string {
	bpf := radius.CaptureBPF(c.Ports...)
	if base != "" {
		return "(" + base + ") and " + bpf
	}
	return bpf
}

type matcher struct{ group *radius.Group }

func (m *matcher) MatchRADIUSObservation(o *radius.Observation) (bool, []string, []radius.AttributionReference) {
	ref, ok, err := m.group.Match(o)
	if err != nil || !ok {
		return false, nil, nil
	}
	return true, []string{ref.CriterionGroupID}, []radius.AttributionReference{ref}
}
func (m *matcher) RADIUSEvidenceCurrent(ref radius.AttributionReference) bool {
	return m.group.CurrentReference(ref)
}

// Selected admits direct and uniquely inherited ordinary matches after correlation.
func Selected(m radius.ObservationMatcher, o *radius.Observation) bool {
	if m == nil {
		return true
	}
	if o == nil {
		return false
	}
	for _, refs := range [][]radius.AttributionReference{o.Direct, o.Inherited} {
		for _, ref := range refs {
			if m.RADIUSEvidenceCurrent(ref) {
				return true
			}
		}
	}
	return false
}

// Attribute environment values are comma-separated hex AVPs; YAML also accepts a list.
func attributeValues(value any) ([]string, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case []string:
		return value, nil
	case string:
		if value == "" {
			return nil, fmt.Errorf("radius.attribute must not be empty")
		}
		return strings.Split(value, ","), nil
	case []interface{}:
		result := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("radius.attribute entries must be hex strings")
			}
			result = append(result, text)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("radius.attribute requires a hex string or list of hex strings")
	}
}
