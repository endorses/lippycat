package failover

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func resolverFixture(t *testing.T, yaml string, args ...string) (*viper.Viper, *pflag.FlagSet) {
	t.Helper()
	v := viper.New()
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("processor", "", "legacy processor")
	require.NoError(t, v.BindPFlag("hunter.processor_addr", flags.Lookup("processor")))
	Register(flags, v, "hunter")
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
	require.NoError(t, flags.Parse(args))
	return v, flags
}

func TestResolveSelectorPrecedence(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		args []string
		want []Endpoint
		err  string
	}{
		{name: "optional absent", yaml: "{}"},
		{name: "legacy YAML", yaml: "hunter:\n  processor_addr: a:1", want: []Endpoint{{Address: "a:1"}}},
		{name: "list YAML", yaml: "hunter:\n  processors: [a:1, b:2]", want: []Endpoint{{Address: "a:1"}, {Address: "b:2"}}},
		{name: "CLI list replaces YAML scalar", yaml: "hunter:\n  processor_addr: a:1", args: []string{"--processors=b:2,c:3"}, want: []Endpoint{{Address: "b:2"}, {Address: "c:3"}}},
		{name: "CLI scalar replaces YAML list", yaml: "hunter:\n  processors: [a:1, b:2]", args: []string{"--processor=c:3"}, want: []Endpoint{{Address: "c:3"}}},
		{name: "CLI selector replaces conflicting YAML", yaml: "hunter:\n  processor_addr: a:1\n  processors: [b:2]", args: []string{"--processor=c:3"}, want: []Endpoint{{Address: "c:3"}}},
		{name: "same priority YAML conflict", yaml: "hunter:\n  processor_addr: a:1\n  processors: [b:2]", err: "both"},
		{name: "same priority CLI conflict", yaml: "{}", args: []string{"--processor=a:1", "--processors=b:2"}, err: "both"},
		{name: "empty list YAML", yaml: "hunter:\n  processors: []", err: "at least one"},
		{name: "empty list CLI", yaml: "{}", args: []string{"--processors="}, err: "at least one"},
		{name: "empty scalar YAML", yaml: "hunter:\n  processor_addr: ''", err: "non-empty"},
		{name: "empty scalar CLI", yaml: "hunter:\n  processors: [b:2]", args: []string{"--processor="}, err: "empty"},
		{name: "blank candidate", yaml: "hunter:\n  processors: [a:1, '']", err: "candidate 2"},
		{name: "structured endpoint", yaml: "hunter:\n  processors:\n    - address: 192.0.2.1:55555\n      tls_server_name: station.example", want: []Endpoint{{Address: "192.0.2.1:55555", TLSServerName: "station.example"}}},
		{name: "unsupported credentials", yaml: "hunter:\n  processors:\n    - address: a:1\n      tls_skip_verify: true", err: "candidate 1"},
		{name: "wrong scalar type", yaml: "hunter:\n  processor_addr: 123", err: "non-empty address string"},
		{name: "wrong list type", yaml: "hunter:\n  processors: a:1", err: "must be a list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, flags := resolverFixture(t, tt.yaml, tt.args...)
			got, config, err := Resolve(v, flags, "hunter", "hunter.processor_addr", "processor")
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, DefaultConfig(), config)
		})
	}
}

func TestResolveConfig(t *testing.T) {
	v, flags := resolverFixture(t, "hunter:\n  failover:\n    attempt_timeout: 3s\n    reconnect_attempts: 0\n    retry_initial: 2s\n    retry_max: 5s")
	_, got, err := Resolve(v, flags, "hunter", "hunter.processor_addr", "processor")
	require.NoError(t, err)
	require.Equal(t, Config{AttemptTimeout: 3 * time.Second, RetryInitial: 2 * time.Second, RetryMax: 5 * time.Second}, got)
	require.NoError(t, flags.Set("processor-attempt-timeout", "4s"))
	require.NoError(t, flags.Set("processor-reconnect-attempts", "2"))
	_, got, err = Resolve(v, flags, "hunter", "hunter.processor_addr", "processor")
	require.NoError(t, err)
	require.Equal(t, 4*time.Second, got.AttemptTimeout)
	require.Equal(t, 2, got.ReconnectAttempts)
	for _, setting := range []string{
		"attempt_timeout: 0s", "attempt_timeout: -1s", "attempt_timeout: invalid", "attempt_timeout: 123",
		"reconnect_attempts: -1", "reconnect_attempts: 1.5", "reconnect_attempts: invalid", "reconnect_attempts: true",
		"retry_initial: 0s", "retry_max: 0s", "retry_initial: 2m\n    retry_max: 1s",
	} {
		t.Run(setting, func(t *testing.T) {
			v, flags := resolverFixture(t, "hunter:\n  failover:\n    "+setting)
			_, _, err := Resolve(v, flags, "hunter", "hunter.processor_addr", "processor")
			require.Error(t, err)
		})
	}
}
