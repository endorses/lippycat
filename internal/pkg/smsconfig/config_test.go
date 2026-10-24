package smsconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSMSConfigDefaultsAndExplicitKeywords(t *testing.T) {
	v := viper.New()
	cmd := &cobra.Command{Use: "voip"}
	require.NoError(t, RegisterFlags(cmd, v, "tap.voip.sms"))
	defaults, err := ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Empty(t, defaults.Keywords)
	require.Equal(t, 4<<20, defaults.Assembly.MaxBytes)
	require.Equal(t, 5*time.Minute, defaults.Assembly.Lifetime)
	filename := filepath.Join(t.TempDir(), "keywords.txt")
	require.NoError(t, os.WriteFile(filename, []byte("# comment\nworld\n\n"), 0600))
	require.NoError(t, cmd.Flags().Parse([]string{"--sms-keywords", "hello,€", "--sms-keywords-file", filename}))
	v.Set("hunter.voip.sms.keywords", []string{"unrelated-role"})
	v.Set("tap.voip.sms.max_bytes", 4096)
	configured, err := ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Equal(t, []string{"hello", "€", "world"}, configured.Keywords)
	require.Equal(t, 4096, configured.Assembly.MaxBytes)
}

func TestSMSConfigRejectsInvalidBudgetsAndFiles(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"max_assemblies", -1}, {"max_bytes", 0}, {"max_segments", 256}, {"max_pending_messages", "bad"}, {"max_pending_bytes", 1.5}, {"lifetime", "bad"}, {"lifetime", "-1s"}, {"lifetime", true}, {"keywords_file", "/nonexistent/sms-keywords"}, {"keywords", []string{string([]byte{0xff})}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			v := viper.New()
			v.Set("hunter.voip.sms."+tc.key, tc.value)
			_, err := ReadConfig(v, "hunter.voip.sms")
			require.Error(t, err)
		})
	}
}

func TestSMSConfigEnvironmentPrecedenceAndEmptyFiltering(t *testing.T) {
	v := viper.New()
	v.SetEnvPrefix("LIPPYCAT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetConfigType("yaml")
	cmd := &cobra.Command{Use: "voip"}
	require.NoError(t, RegisterFlags(cmd, v, "tap.voip.sms"))
	require.NoError(t, v.ReadConfig(strings.NewReader("tap:\n  voip:\n    sms:\n      keywords: [yaml]\n      max_bytes: 2048\n")))
	t.Setenv("LIPPYCAT_TAP_VOIP_SMS_KEYWORDS", "env one,env two")
	t.Setenv("LIPPYCAT_TAP_VOIP_SMS_MAX_BYTES", "8192")
	fromEnv, err := ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Equal(t, []string{"env one", "env two"}, fromEnv.Keywords)
	require.Equal(t, 8192, fromEnv.Assembly.MaxBytes)
	require.NoError(t, cmd.Flags().Parse([]string{"--sms-keywords", "cli"}))
	fromCLI, err := ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Equal(t, []string{"cli"}, fromCLI.Keywords)
	require.NoError(t, cmd.Flags().Lookup("sms-keywords").Value.(interface{ Replace([]string) error }).Replace(nil))
	disabled, err := ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Empty(t, disabled.Keywords)
	v.Set("tap.voip.sms.keywords", []string{" ", "\t"})
	disabled, err = ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Empty(t, disabled.Keywords)
	filename := filepath.Join(t.TempDir(), "empty.txt")
	require.NoError(t, os.WriteFile(filename, []byte("# only comments\n\n"), 0600))
	v.Set("tap.voip.sms.keywords_file", filename)
	disabled, err = ReadConfig(v, "tap.voip.sms")
	require.NoError(t, err)
	require.Empty(t, disabled.Keywords)
}
