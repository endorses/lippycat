package voip

import "github.com/spf13/viper"

// ResetSecurityConfigForTesting preserves the legacy test setup while keeping
// Viper entirely outside production VoIP code.
func ResetSecurityConfigForTesting() {
	cfg := DefaultConfig()
	cfg.Security = DefaultSecurityConfig()
	cfg.Security.SanitizeCallIDs = viper.GetBool("voip.security.sanitize_call_ids")
	cfg.Security.EnablePCAPEncryption = viper.GetBool("voip.security.enable_pcap_encryption")
	if value := viper.GetInt("voip.security.call_id_hash_length"); value > 0 {
		cfg.Security.CallIDHashLength = value
	}
	if value := viper.GetInt("voip.security.call_id_max_log_length"); value > 0 {
		cfg.Security.CallIDMaxLogLength = value
	}
	if viper.IsSet("voip.security.max_content_length") {
		cfg.Security.MaxContentLength = viper.GetInt("voip.security.max_content_length")
	}
	if value := viper.GetInt("voip.security.max_message_size"); value > 0 {
		cfg.Security.MaxMessageSize = value
	}
	SetConfig(cfg)
}
