//go:build !li

package tap

import "github.com/spf13/cobra"

// LIConfig holds all LI-related configuration.
// In non-LI builds, this is only used for the nil return type.
type LIConfig struct {
	Enabled       bool
	X1ListenAddr  string
	X1TLSCertFile string
	X1TLSKeyFile  string
	X1TLSCAFile   string
	ADMFEndpoint  string
	// ADMF client (X1 notifications) TLS
	ADMFTLSCertFile string
	ADMFTLSKeyFile  string
	ADMFTLSCAFile   string
	ADMFKeepalive   string
	// Delivery (X2/X3) TLS
	DeliveryTLSCertFile   string
	DeliveryTLSKeyFile    string
	DeliveryTLSCAFile     string
	DeliveryTLSPinnedCert []string
}

// RegisterLIFlags is a no-op in non-LI builds.
func RegisterLIFlags(cmd *cobra.Command) {}

// BindLIViperFlags is a no-op in non-LI builds.
func BindLIViperFlags(cmd *cobra.Command) {}

// GetLIConfig returns nil in non-LI builds.
func GetLIConfig() *LIConfig {
	return nil
}
