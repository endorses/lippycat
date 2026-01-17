//go:build li

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// LI (Lawful Interception) flags - requires -tags li build
	liEnabled       bool
	liX1ListenAddr  string
	liX1TLSCertFile string
	liX1TLSKeyFile  string
	liX1TLSCAFile   string
	liADMFEndpoint  string
	// LI ADMF client (X1 notifications) TLS flags
	liADMFTLSCertFile string
	liADMFTLSKeyFile  string
	liADMFTLSCAFile   string
	liADMFKeepalive   string
	// LI Delivery (X2/X3) TLS flags
	liDeliveryTLSCertFile   string
	liDeliveryTLSKeyFile    string
	liDeliveryTLSCAFile     string
	liDeliveryTLSPinnedCert []string
)

// LIConfig holds all LI-related configuration.
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

// RegisterLIFlags adds LI-related flags to the command.
func RegisterLIFlags(cmd *cobra.Command) {
	// LI (Lawful Interception) flags - requires build with -tags li
	cmd.PersistentFlags().BoolVar(&liEnabled, "li-enabled", false, "Enable ETSI LI (Lawful Interception) support (requires -tags li build)")
	cmd.PersistentFlags().StringVar(&liX1ListenAddr, "li-x1-listen", ":8443", "X1 administration interface listen address")
	cmd.PersistentFlags().StringVar(&liX1TLSCertFile, "li-x1-tls-cert", "", "Path to X1 server TLS certificate")
	cmd.PersistentFlags().StringVar(&liX1TLSKeyFile, "li-x1-tls-key", "", "Path to X1 server TLS key")
	cmd.PersistentFlags().StringVar(&liX1TLSCAFile, "li-x1-tls-ca", "", "Path to CA certificate for X1 client verification (mutual TLS)")
	cmd.PersistentFlags().StringVar(&liADMFEndpoint, "li-admf-endpoint", "", "ADMF endpoint for X1 notifications (e.g., https://admf:8443)")
	// LI ADMF client (X1 notifications) TLS flags - for connecting to ADMF
	cmd.PersistentFlags().StringVar(&liADMFTLSCertFile, "li-admf-tls-cert", "", "Path to client TLS certificate for ADMF notifications (mutual TLS)")
	cmd.PersistentFlags().StringVar(&liADMFTLSKeyFile, "li-admf-tls-key", "", "Path to client TLS key for ADMF notifications")
	cmd.PersistentFlags().StringVar(&liADMFTLSCAFile, "li-admf-tls-ca", "", "Path to CA certificate for verifying ADMF server")
	cmd.PersistentFlags().StringVar(&liADMFKeepalive, "li-admf-keepalive", "30s", "Keepalive interval for ADMF notifications (0 to disable)")
	// LI Delivery (X2/X3) TLS flags - mutual TLS is required for delivery
	cmd.PersistentFlags().StringVar(&liDeliveryTLSCertFile, "li-delivery-tls-cert", "", "Path to client TLS certificate for X2/X3 delivery (mutual TLS required)")
	cmd.PersistentFlags().StringVar(&liDeliveryTLSKeyFile, "li-delivery-tls-key", "", "Path to client TLS key for X2/X3 delivery")
	cmd.PersistentFlags().StringVar(&liDeliveryTLSCAFile, "li-delivery-tls-ca", "", "Path to CA certificate for verifying MDF servers")
	cmd.PersistentFlags().StringSliceVar(&liDeliveryTLSPinnedCert, "li-delivery-tls-pinned-cert", nil, "Pinned certificate fingerprints for MDF servers (SHA256, hex encoded, comma-separated)")
}

// BindLIViperFlags binds LI flags to viper for config file support.
func BindLIViperFlags(cmd *cobra.Command) {
	_ = viper.BindPFlag("tap.li.enabled", cmd.PersistentFlags().Lookup("li-enabled"))
	_ = viper.BindPFlag("tap.li.x1_listen_addr", cmd.PersistentFlags().Lookup("li-x1-listen"))
	_ = viper.BindPFlag("tap.li.x1_tls_cert", cmd.PersistentFlags().Lookup("li-x1-tls-cert"))
	_ = viper.BindPFlag("tap.li.x1_tls_key", cmd.PersistentFlags().Lookup("li-x1-tls-key"))
	_ = viper.BindPFlag("tap.li.x1_tls_ca", cmd.PersistentFlags().Lookup("li-x1-tls-ca"))
	_ = viper.BindPFlag("tap.li.admf_endpoint", cmd.PersistentFlags().Lookup("li-admf-endpoint"))
	// LI ADMF client (X1 notifications) viper bindings
	_ = viper.BindPFlag("tap.li.admf_tls_cert", cmd.PersistentFlags().Lookup("li-admf-tls-cert"))
	_ = viper.BindPFlag("tap.li.admf_tls_key", cmd.PersistentFlags().Lookup("li-admf-tls-key"))
	_ = viper.BindPFlag("tap.li.admf_tls_ca", cmd.PersistentFlags().Lookup("li-admf-tls-ca"))
	_ = viper.BindPFlag("tap.li.admf_keepalive", cmd.PersistentFlags().Lookup("li-admf-keepalive"))
	// LI Delivery (X2/X3) viper bindings
	_ = viper.BindPFlag("tap.li.delivery_tls_cert", cmd.PersistentFlags().Lookup("li-delivery-tls-cert"))
	_ = viper.BindPFlag("tap.li.delivery_tls_key", cmd.PersistentFlags().Lookup("li-delivery-tls-key"))
	_ = viper.BindPFlag("tap.li.delivery_tls_ca", cmd.PersistentFlags().Lookup("li-delivery-tls-ca"))
	_ = viper.BindPFlag("tap.li.delivery_tls_pinned_cert", cmd.PersistentFlags().Lookup("li-delivery-tls-pinned-cert"))
}

// GetLIConfig returns the LI configuration from flags and viper.
func GetLIConfig() *LIConfig {
	return &LIConfig{
		Enabled:               cmdutil.GetBoolConfig("tap.li.enabled", liEnabled),
		X1ListenAddr:          cmdutil.GetStringConfig("tap.li.x1_listen_addr", liX1ListenAddr),
		X1TLSCertFile:         cmdutil.GetStringConfig("tap.li.x1_tls_cert", liX1TLSCertFile),
		X1TLSKeyFile:          cmdutil.GetStringConfig("tap.li.x1_tls_key", liX1TLSKeyFile),
		X1TLSCAFile:           cmdutil.GetStringConfig("tap.li.x1_tls_ca", liX1TLSCAFile),
		ADMFEndpoint:          cmdutil.GetStringConfig("tap.li.admf_endpoint", liADMFEndpoint),
		ADMFTLSCertFile:       cmdutil.GetStringConfig("tap.li.admf_tls_cert", liADMFTLSCertFile),
		ADMFTLSKeyFile:        cmdutil.GetStringConfig("tap.li.admf_tls_key", liADMFTLSKeyFile),
		ADMFTLSCAFile:         cmdutil.GetStringConfig("tap.li.admf_tls_ca", liADMFTLSCAFile),
		ADMFKeepalive:         cmdutil.GetStringConfig("tap.li.admf_keepalive", liADMFKeepalive),
		DeliveryTLSCertFile:   cmdutil.GetStringConfig("tap.li.delivery_tls_cert", liDeliveryTLSCertFile),
		DeliveryTLSKeyFile:    cmdutil.GetStringConfig("tap.li.delivery_tls_key", liDeliveryTLSKeyFile),
		DeliveryTLSCAFile:     cmdutil.GetStringConfig("tap.li.delivery_tls_ca", liDeliveryTLSCAFile),
		DeliveryTLSPinnedCert: cmdutil.GetStringSliceConfig("tap.li.delivery_tls_pinned_cert", liDeliveryTLSPinnedCert),
	}
}
