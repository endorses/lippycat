//go:build li

package process

import (
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
	cmd.Flags().BoolVar(&liEnabled, "li-enabled", false, "Enable ETSI LI (Lawful Interception) support (requires -tags li build)")
	cmd.Flags().StringVar(&liX1ListenAddr, "li-x1-listen", ":8443", "X1 administration interface listen address")
	cmd.Flags().StringVar(&liX1TLSCertFile, "li-x1-tls-cert", "", "Path to X1 server TLS certificate")
	cmd.Flags().StringVar(&liX1TLSKeyFile, "li-x1-tls-key", "", "Path to X1 server TLS key")
	cmd.Flags().StringVar(&liX1TLSCAFile, "li-x1-tls-ca", "", "Path to CA certificate for X1 client verification (mutual TLS)")
	cmd.Flags().StringVar(&liADMFEndpoint, "li-admf-endpoint", "", "ADMF endpoint for X1 notifications (e.g., https://admf:8443)")
	// LI ADMF client (X1 notifications) TLS flags - for connecting to ADMF
	cmd.Flags().StringVar(&liADMFTLSCertFile, "li-admf-tls-cert", "", "Path to client TLS certificate for ADMF notifications (mutual TLS)")
	cmd.Flags().StringVar(&liADMFTLSKeyFile, "li-admf-tls-key", "", "Path to client TLS key for ADMF notifications")
	cmd.Flags().StringVar(&liADMFTLSCAFile, "li-admf-tls-ca", "", "Path to CA certificate for verifying ADMF server")
	cmd.Flags().StringVar(&liADMFKeepalive, "li-admf-keepalive", "30s", "Keepalive interval for ADMF notifications (0 to disable)")
	// LI Delivery (X2/X3) TLS flags - mutual TLS is required for delivery
	cmd.Flags().StringVar(&liDeliveryTLSCertFile, "li-delivery-tls-cert", "", "Path to client TLS certificate for X2/X3 delivery (mutual TLS required)")
	cmd.Flags().StringVar(&liDeliveryTLSKeyFile, "li-delivery-tls-key", "", "Path to client TLS key for X2/X3 delivery")
	cmd.Flags().StringVar(&liDeliveryTLSCAFile, "li-delivery-tls-ca", "", "Path to CA certificate for verifying MDF servers")
	cmd.Flags().StringSliceVar(&liDeliveryTLSPinnedCert, "li-delivery-tls-pinned-cert", nil, "Pinned certificate fingerprints for MDF servers (SHA256, hex encoded, comma-separated)")
}

// BindLIViperFlags binds LI flags to viper for config file support.
func BindLIViperFlags(cmd *cobra.Command) {
	_ = viper.BindPFlag("processor.li.enabled", cmd.Flags().Lookup("li-enabled"))
	_ = viper.BindPFlag("processor.li.x1_listen_addr", cmd.Flags().Lookup("li-x1-listen"))
	_ = viper.BindPFlag("processor.li.x1_tls_cert", cmd.Flags().Lookup("li-x1-tls-cert"))
	_ = viper.BindPFlag("processor.li.x1_tls_key", cmd.Flags().Lookup("li-x1-tls-key"))
	_ = viper.BindPFlag("processor.li.x1_tls_ca", cmd.Flags().Lookup("li-x1-tls-ca"))
	_ = viper.BindPFlag("processor.li.admf_endpoint", cmd.Flags().Lookup("li-admf-endpoint"))
	// LI ADMF client (X1 notifications) viper bindings
	_ = viper.BindPFlag("processor.li.admf_tls_cert", cmd.Flags().Lookup("li-admf-tls-cert"))
	_ = viper.BindPFlag("processor.li.admf_tls_key", cmd.Flags().Lookup("li-admf-tls-key"))
	_ = viper.BindPFlag("processor.li.admf_tls_ca", cmd.Flags().Lookup("li-admf-tls-ca"))
	_ = viper.BindPFlag("processor.li.admf_keepalive", cmd.Flags().Lookup("li-admf-keepalive"))
	// LI Delivery (X2/X3) viper bindings
	_ = viper.BindPFlag("processor.li.delivery_tls_cert", cmd.Flags().Lookup("li-delivery-tls-cert"))
	_ = viper.BindPFlag("processor.li.delivery_tls_key", cmd.Flags().Lookup("li-delivery-tls-key"))
	_ = viper.BindPFlag("processor.li.delivery_tls_ca", cmd.Flags().Lookup("li-delivery-tls-ca"))
	_ = viper.BindPFlag("processor.li.delivery_tls_pinned_cert", cmd.Flags().Lookup("li-delivery-tls-pinned-cert"))
}

// GetLIConfig returns the LI configuration from flags and viper.
func GetLIConfig() *LIConfig {
	return &LIConfig{
		Enabled:               cmdutil.GetBoolConfig("processor.li.enabled", liEnabled),
		X1ListenAddr:          cmdutil.GetStringConfig("processor.li.x1_listen_addr", liX1ListenAddr),
		X1TLSCertFile:         cmdutil.GetStringConfig("processor.li.x1_tls_cert", liX1TLSCertFile),
		X1TLSKeyFile:          cmdutil.GetStringConfig("processor.li.x1_tls_key", liX1TLSKeyFile),
		X1TLSCAFile:           cmdutil.GetStringConfig("processor.li.x1_tls_ca", liX1TLSCAFile),
		ADMFEndpoint:          cmdutil.GetStringConfig("processor.li.admf_endpoint", liADMFEndpoint),
		ADMFTLSCertFile:       cmdutil.GetStringConfig("processor.li.admf_tls_cert", liADMFTLSCertFile),
		ADMFTLSKeyFile:        cmdutil.GetStringConfig("processor.li.admf_tls_key", liADMFTLSKeyFile),
		ADMFTLSCAFile:         cmdutil.GetStringConfig("processor.li.admf_tls_ca", liADMFTLSCAFile),
		ADMFKeepalive:         cmdutil.GetStringConfig("processor.li.admf_keepalive", liADMFKeepalive),
		DeliveryTLSCertFile:   cmdutil.GetStringConfig("processor.li.delivery_tls_cert", liDeliveryTLSCertFile),
		DeliveryTLSKeyFile:    cmdutil.GetStringConfig("processor.li.delivery_tls_key", liDeliveryTLSKeyFile),
		DeliveryTLSCAFile:     cmdutil.GetStringConfig("processor.li.delivery_tls_ca", liDeliveryTLSCAFile),
		DeliveryTLSPinnedCert: cmdutil.GetStringSliceConfig("processor.li.delivery_tls_pinned_cert", liDeliveryTLSPinnedCert),
	}
}
