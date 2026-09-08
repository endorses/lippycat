//go:build (tap || all) && li

package tap

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/processor"
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
	liDeliveryTLSCertFile                   string
	liDeliveryTLSKeyFile                    string
	liDeliveryTLSCAFile                     string
	liDeliveryTLSPinnedCert                 []string
	liDeliveryQueueSize                     int
	liDeliveryX2QueueSize                   int
	liDeliveryX3QueueSize                   int
	liDeliveryX2QueueBytes                  int64
	liDeliveryX3QueueBytes                  int64
	liDeliveryX3MaxAge                      time.Duration
	liDeliveryMemoryBudgetBytes             int64
	liDeliveryX2SpoolDir                    string
	liDeliveryX2SpoolMaxBytes               int64
	liDeliveryX2SpoolKeyFile                string
	liDeliveryX2SpoolReplayPolicy           string
	liDeliveryX2SpoolReplayManifest         string
	liDeliveryX2SpoolExportManifest         string
	liDeliverySendTimeout                   time.Duration
	liDeliveryInitialBackoff                time.Duration
	liDeliveryMaxBackoff                    time.Duration
	liDeliveryKeepAliveIdle                 time.Duration
	liDeliveryKeepAliveInterval             time.Duration
	liDeliveryKeepAliveCount                int
	liDeliveryX2KeepaliveEnabled            bool
	liDeliveryX2KeepaliveTimeP1             time.Duration
	liDeliveryX2KeepaliveTimeP2             time.Duration
	liDeliveryX3KeepaliveEnabled            bool
	liDeliveryX3KeepaliveTimeP1             time.Duration
	liDeliveryX3KeepaliveTimeP2             time.Duration
	liDeliveryX2AcknowledgeInboundKeepalive bool
	liDeliveryX3AcknowledgeInboundKeepalive bool
	liDeliveryShutdownTimeout               time.Duration
	// LI ADMF state sync flags
	liADMFSyncOnStartup         bool
	liADMFSyncTimeout           time.Duration
	liADMFReconcileInterval     time.Duration
	liMetadataEventsEnabled     bool
	liMetadataDeliveryProfile   string
	liMetadataAllowFileMetadata bool
	liStateFile                 string
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
	DeliveryTLSCertFile                   string
	DeliveryTLSKeyFile                    string
	DeliveryTLSCAFile                     string
	DeliveryTLSPinnedCert                 []string
	DeliveryQueueSize                     int
	DeliveryX2QueueSize                   int
	DeliveryX3QueueSize                   int
	DeliveryX2QueueBytes                  int64
	DeliveryX3QueueBytes                  int64
	DeliveryX3MaxAge                      time.Duration
	DeliveryMemoryBudgetBytes             int64
	DeliveryX2SpoolDir                    string
	DeliveryX2SpoolMaxBytes               int64
	DeliveryX2SpoolKeyFile                string
	DeliveryX2SpoolReplayPolicy           string
	DeliveryX2SpoolReplayManifest         string
	DeliveryX2SpoolExportManifest         string
	DeliverySendTimeout                   time.Duration
	DeliveryInitialBackoff                time.Duration
	DeliveryMaxBackoff                    time.Duration
	DeliveryKeepAliveIdle                 time.Duration
	DeliveryKeepAliveInterval             time.Duration
	DeliveryKeepAliveCount                int
	DeliveryX2KeepaliveEnabled            bool
	DeliveryX2KeepaliveTimeP1             time.Duration
	DeliveryX2KeepaliveTimeP2             time.Duration
	DeliveryX3KeepaliveEnabled            bool
	DeliveryX3KeepaliveTimeP1             time.Duration
	DeliveryX3KeepaliveTimeP2             time.Duration
	DeliveryX2AcknowledgeInboundKeepalive bool
	DeliveryX3AcknowledgeInboundKeepalive bool
	DeliveryShutdownTimeout               time.Duration
	// ADMF state sync
	ADMFSyncOnStartup         bool
	ADMFSyncTimeout           time.Duration
	ADMFReconcileInterval     time.Duration
	MetadataEventsEnabled     bool
	MetadataDeliveryProfile   string
	MetadataAllowFileMetadata bool
	StateFile                 string
}

// RegisterLIFlags adds LI-related flags to the command.
func RegisterLIFlags(cmd *cobra.Command) {
	// LI (Lawful Interception) flags - requires build with -tags li
	cmd.PersistentFlags().BoolVar(&liEnabled, "li-enabled", false, "Enable ETSI LI (Lawful Interception) support (requires -tags li build)")
	cmd.PersistentFlags().StringVar(&liX1ListenAddr, "li-x1-listen", ":8443", "X1 administration interface listen address")
	cmd.PersistentFlags().StringVar(&liX1TLSCertFile, "li-x1-tls-cert", "", "Path to X1 server TLS certificate")
	cmd.PersistentFlags().StringVar(&liX1TLSKeyFile, "li-x1-tls-key", "", "Path to X1 server TLS key")
	cmd.PersistentFlags().StringVar(&liX1TLSCAFile, "li-x1-tls-ca", "", "Required path to CA certificate for X1 client verification (mutual TLS)")
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
	cmd.PersistentFlags().IntVar(&liDeliveryQueueSize, "li-delivery-queue-size", 10000, "Maximum queued X2/X3 PDUs per destination and interface")
	cmd.PersistentFlags().IntVar(&liDeliveryX2QueueSize, "li-delivery-x2-queue-size", 0, "Maximum X2 PDUs per destination (0 inherits li-delivery-queue-size)")
	cmd.PersistentFlags().IntVar(&liDeliveryX3QueueSize, "li-delivery-x3-queue-size", 0, "Maximum X3 PDUs per destination (0 inherits li-delivery-queue-size)")
	cmd.PersistentFlags().Int64Var(&liDeliveryX2QueueBytes, "li-delivery-x2-queue-bytes", 0, "Encoded X2 byte capacity per destination and interface (0 disables byte limit)")
	cmd.PersistentFlags().Int64Var(&liDeliveryX3QueueBytes, "li-delivery-x3-queue-bytes", 0, "Encoded X3 byte capacity per destination and interface (0 disables byte limit)")
	cmd.PersistentFlags().DurationVar(&liDeliveryX3MaxAge, "li-delivery-x3-max-age", 0, "Maximum local X3 residence including retries (0 disables expiry)")
	cmd.PersistentFlags().Int64Var(&liDeliveryMemoryBudgetBytes, "li-delivery-memory-budget-bytes", 0, "Overall reserved LI delivery memory budget in bytes (0 disables reservation validation)")
	cmd.PersistentFlags().StringVar(&liDeliveryX2SpoolDir, "li-delivery-x2-spool-dir", "", "Directory for encrypted X2 journal (empty disables persistence)")
	cmd.PersistentFlags().Int64Var(&liDeliveryX2SpoolMaxBytes, "li-delivery-x2-spool-max-bytes", 0, "Maximum X2 journal bytes including pending reservations")
	cmd.PersistentFlags().StringVar(&liDeliveryX2SpoolKeyFile, "li-delivery-x2-spool-key-file", "", "Path to private 32-byte raw AES key for X2 journal")
	cmd.PersistentFlags().StringVar(&liDeliveryX2SpoolReplayPolicy, "li-delivery-x2-spool-replay-policy", "hold", "Recovered X2 policy: hold for explicit authorization or purge")
	cmd.PersistentFlags().StringVar(&liDeliveryX2SpoolReplayManifest, "li-delivery-x2-spool-replay-manifest", "", "Private JSON manifest authorizing exact recovered X2 identities after ADMF startup sync")
	cmd.PersistentFlags().StringVar(&liDeliveryX2SpoolExportManifest, "li-delivery-x2-spool-export-manifest", "", "Export private JSON identity manifest of held X2 records at startup")
	cmd.PersistentFlags().DurationVar(&liDeliverySendTimeout, "li-delivery-send-timeout", 5*time.Second, "Timeout for each X2/X3 delivery write")
	cmd.PersistentFlags().DurationVar(&liDeliveryInitialBackoff, "li-delivery-reconnect-initial-backoff", 500*time.Millisecond, "Initial MDF reconnect backoff")
	cmd.PersistentFlags().DurationVar(&liDeliveryMaxBackoff, "li-delivery-reconnect-max-backoff", 5*time.Second, "Maximum MDF reconnect backoff")
	cmd.PersistentFlags().DurationVar(&liDeliveryKeepAliveIdle, "li-delivery-keepalive-idle", 15*time.Second, "Idle time before MDF TCP keepalive probes")
	cmd.PersistentFlags().DurationVar(&liDeliveryKeepAliveInterval, "li-delivery-keepalive-interval", 5*time.Second, "Interval between MDF TCP keepalive probes")
	cmd.PersistentFlags().IntVar(&liDeliveryKeepAliveCount, "li-delivery-keepalive-count", 3, "Failed MDF TCP keepalive probes before disconnect")
	cmd.PersistentFlags().BoolVar(&liDeliveryX2KeepaliveEnabled, "li-delivery-x2-keepalive", false, "Enable X2 keepalive; MDF must ACK the same sequence before TIME_P2 or X2 is disconnected")
	cmd.PersistentFlags().DurationVar(&liDeliveryX2KeepaliveTimeP1, "li-delivery-x2-time-p1", 60*time.Second, "X2 Keepalive interval (minimum 1s)")
	cmd.PersistentFlags().DurationVar(&liDeliveryX2KeepaliveTimeP2, "li-delivery-x2-time-p2", 180*time.Second, "X2 Keepalive acknowledgement timeout (minimum 1s)")
	cmd.PersistentFlags().BoolVar(&liDeliveryX3KeepaliveEnabled, "li-delivery-x3-keepalive", false, "Enable X3 keepalive; MDF must ACK the same sequence before TIME_P2 or X3 is disconnected")
	cmd.PersistentFlags().DurationVar(&liDeliveryX3KeepaliveTimeP1, "li-delivery-x3-time-p1", 60*time.Second, "X3 Keepalive interval (minimum 1s)")
	cmd.PersistentFlags().DurationVar(&liDeliveryX3KeepaliveTimeP2, "li-delivery-x3-time-p2", 180*time.Second, "X3 Keepalive acknowledgement timeout (minimum 1s)")
	cmd.PersistentFlags().BoolVar(&liDeliveryX2AcknowledgeInboundKeepalive, "li-delivery-x2-ack-inbound-keepalive", false, "ACK valid inbound X2 keepalives with the same sequence (disabled by default)")
	cmd.PersistentFlags().BoolVar(&liDeliveryX3AcknowledgeInboundKeepalive, "li-delivery-x3-ack-inbound-keepalive", false, "ACK valid inbound X3 keepalives with the same sequence (disabled by default)")
	cmd.PersistentFlags().DurationVar(&liDeliveryShutdownTimeout, "li-delivery-shutdown-timeout", 10*time.Second, "Maximum time to flush LI delivery queues during shutdown")
	// LI ADMF state sync flags
	cmd.PersistentFlags().BoolVar(&liADMFSyncOnStartup, "li-admf-sync-on-startup", true, "Query ADMF for task/destination state on startup")
	cmd.PersistentFlags().DurationVar(&liADMFSyncTimeout, "li-admf-sync-timeout", 30*time.Second, "Timeout for startup state sync")
	cmd.PersistentFlags().DurationVar(&liADMFReconcileInterval, "li-admf-reconcile-interval", 5*time.Minute, "Periodic ADMF reconciliation interval (0 = disabled; drift is not corrected while off)")
	cmd.PersistentFlags().BoolVar(&liMetadataEventsEnabled, "li-metadata-events", false, "Deliver authorized normalized protocol metadata over X2")
	cmd.PersistentFlags().StringVar(&liMetadataDeliveryProfile, "li-metadata-delivery-profile", "internet_metadata", "LI metadata delivery profile")
	cmd.PersistentFlags().BoolVar(&liMetadataAllowFileMetadata, "li-metadata-allow-file-metadata", false, "Allow file metadata (never file content) in the LI metadata profile")
	cmd.PersistentFlags().StringVar(&liStateFile, "li-state-file", "", "Path to atomic LI lifecycle state file (empty disables local persistence)")
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
	_ = viper.BindEnv("tap.li.delivery_x2_queue_bytes", "LIPPYCAT_TAP_LI_DELIVERY_X2_QUEUE_BYTES")
	_ = viper.BindEnv("tap.li.delivery_x3_queue_bytes", "LIPPYCAT_TAP_LI_DELIVERY_X3_QUEUE_BYTES")
	_ = viper.BindEnv("tap.li.delivery_x3_max_age", "LIPPYCAT_TAP_LI_DELIVERY_X3_MAX_AGE")
	_ = viper.BindEnv("tap.li.delivery_memory_budget_bytes", "LIPPYCAT_TAP_LI_DELIVERY_MEMORY_BUDGET_BYTES")
	_ = viper.BindEnv("tap.li.delivery_x2_spool_dir", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_DIR")
	_ = viper.BindEnv("tap.li.delivery_x2_spool_max_bytes", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_MAX_BYTES")
	_ = viper.BindEnv("tap.li.delivery_x2_spool_key_file", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_KEY_FILE")
	_ = viper.BindPFlag("tap.li.delivery_tls_cert", cmd.PersistentFlags().Lookup("li-delivery-tls-cert"))
	_ = viper.BindPFlag("tap.li.delivery_tls_key", cmd.PersistentFlags().Lookup("li-delivery-tls-key"))
	_ = viper.BindPFlag("tap.li.delivery_tls_ca", cmd.PersistentFlags().Lookup("li-delivery-tls-ca"))
	_ = viper.BindPFlag("tap.li.delivery_tls_pinned_cert", cmd.PersistentFlags().Lookup("li-delivery-tls-pinned-cert"))
	_ = viper.BindPFlag("tap.li.delivery_queue_size", cmd.PersistentFlags().Lookup("li-delivery-queue-size"))
	_ = viper.BindPFlag("tap.li.delivery_x2_queue_size", cmd.PersistentFlags().Lookup("li-delivery-x2-queue-size"))
	_ = viper.BindEnv("tap.li.delivery_x2_queue_size", "LIPPYCAT_TAP_LI_DELIVERY_X2_QUEUE_SIZE")
	_ = viper.BindPFlag("tap.li.delivery_x3_queue_size", cmd.PersistentFlags().Lookup("li-delivery-x3-queue-size"))
	_ = viper.BindEnv("tap.li.delivery_x3_queue_size", "LIPPYCAT_TAP_LI_DELIVERY_X3_QUEUE_SIZE")
	_ = viper.BindPFlag("tap.li.delivery_x2_queue_bytes", cmd.PersistentFlags().Lookup("li-delivery-x2-queue-bytes"))
	_ = viper.BindPFlag("tap.li.delivery_x3_queue_bytes", cmd.PersistentFlags().Lookup("li-delivery-x3-queue-bytes"))
	_ = viper.BindPFlag("tap.li.delivery_x3_max_age", cmd.PersistentFlags().Lookup("li-delivery-x3-max-age"))
	_ = viper.BindPFlag("tap.li.delivery_memory_budget_bytes", cmd.PersistentFlags().Lookup("li-delivery-memory-budget-bytes"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_dir", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-dir"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_max_bytes", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-max-bytes"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_key_file", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-key-file"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_replay_policy", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-replay-policy"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_replay_manifest", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-replay-manifest"))
	_ = viper.BindPFlag("tap.li.delivery_x2_spool_export_manifest", cmd.PersistentFlags().Lookup("li-delivery-x2-spool-export-manifest"))
	_ = viper.BindEnv("tap.li.delivery_x2_spool_export_manifest", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_EXPORT_MANIFEST")
	_ = viper.BindEnv("tap.li.delivery_x2_spool_replay_manifest", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_REPLAY_MANIFEST")
	_ = viper.BindEnv("tap.li.delivery_x2_spool_replay_policy", "LIPPYCAT_TAP_LI_DELIVERY_X2_SPOOL_REPLAY_POLICY")
	_ = viper.BindPFlag("tap.li.delivery_send_timeout", cmd.PersistentFlags().Lookup("li-delivery-send-timeout"))
	_ = viper.BindPFlag("tap.li.delivery_reconnect_initial_backoff", cmd.PersistentFlags().Lookup("li-delivery-reconnect-initial-backoff"))
	_ = viper.BindPFlag("tap.li.delivery_reconnect_max_backoff", cmd.PersistentFlags().Lookup("li-delivery-reconnect-max-backoff"))
	_ = viper.BindPFlag("tap.li.delivery_keepalive_idle", cmd.PersistentFlags().Lookup("li-delivery-keepalive-idle"))
	_ = viper.BindPFlag("tap.li.delivery_keepalive_interval", cmd.PersistentFlags().Lookup("li-delivery-keepalive-interval"))
	_ = viper.BindPFlag("tap.li.delivery_keepalive_count", cmd.PersistentFlags().Lookup("li-delivery-keepalive-count"))
	_ = viper.BindPFlag("tap.li.delivery_x2_keepalive", cmd.PersistentFlags().Lookup("li-delivery-x2-keepalive"))
	_ = viper.BindPFlag("tap.li.delivery_x2_time_p1", cmd.PersistentFlags().Lookup("li-delivery-x2-time-p1"))
	_ = viper.BindPFlag("tap.li.delivery_x2_time_p2", cmd.PersistentFlags().Lookup("li-delivery-x2-time-p2"))
	_ = viper.BindPFlag("tap.li.delivery_x3_keepalive", cmd.PersistentFlags().Lookup("li-delivery-x3-keepalive"))
	_ = viper.BindPFlag("tap.li.delivery_x3_time_p1", cmd.PersistentFlags().Lookup("li-delivery-x3-time-p1"))
	_ = viper.BindPFlag("tap.li.delivery_x3_time_p2", cmd.PersistentFlags().Lookup("li-delivery-x3-time-p2"))
	_ = viper.BindPFlag("tap.li.delivery_x2_ack_inbound_keepalive", cmd.PersistentFlags().Lookup("li-delivery-x2-ack-inbound-keepalive"))
	_ = viper.BindPFlag("tap.li.delivery_x3_ack_inbound_keepalive", cmd.PersistentFlags().Lookup("li-delivery-x3-ack-inbound-keepalive"))
	_ = viper.BindPFlag("tap.li.delivery_shutdown_timeout", cmd.PersistentFlags().Lookup("li-delivery-shutdown-timeout"))
	// LI ADMF state sync viper bindings
	_ = viper.BindPFlag("tap.li.admf_sync_on_startup", cmd.PersistentFlags().Lookup("li-admf-sync-on-startup"))
	_ = viper.BindPFlag("tap.li.admf_sync_timeout", cmd.PersistentFlags().Lookup("li-admf-sync-timeout"))
	_ = viper.BindPFlag("tap.li.admf_reconcile_interval", cmd.PersistentFlags().Lookup("li-admf-reconcile-interval"))
	_ = viper.BindPFlag("tap.li.metadata_events.enabled", cmd.PersistentFlags().Lookup("li-metadata-events"))
	_ = viper.BindPFlag("tap.li.metadata_events.delivery_profile", cmd.PersistentFlags().Lookup("li-metadata-delivery-profile"))
	_ = viper.BindPFlag("tap.li.metadata_events.allow_file_metadata", cmd.PersistentFlags().Lookup("li-metadata-allow-file-metadata"))
	_ = viper.BindPFlag("tap.li.state_file", cmd.PersistentFlags().Lookup("li-state-file"))
}

// GetLIConfig returns the LI configuration from flags and viper.
func GetLIConfig() *LIConfig {
	return &LIConfig{
		Enabled:                               cmdutil.GetBoolConfig("tap.li.enabled", liEnabled),
		X1ListenAddr:                          cmdutil.GetStringConfig("tap.li.x1_listen_addr", liX1ListenAddr),
		X1TLSCertFile:                         cmdutil.GetStringConfig("tap.li.x1_tls_cert", liX1TLSCertFile),
		X1TLSKeyFile:                          cmdutil.GetStringConfig("tap.li.x1_tls_key", liX1TLSKeyFile),
		X1TLSCAFile:                           cmdutil.GetStringConfig("tap.li.x1_tls_ca", liX1TLSCAFile),
		ADMFEndpoint:                          cmdutil.GetStringConfig("tap.li.admf_endpoint", liADMFEndpoint),
		ADMFTLSCertFile:                       cmdutil.GetStringConfig("tap.li.admf_tls_cert", liADMFTLSCertFile),
		ADMFTLSKeyFile:                        cmdutil.GetStringConfig("tap.li.admf_tls_key", liADMFTLSKeyFile),
		ADMFTLSCAFile:                         cmdutil.GetStringConfig("tap.li.admf_tls_ca", liADMFTLSCAFile),
		ADMFKeepalive:                         cmdutil.GetStringConfig("tap.li.admf_keepalive", liADMFKeepalive),
		DeliveryTLSCertFile:                   cmdutil.GetStringConfig("tap.li.delivery_tls_cert", liDeliveryTLSCertFile),
		DeliveryTLSKeyFile:                    cmdutil.GetStringConfig("tap.li.delivery_tls_key", liDeliveryTLSKeyFile),
		DeliveryTLSCAFile:                     cmdutil.GetStringConfig("tap.li.delivery_tls_ca", liDeliveryTLSCAFile),
		DeliveryTLSPinnedCert:                 cmdutil.GetStringSliceConfig("tap.li.delivery_tls_pinned_cert", liDeliveryTLSPinnedCert),
		DeliveryQueueSize:                     cmdutil.GetIntConfig("tap.li.delivery_queue_size", liDeliveryQueueSize),
		DeliveryX2QueueSize:                   viper.GetInt("tap.li.delivery_x2_queue_size"),
		DeliveryX3QueueSize:                   viper.GetInt("tap.li.delivery_x3_queue_size"),
		DeliveryX2QueueBytes:                  viper.GetInt64("tap.li.delivery_x2_queue_bytes"),
		DeliveryX3QueueBytes:                  viper.GetInt64("tap.li.delivery_x3_queue_bytes"),
		DeliveryX3MaxAge:                      viper.GetDuration("tap.li.delivery_x3_max_age"),
		DeliveryMemoryBudgetBytes:             viper.GetInt64("tap.li.delivery_memory_budget_bytes"),
		DeliveryX2SpoolDir:                    viper.GetString("tap.li.delivery_x2_spool_dir"),
		DeliveryX2SpoolMaxBytes:               viper.GetInt64("tap.li.delivery_x2_spool_max_bytes"),
		DeliveryX2SpoolKeyFile:                viper.GetString("tap.li.delivery_x2_spool_key_file"),
		DeliveryX2SpoolReplayPolicy:           viper.GetString("tap.li.delivery_x2_spool_replay_policy"),
		DeliveryX2SpoolReplayManifest:         viper.GetString("tap.li.delivery_x2_spool_replay_manifest"),
		DeliveryX2SpoolExportManifest:         viper.GetString("tap.li.delivery_x2_spool_export_manifest"),
		DeliverySendTimeout:                   viper.GetDuration("tap.li.delivery_send_timeout"),
		DeliveryInitialBackoff:                viper.GetDuration("tap.li.delivery_reconnect_initial_backoff"),
		DeliveryMaxBackoff:                    viper.GetDuration("tap.li.delivery_reconnect_max_backoff"),
		DeliveryKeepAliveIdle:                 viper.GetDuration("tap.li.delivery_keepalive_idle"),
		DeliveryKeepAliveInterval:             viper.GetDuration("tap.li.delivery_keepalive_interval"),
		DeliveryKeepAliveCount:                cmdutil.GetIntConfig("tap.li.delivery_keepalive_count", liDeliveryKeepAliveCount),
		DeliveryX2KeepaliveEnabled:            cmdutil.GetBoolConfig("tap.li.delivery_x2_keepalive", liDeliveryX2KeepaliveEnabled),
		DeliveryX2KeepaliveTimeP1:             viper.GetDuration("tap.li.delivery_x2_time_p1"),
		DeliveryX2KeepaliveTimeP2:             viper.GetDuration("tap.li.delivery_x2_time_p2"),
		DeliveryX3KeepaliveEnabled:            cmdutil.GetBoolConfig("tap.li.delivery_x3_keepalive", liDeliveryX3KeepaliveEnabled),
		DeliveryX3KeepaliveTimeP1:             viper.GetDuration("tap.li.delivery_x3_time_p1"),
		DeliveryX3KeepaliveTimeP2:             viper.GetDuration("tap.li.delivery_x3_time_p2"),
		DeliveryX2AcknowledgeInboundKeepalive: cmdutil.GetBoolConfig("tap.li.delivery_x2_ack_inbound_keepalive", liDeliveryX2AcknowledgeInboundKeepalive),
		DeliveryX3AcknowledgeInboundKeepalive: cmdutil.GetBoolConfig("tap.li.delivery_x3_ack_inbound_keepalive", liDeliveryX3AcknowledgeInboundKeepalive),
		DeliveryShutdownTimeout:               viper.GetDuration("tap.li.delivery_shutdown_timeout"),
		// ADMF state sync
		ADMFSyncOnStartup:         cmdutil.GetBoolConfig("tap.li.admf_sync_on_startup", liADMFSyncOnStartup),
		ADMFSyncTimeout:           viper.GetDuration("tap.li.admf_sync_timeout"),
		ADMFReconcileInterval:     viper.GetDuration("tap.li.admf_reconcile_interval"),
		MetadataEventsEnabled:     cmdutil.GetBoolConfig("tap.li.metadata_events.enabled", liMetadataEventsEnabled),
		MetadataDeliveryProfile:   cmdutil.GetStringConfig("tap.li.metadata_events.delivery_profile", liMetadataDeliveryProfile),
		MetadataAllowFileMetadata: cmdutil.GetBoolConfig("tap.li.metadata_events.allow_file_metadata", liMetadataAllowFileMetadata),
		StateFile:                 cmdutil.GetStringConfig("tap.li.state_file", liStateFile),
	}
}

func applyLIDeliveryConfig(config *processor.Config, liConfig *LIConfig) {
	config.LIMetadataEventsEnabled = liConfig.MetadataEventsEnabled
	config.LIMetadataDeliveryProfile = liConfig.MetadataDeliveryProfile
	config.LIMetadataAllowFileMetadata = liConfig.MetadataAllowFileMetadata
	config.LIStateFile = liConfig.StateFile
	config.LIDeliveryQueueSize = liConfig.DeliveryQueueSize
	config.LIDeliveryX2QueueSize = liConfig.DeliveryX2QueueSize
	config.LIDeliveryX3QueueSize = liConfig.DeliveryX3QueueSize
	config.LIDeliveryX2QueueBytes = liConfig.DeliveryX2QueueBytes
	config.LIDeliveryX3QueueBytes = liConfig.DeliveryX3QueueBytes
	config.LIDeliveryX3MaxAge = liConfig.DeliveryX3MaxAge
	config.LIDeliveryMemoryBudgetBytes = liConfig.DeliveryMemoryBudgetBytes
	config.LIDeliveryX2SpoolDir = liConfig.DeliveryX2SpoolDir
	config.LIDeliveryX2SpoolMaxBytes = liConfig.DeliveryX2SpoolMaxBytes
	config.LIDeliveryX2SpoolKeyFile = liConfig.DeliveryX2SpoolKeyFile
	config.LIDeliveryX2SpoolReplayPolicy = liConfig.DeliveryX2SpoolReplayPolicy
	config.LIDeliveryX2SpoolReplayManifest = liConfig.DeliveryX2SpoolReplayManifest
	config.LIDeliveryX2SpoolExportManifest = liConfig.DeliveryX2SpoolExportManifest
	config.LIDeliverySendTimeout = liConfig.DeliverySendTimeout
	config.LIDeliveryInitialBackoff = liConfig.DeliveryInitialBackoff
	config.LIDeliveryMaxBackoff = liConfig.DeliveryMaxBackoff
	config.LIDeliveryKeepAliveIdle = liConfig.DeliveryKeepAliveIdle
	config.LIDeliveryKeepAliveInterval = liConfig.DeliveryKeepAliveInterval
	config.LIDeliveryKeepAliveCount = liConfig.DeliveryKeepAliveCount
	config.LIDeliveryX2KeepaliveEnabled = liConfig.DeliveryX2KeepaliveEnabled
	config.LIDeliveryX2KeepaliveTimeP1 = liConfig.DeliveryX2KeepaliveTimeP1
	config.LIDeliveryX2KeepaliveTimeP2 = liConfig.DeliveryX2KeepaliveTimeP2
	config.LIDeliveryX3KeepaliveEnabled = liConfig.DeliveryX3KeepaliveEnabled
	config.LIDeliveryX3KeepaliveTimeP1 = liConfig.DeliveryX3KeepaliveTimeP1
	config.LIDeliveryX3KeepaliveTimeP2 = liConfig.DeliveryX3KeepaliveTimeP2
	config.LIDeliveryX2AcknowledgeInboundKeepalive = liConfig.DeliveryX2AcknowledgeInboundKeepalive
	config.LIDeliveryX3AcknowledgeInboundKeepalive = liConfig.DeliveryX3AcknowledgeInboundKeepalive
	config.LIDeliveryShutdownTimeout = liConfig.DeliveryShutdownTimeout
}
