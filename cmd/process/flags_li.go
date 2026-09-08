//go:build (processor || all) && li

package process

import (
	"time"

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
	cmd.Flags().BoolVar(&liEnabled, "li-enabled", false, "Enable ETSI LI (Lawful Interception) support (requires -tags li build)")
	cmd.Flags().StringVar(&liX1ListenAddr, "li-x1-listen", ":8443", "X1 administration interface listen address")
	cmd.Flags().StringVar(&liX1TLSCertFile, "li-x1-tls-cert", "", "Path to X1 server TLS certificate")
	cmd.Flags().StringVar(&liX1TLSKeyFile, "li-x1-tls-key", "", "Path to X1 server TLS key")
	cmd.Flags().StringVar(&liX1TLSCAFile, "li-x1-tls-ca", "", "Required path to CA certificate for X1 client verification (mutual TLS)")
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
	cmd.Flags().IntVar(&liDeliveryQueueSize, "li-delivery-queue-size", 10000, "Maximum queued X2/X3 PDUs per destination and interface")
	cmd.Flags().IntVar(&liDeliveryX2QueueSize, "li-delivery-x2-queue-size", 0, "Maximum X2 PDUs per destination (0 inherits li-delivery-queue-size)")
	cmd.Flags().IntVar(&liDeliveryX3QueueSize, "li-delivery-x3-queue-size", 0, "Maximum X3 PDUs per destination (0 inherits li-delivery-queue-size)")
	cmd.Flags().Int64Var(&liDeliveryX2QueueBytes, "li-delivery-x2-queue-bytes", 0, "Encoded X2 byte capacity per destination and interface (0 disables byte limit)")
	cmd.Flags().Int64Var(&liDeliveryX3QueueBytes, "li-delivery-x3-queue-bytes", 0, "Encoded X3 byte capacity per destination and interface (0 disables byte limit)")
	cmd.Flags().DurationVar(&liDeliveryX3MaxAge, "li-delivery-x3-max-age", 0, "Maximum local X3 residence including retries (0 disables expiry)")
	cmd.Flags().Int64Var(&liDeliveryMemoryBudgetBytes, "li-delivery-memory-budget-bytes", 0, "Overall reserved LI delivery memory budget in bytes (0 disables reservation validation)")
	cmd.Flags().StringVar(&liDeliveryX2SpoolDir, "li-delivery-x2-spool-dir", "", "Directory for encrypted X2 journal (empty disables persistence)")
	cmd.Flags().Int64Var(&liDeliveryX2SpoolMaxBytes, "li-delivery-x2-spool-max-bytes", 0, "Maximum X2 journal bytes including pending reservations")
	cmd.Flags().StringVar(&liDeliveryX2SpoolKeyFile, "li-delivery-x2-spool-key-file", "", "Path to private 32-byte raw AES key for X2 journal")
	cmd.Flags().StringVar(&liDeliveryX2SpoolReplayPolicy, "li-delivery-x2-spool-replay-policy", "hold", "Recovered X2 policy: hold for explicit authorization or purge")
	cmd.Flags().StringVar(&liDeliveryX2SpoolReplayManifest, "li-delivery-x2-spool-replay-manifest", "", "Private JSON manifest authorizing exact recovered X2 identities after ADMF startup sync")
	cmd.Flags().StringVar(&liDeliveryX2SpoolExportManifest, "li-delivery-x2-spool-export-manifest", "", "Export private JSON identity manifest of held X2 records at startup")
	cmd.Flags().DurationVar(&liDeliverySendTimeout, "li-delivery-send-timeout", 5*time.Second, "Timeout for each X2/X3 delivery write")
	cmd.Flags().DurationVar(&liDeliveryInitialBackoff, "li-delivery-reconnect-initial-backoff", 500*time.Millisecond, "Initial MDF reconnect backoff")
	cmd.Flags().DurationVar(&liDeliveryMaxBackoff, "li-delivery-reconnect-max-backoff", 5*time.Second, "Maximum MDF reconnect backoff")
	cmd.Flags().DurationVar(&liDeliveryKeepAliveIdle, "li-delivery-keepalive-idle", 15*time.Second, "Idle time before MDF TCP keepalive probes")
	cmd.Flags().DurationVar(&liDeliveryKeepAliveInterval, "li-delivery-keepalive-interval", 5*time.Second, "Interval between MDF TCP keepalive probes")
	cmd.Flags().IntVar(&liDeliveryKeepAliveCount, "li-delivery-keepalive-count", 3, "Failed MDF TCP keepalive probes before disconnect")
	cmd.Flags().BoolVar(&liDeliveryX2KeepaliveEnabled, "li-delivery-x2-keepalive", false, "Enable X2 keepalive; MDF must ACK the same sequence before TIME_P2 or X2 is disconnected")
	cmd.Flags().DurationVar(&liDeliveryX2KeepaliveTimeP1, "li-delivery-x2-time-p1", 60*time.Second, "X2 Keepalive interval (minimum 1s)")
	cmd.Flags().DurationVar(&liDeliveryX2KeepaliveTimeP2, "li-delivery-x2-time-p2", 180*time.Second, "X2 Keepalive acknowledgement timeout (minimum 1s)")
	cmd.Flags().BoolVar(&liDeliveryX3KeepaliveEnabled, "li-delivery-x3-keepalive", false, "Enable X3 keepalive; MDF must ACK the same sequence before TIME_P2 or X3 is disconnected")
	cmd.Flags().DurationVar(&liDeliveryX3KeepaliveTimeP1, "li-delivery-x3-time-p1", 60*time.Second, "X3 Keepalive interval (minimum 1s)")
	cmd.Flags().DurationVar(&liDeliveryX3KeepaliveTimeP2, "li-delivery-x3-time-p2", 180*time.Second, "X3 Keepalive acknowledgement timeout (minimum 1s)")
	cmd.Flags().BoolVar(&liDeliveryX2AcknowledgeInboundKeepalive, "li-delivery-x2-ack-inbound-keepalive", false, "ACK valid inbound X2 keepalives with the same sequence (disabled by default)")
	cmd.Flags().BoolVar(&liDeliveryX3AcknowledgeInboundKeepalive, "li-delivery-x3-ack-inbound-keepalive", false, "ACK valid inbound X3 keepalives with the same sequence (disabled by default)")
	cmd.Flags().DurationVar(&liDeliveryShutdownTimeout, "li-delivery-shutdown-timeout", 10*time.Second, "Maximum time to flush LI delivery queues during shutdown")
	// LI ADMF state sync flags
	cmd.Flags().BoolVar(&liADMFSyncOnStartup, "li-admf-sync-on-startup", true, "Query ADMF for task/destination state on startup")
	cmd.Flags().DurationVar(&liADMFSyncTimeout, "li-admf-sync-timeout", 30*time.Second, "Timeout for startup state sync")
	cmd.Flags().DurationVar(&liADMFReconcileInterval, "li-admf-reconcile-interval", 5*time.Minute, "Periodic ADMF reconciliation interval (0 = disabled; drift is not corrected while off)")
	cmd.Flags().BoolVar(&liMetadataEventsEnabled, "li-metadata-events", false, "Deliver authorized normalized protocol metadata over X2")
	cmd.Flags().StringVar(&liMetadataDeliveryProfile, "li-metadata-delivery-profile", "internet_metadata", "LI metadata delivery profile")
	cmd.Flags().BoolVar(&liMetadataAllowFileMetadata, "li-metadata-allow-file-metadata", false, "Allow file metadata (never file content) in the LI metadata profile")
	cmd.Flags().StringVar(&liStateFile, "li-state-file", "", "Path to atomic LI lifecycle state file (empty disables local persistence)")
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
	_ = viper.BindEnv("processor.li.delivery_x2_queue_bytes", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_QUEUE_BYTES")
	_ = viper.BindEnv("processor.li.delivery_x3_queue_bytes", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X3_QUEUE_BYTES")
	_ = viper.BindEnv("processor.li.delivery_x3_max_age", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X3_MAX_AGE")
	_ = viper.BindEnv("processor.li.delivery_memory_budget_bytes", "LIPPYCAT_PROCESSOR_LI_DELIVERY_MEMORY_BUDGET_BYTES")
	_ = viper.BindEnv("processor.li.delivery_x2_spool_dir", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_DIR")
	_ = viper.BindEnv("processor.li.delivery_x2_spool_max_bytes", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_MAX_BYTES")
	_ = viper.BindEnv("processor.li.delivery_x2_spool_key_file", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_KEY_FILE")
	_ = viper.BindPFlag("processor.li.delivery_tls_cert", cmd.Flags().Lookup("li-delivery-tls-cert"))
	_ = viper.BindPFlag("processor.li.delivery_tls_key", cmd.Flags().Lookup("li-delivery-tls-key"))
	_ = viper.BindPFlag("processor.li.delivery_tls_ca", cmd.Flags().Lookup("li-delivery-tls-ca"))
	_ = viper.BindPFlag("processor.li.delivery_tls_pinned_cert", cmd.Flags().Lookup("li-delivery-tls-pinned-cert"))
	_ = viper.BindPFlag("processor.li.delivery_queue_size", cmd.Flags().Lookup("li-delivery-queue-size"))
	_ = viper.BindPFlag("processor.li.delivery_x2_queue_size", cmd.Flags().Lookup("li-delivery-x2-queue-size"))
	_ = viper.BindEnv("processor.li.delivery_x2_queue_size", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_QUEUE_SIZE")
	_ = viper.BindPFlag("processor.li.delivery_x3_queue_size", cmd.Flags().Lookup("li-delivery-x3-queue-size"))
	_ = viper.BindEnv("processor.li.delivery_x3_queue_size", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X3_QUEUE_SIZE")
	_ = viper.BindPFlag("processor.li.delivery_x2_queue_bytes", cmd.Flags().Lookup("li-delivery-x2-queue-bytes"))
	_ = viper.BindPFlag("processor.li.delivery_x3_queue_bytes", cmd.Flags().Lookup("li-delivery-x3-queue-bytes"))
	_ = viper.BindPFlag("processor.li.delivery_x3_max_age", cmd.Flags().Lookup("li-delivery-x3-max-age"))
	_ = viper.BindPFlag("processor.li.delivery_memory_budget_bytes", cmd.Flags().Lookup("li-delivery-memory-budget-bytes"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_dir", cmd.Flags().Lookup("li-delivery-x2-spool-dir"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_max_bytes", cmd.Flags().Lookup("li-delivery-x2-spool-max-bytes"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_key_file", cmd.Flags().Lookup("li-delivery-x2-spool-key-file"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_replay_policy", cmd.Flags().Lookup("li-delivery-x2-spool-replay-policy"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_replay_manifest", cmd.Flags().Lookup("li-delivery-x2-spool-replay-manifest"))
	_ = viper.BindPFlag("processor.li.delivery_x2_spool_export_manifest", cmd.Flags().Lookup("li-delivery-x2-spool-export-manifest"))
	_ = viper.BindEnv("processor.li.delivery_x2_spool_export_manifest", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_EXPORT_MANIFEST")
	_ = viper.BindEnv("processor.li.delivery_x2_spool_replay_manifest", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_REPLAY_MANIFEST")
	_ = viper.BindEnv("processor.li.delivery_x2_spool_replay_policy", "LIPPYCAT_PROCESSOR_LI_DELIVERY_X2_SPOOL_REPLAY_POLICY")
	_ = viper.BindPFlag("processor.li.delivery_send_timeout", cmd.Flags().Lookup("li-delivery-send-timeout"))
	_ = viper.BindPFlag("processor.li.delivery_reconnect_initial_backoff", cmd.Flags().Lookup("li-delivery-reconnect-initial-backoff"))
	_ = viper.BindPFlag("processor.li.delivery_reconnect_max_backoff", cmd.Flags().Lookup("li-delivery-reconnect-max-backoff"))
	_ = viper.BindPFlag("processor.li.delivery_keepalive_idle", cmd.Flags().Lookup("li-delivery-keepalive-idle"))
	_ = viper.BindPFlag("processor.li.delivery_keepalive_interval", cmd.Flags().Lookup("li-delivery-keepalive-interval"))
	_ = viper.BindPFlag("processor.li.delivery_keepalive_count", cmd.Flags().Lookup("li-delivery-keepalive-count"))
	_ = viper.BindPFlag("processor.li.delivery_x2_keepalive", cmd.Flags().Lookup("li-delivery-x2-keepalive"))
	_ = viper.BindPFlag("processor.li.delivery_x2_time_p1", cmd.Flags().Lookup("li-delivery-x2-time-p1"))
	_ = viper.BindPFlag("processor.li.delivery_x2_time_p2", cmd.Flags().Lookup("li-delivery-x2-time-p2"))
	_ = viper.BindPFlag("processor.li.delivery_x3_keepalive", cmd.Flags().Lookup("li-delivery-x3-keepalive"))
	_ = viper.BindPFlag("processor.li.delivery_x3_time_p1", cmd.Flags().Lookup("li-delivery-x3-time-p1"))
	_ = viper.BindPFlag("processor.li.delivery_x3_time_p2", cmd.Flags().Lookup("li-delivery-x3-time-p2"))
	_ = viper.BindPFlag("processor.li.delivery_x2_ack_inbound_keepalive", cmd.Flags().Lookup("li-delivery-x2-ack-inbound-keepalive"))
	_ = viper.BindPFlag("processor.li.delivery_x3_ack_inbound_keepalive", cmd.Flags().Lookup("li-delivery-x3-ack-inbound-keepalive"))
	_ = viper.BindPFlag("processor.li.delivery_shutdown_timeout", cmd.Flags().Lookup("li-delivery-shutdown-timeout"))
	// LI ADMF state sync viper bindings
	_ = viper.BindPFlag("processor.li.admf_sync_on_startup", cmd.Flags().Lookup("li-admf-sync-on-startup"))
	_ = viper.BindPFlag("processor.li.admf_sync_timeout", cmd.Flags().Lookup("li-admf-sync-timeout"))
	_ = viper.BindPFlag("processor.li.admf_reconcile_interval", cmd.Flags().Lookup("li-admf-reconcile-interval"))
	_ = viper.BindPFlag("processor.li.metadata_events.enabled", cmd.Flags().Lookup("li-metadata-events"))
	_ = viper.BindPFlag("processor.li.metadata_events.delivery_profile", cmd.Flags().Lookup("li-metadata-delivery-profile"))
	_ = viper.BindPFlag("processor.li.metadata_events.allow_file_metadata", cmd.Flags().Lookup("li-metadata-allow-file-metadata"))
	_ = viper.BindPFlag("processor.li.state_file", cmd.Flags().Lookup("li-state-file"))
}

// GetLIConfig returns the LI configuration from flags and viper.
func GetLIConfig() *LIConfig {
	return &LIConfig{
		Enabled:                               cmdutil.GetBoolConfig("processor.li.enabled", liEnabled),
		X1ListenAddr:                          cmdutil.GetStringConfig("processor.li.x1_listen_addr", liX1ListenAddr),
		X1TLSCertFile:                         cmdutil.GetStringConfig("processor.li.x1_tls_cert", liX1TLSCertFile),
		X1TLSKeyFile:                          cmdutil.GetStringConfig("processor.li.x1_tls_key", liX1TLSKeyFile),
		X1TLSCAFile:                           cmdutil.GetStringConfig("processor.li.x1_tls_ca", liX1TLSCAFile),
		ADMFEndpoint:                          cmdutil.GetStringConfig("processor.li.admf_endpoint", liADMFEndpoint),
		ADMFTLSCertFile:                       cmdutil.GetStringConfig("processor.li.admf_tls_cert", liADMFTLSCertFile),
		ADMFTLSKeyFile:                        cmdutil.GetStringConfig("processor.li.admf_tls_key", liADMFTLSKeyFile),
		ADMFTLSCAFile:                         cmdutil.GetStringConfig("processor.li.admf_tls_ca", liADMFTLSCAFile),
		ADMFKeepalive:                         cmdutil.GetStringConfig("processor.li.admf_keepalive", liADMFKeepalive),
		DeliveryTLSCertFile:                   cmdutil.GetStringConfig("processor.li.delivery_tls_cert", liDeliveryTLSCertFile),
		DeliveryTLSKeyFile:                    cmdutil.GetStringConfig("processor.li.delivery_tls_key", liDeliveryTLSKeyFile),
		DeliveryTLSCAFile:                     cmdutil.GetStringConfig("processor.li.delivery_tls_ca", liDeliveryTLSCAFile),
		DeliveryTLSPinnedCert:                 cmdutil.GetStringSliceConfig("processor.li.delivery_tls_pinned_cert", liDeliveryTLSPinnedCert),
		DeliveryQueueSize:                     cmdutil.GetIntConfig("processor.li.delivery_queue_size", liDeliveryQueueSize),
		DeliveryX2QueueSize:                   viper.GetInt("processor.li.delivery_x2_queue_size"),
		DeliveryX3QueueSize:                   viper.GetInt("processor.li.delivery_x3_queue_size"),
		DeliveryX2QueueBytes:                  viper.GetInt64("processor.li.delivery_x2_queue_bytes"),
		DeliveryX3QueueBytes:                  viper.GetInt64("processor.li.delivery_x3_queue_bytes"),
		DeliveryX3MaxAge:                      viper.GetDuration("processor.li.delivery_x3_max_age"),
		DeliveryMemoryBudgetBytes:             viper.GetInt64("processor.li.delivery_memory_budget_bytes"),
		DeliveryX2SpoolDir:                    viper.GetString("processor.li.delivery_x2_spool_dir"),
		DeliveryX2SpoolMaxBytes:               viper.GetInt64("processor.li.delivery_x2_spool_max_bytes"),
		DeliveryX2SpoolKeyFile:                viper.GetString("processor.li.delivery_x2_spool_key_file"),
		DeliveryX2SpoolReplayPolicy:           viper.GetString("processor.li.delivery_x2_spool_replay_policy"),
		DeliveryX2SpoolReplayManifest:         viper.GetString("processor.li.delivery_x2_spool_replay_manifest"),
		DeliveryX2SpoolExportManifest:         viper.GetString("processor.li.delivery_x2_spool_export_manifest"),
		DeliverySendTimeout:                   viper.GetDuration("processor.li.delivery_send_timeout"),
		DeliveryInitialBackoff:                viper.GetDuration("processor.li.delivery_reconnect_initial_backoff"),
		DeliveryMaxBackoff:                    viper.GetDuration("processor.li.delivery_reconnect_max_backoff"),
		DeliveryKeepAliveIdle:                 viper.GetDuration("processor.li.delivery_keepalive_idle"),
		DeliveryKeepAliveInterval:             viper.GetDuration("processor.li.delivery_keepalive_interval"),
		DeliveryKeepAliveCount:                cmdutil.GetIntConfig("processor.li.delivery_keepalive_count", liDeliveryKeepAliveCount),
		DeliveryX2KeepaliveEnabled:            cmdutil.GetBoolConfig("processor.li.delivery_x2_keepalive", liDeliveryX2KeepaliveEnabled),
		DeliveryX2KeepaliveTimeP1:             viper.GetDuration("processor.li.delivery_x2_time_p1"),
		DeliveryX2KeepaliveTimeP2:             viper.GetDuration("processor.li.delivery_x2_time_p2"),
		DeliveryX3KeepaliveEnabled:            cmdutil.GetBoolConfig("processor.li.delivery_x3_keepalive", liDeliveryX3KeepaliveEnabled),
		DeliveryX3KeepaliveTimeP1:             viper.GetDuration("processor.li.delivery_x3_time_p1"),
		DeliveryX3KeepaliveTimeP2:             viper.GetDuration("processor.li.delivery_x3_time_p2"),
		DeliveryX2AcknowledgeInboundKeepalive: cmdutil.GetBoolConfig("processor.li.delivery_x2_ack_inbound_keepalive", liDeliveryX2AcknowledgeInboundKeepalive),
		DeliveryX3AcknowledgeInboundKeepalive: cmdutil.GetBoolConfig("processor.li.delivery_x3_ack_inbound_keepalive", liDeliveryX3AcknowledgeInboundKeepalive),
		DeliveryShutdownTimeout:               viper.GetDuration("processor.li.delivery_shutdown_timeout"),
		// ADMF state sync
		ADMFSyncOnStartup:         cmdutil.GetBoolConfig("processor.li.admf_sync_on_startup", liADMFSyncOnStartup),
		ADMFSyncTimeout:           viper.GetDuration("processor.li.admf_sync_timeout"),
		ADMFReconcileInterval:     viper.GetDuration("processor.li.admf_reconcile_interval"),
		MetadataEventsEnabled:     cmdutil.GetBoolConfig("processor.li.metadata_events.enabled", liMetadataEventsEnabled),
		MetadataDeliveryProfile:   cmdutil.GetStringConfig("processor.li.metadata_events.delivery_profile", liMetadataDeliveryProfile),
		MetadataAllowFileMetadata: cmdutil.GetBoolConfig("processor.li.metadata_events.allow_file_metadata", liMetadataAllowFileMetadata),
		StateFile:                 cmdutil.GetStringConfig("processor.li.state_file", liStateFile),
	}
}
