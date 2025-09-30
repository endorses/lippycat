package sniff

import (
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var voipCmd = &cobra.Command{
	Use:   "voip",
	Short: "Sniff in VOIP mode",
	Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
	Run:   voipHandler,
}

var (
	sipuser   string
	writeVoip bool

	// GPU acceleration flags
	gpuBackend         string
	gpuBatchSize       int
	gpuMaxMemory       int64
	gpuEnable          bool

	// TCP-specific configuration flags
	tcpMaxGoroutines      int
	tcpCleanupInterval    time.Duration
	tcpBufferMaxAge       time.Duration
	tcpStreamMaxQueueTime time.Duration
	maxTCPBuffers         int
	tcpStreamTimeout      time.Duration
	tcpAssemblerMaxPages  int
	tcpPerformanceMode    string
	tcpBufferStrategy     string
	enableBackpressure    bool
	memoryOptimization    bool
)

func voipHandler(cmd *cobra.Command, args []string) {
	expirationDate := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
	su := sipusers.SipUser{ExpirationDate: expirationDate}

	for _, user := range strings.Split(sipuser, ",") {
		sipusers.AddSipUser(user, &su)
	}

	logger.Info("Starting VoIP sniffing",
		"users", strings.Split(sipuser, ","),
		"interfaces", interfaces,
		"write_voip", writeVoip)
	viper.Set("writeVoip", writeVoip)

	// Set GPU configuration values
	if cmd.Flags().Changed("gpu-enable") {
		viper.Set("voip.gpu_enable", gpuEnable)
	}
	if cmd.Flags().Changed("gpu-backend") {
		viper.Set("voip.gpu_backend", gpuBackend)
	}
	if cmd.Flags().Changed("gpu-batch-size") {
		viper.Set("voip.gpu_batch_size", gpuBatchSize)
	}
	if cmd.Flags().Changed("gpu-max-memory") {
		viper.Set("voip.gpu_max_memory", gpuMaxMemory)
	}

	// Set TCP-specific configuration values
	if cmd.Flags().Changed("tcp-max-goroutines") {
		viper.Set("voip.max_goroutines", tcpMaxGoroutines)
	}
	if cmd.Flags().Changed("tcp-cleanup-interval") {
		viper.Set("voip.tcp_cleanup_interval", tcpCleanupInterval)
	}
	if cmd.Flags().Changed("tcp-buffer-max-age") {
		viper.Set("voip.tcp_buffer_max_age", tcpBufferMaxAge)
	}
	if cmd.Flags().Changed("tcp-stream-max-queue-time") {
		viper.Set("voip.tcp_stream_max_queue_time", tcpStreamMaxQueueTime)
	}
	if cmd.Flags().Changed("max-tcp-buffers") {
		viper.Set("voip.max_tcp_buffers", maxTCPBuffers)
	}
	if cmd.Flags().Changed("tcp-stream-timeout") {
		viper.Set("voip.tcp_stream_timeout", tcpStreamTimeout)
	}
	if cmd.Flags().Changed("tcp-assembler-max-pages") {
		viper.Set("voip.tcp_assembler_max_pages", tcpAssemblerMaxPages)
	}
	if cmd.Flags().Changed("tcp-performance-mode") {
		viper.Set("voip.tcp_performance_mode", tcpPerformanceMode)
	}
	if cmd.Flags().Changed("tcp-buffer-strategy") {
		viper.Set("voip.tcp_buffer_strategy", tcpBufferStrategy)
	}
	if cmd.Flags().Changed("enable-backpressure") {
		viper.Set("voip.enable_backpressure", enableBackpressure)
	}
	if cmd.Flags().Changed("memory-optimization") {
		viper.Set("voip.memory_optimization", memoryOptimization)
	}

	logger.Info("Starting VoIP sniffing with optimizations",
		"gpu_enable", viper.GetBool("voip.gpu_enable"),
		"gpu_backend", viper.GetString("voip.gpu_backend"),
		"tcp_max_goroutines", viper.GetInt("voip.max_goroutines"),
		"tcp_performance_mode", viper.GetString("voip.tcp_performance_mode"),
		"tcp_buffer_strategy", viper.GetString("voip.tcp_buffer_strategy"),
		"enable_backpressure", viper.GetBool("voip.enable_backpressure"),
		"memory_optimization", viper.GetBool("voip.memory_optimization"))

	if readFile == "" {
		voip.StartLiveVoipSniffer(interfaces, filter)
	} else {
		voip.StartOfflineVoipSniffer(readFile, filter)
	}
}

func init() {
	voipCmd.Flags().StringVarP(&sipuser, "sipuser", "u", "", "SIP user to intercept")
	voipCmd.Flags().BoolVarP(&writeVoip, "write-file", "w", false, "write to pcap file")

	// GPU Acceleration Flags
	voipCmd.Flags().BoolVar(&gpuEnable, "gpu-enable", true, "Enable GPU acceleration for pattern matching (default: true)")
	voipCmd.Flags().StringVar(&gpuBackend, "gpu-backend", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd', 'disabled' (default: auto)")
	voipCmd.Flags().IntVar(&gpuBatchSize, "gpu-batch-size", 1024, "Batch size for GPU processing (default: 1024)")
	voipCmd.Flags().Int64Var(&gpuMaxMemory, "gpu-max-memory", 0, "Maximum GPU memory in bytes (0 = auto)")

	// TCP Performance and Configuration Flags
	voipCmd.Flags().IntVar(&tcpMaxGoroutines, "tcp-max-goroutines", 0, "Maximum concurrent TCP stream processing goroutines (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpCleanupInterval, "tcp-cleanup-interval", 0, "TCP resource cleanup interval (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpBufferMaxAge, "tcp-buffer-max-age", 0, "Maximum age for TCP packet buffers (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpStreamMaxQueueTime, "tcp-stream-max-queue-time", 0, "Maximum time a stream can wait in queue (0 = use default)")
	voipCmd.Flags().IntVar(&maxTCPBuffers, "max-tcp-buffers", 0, "Maximum number of TCP packet buffers (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpStreamTimeout, "tcp-stream-timeout", 0, "Timeout for TCP stream processing (0 = use default)")
	voipCmd.Flags().IntVar(&tcpAssemblerMaxPages, "tcp-assembler-max-pages", 0, "Maximum pages for TCP assembler (0 = use default)")

	// TCP Performance Optimization Flags
	voipCmd.Flags().StringVar(&tcpPerformanceMode, "tcp-performance-mode", "", "TCP performance mode: 'balanced', 'throughput', 'latency', 'memory' (default: balanced)")
	voipCmd.Flags().StringVar(&tcpBufferStrategy, "tcp-buffer-strategy", "", "TCP buffering strategy: 'adaptive', 'fixed', 'ring' (default: adaptive)")
	voipCmd.Flags().BoolVar(&enableBackpressure, "enable-backpressure", false, "Enable backpressure handling for TCP streams")
	voipCmd.Flags().BoolVar(&memoryOptimization, "memory-optimization", false, "Enable memory usage optimizations")

	// Bind GPU flags to viper for config file support
	viper.BindPFlag("voip.gpu_enable", voipCmd.Flags().Lookup("gpu-enable"))
	viper.BindPFlag("voip.gpu_backend", voipCmd.Flags().Lookup("gpu-backend"))
	viper.BindPFlag("voip.gpu_batch_size", voipCmd.Flags().Lookup("gpu-batch-size"))
	viper.BindPFlag("voip.gpu_max_memory", voipCmd.Flags().Lookup("gpu-max-memory"))

	// Bind flags to viper for config file support
	viper.BindPFlag("voip.max_goroutines", voipCmd.Flags().Lookup("tcp-max-goroutines"))
	viper.BindPFlag("voip.tcp_cleanup_interval", voipCmd.Flags().Lookup("tcp-cleanup-interval"))
	viper.BindPFlag("voip.tcp_buffer_max_age", voipCmd.Flags().Lookup("tcp-buffer-max-age"))
	viper.BindPFlag("voip.tcp_stream_max_queue_time", voipCmd.Flags().Lookup("tcp-stream-max-queue-time"))
	viper.BindPFlag("voip.max_tcp_buffers", voipCmd.Flags().Lookup("max-tcp-buffers"))
	viper.BindPFlag("voip.tcp_stream_timeout", voipCmd.Flags().Lookup("tcp-stream-timeout"))
	viper.BindPFlag("voip.tcp_assembler_max_pages", voipCmd.Flags().Lookup("tcp-assembler-max-pages"))
	viper.BindPFlag("voip.tcp_performance_mode", voipCmd.Flags().Lookup("tcp-performance-mode"))
	viper.BindPFlag("voip.tcp_buffer_strategy", voipCmd.Flags().Lookup("tcp-buffer-strategy"))
	viper.BindPFlag("voip.enable_backpressure", voipCmd.Flags().Lookup("enable-backpressure"))
	viper.BindPFlag("voip.memory_optimization", voipCmd.Flags().Lookup("memory-optimization"))
}
