//go:build cli || all

package sniff

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/eventcoalesce"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/logflags"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	logrecords "github.com/endorses/lippycat/internal/pkg/logstream/records"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var sniffLogFlags logflags.Values

func registerStructuredLogFlags(cmd *cobra.Command) {
	logflags.Register(cmd.PersistentFlags(), &sniffLogFlags, false)
}

type sniffEventSession struct {
	dispatcher *events.Dispatcher
	analysis   *eventanalysis.Runtime
	radius     *radius.CaptureProcessor
	filtered   bool
}

// withEventAnalysis installs optional normalized analysis only for requested
// consumers. Ordinary protocol decoding and packet output own their lifecycle.
func withEventAnalysis(inputFiles []string, analysisProfile, effectiveFilter string, run func()) {
	withEventAnalysisMode(inputFiles, analysisProfile, effectiveFilter, false, func(*sniffEventSession) { run() })
}

func withEventAnalysisMode(inputFiles []string, analysisProfile, effectiveFilter string, pipelineOwned bool, run func(*sniffEventSession)) {
	dir := viper.GetString("logs.dir")
	s, err := newSniffEventSession(dir, inputFiles, analysisProfile, nil)
	if err != nil {
		logger.Error("Failed to initialize normalized event analysis", "error", err)
		return
	}
	if s == nil {
		run(nil)
		return
	}
	s.filtered = strings.TrimSpace(effectiveFilter) != ""
	defer func() {
		if s.radius != nil {
			s.radius.Close()
		}
		s.analysis.EOF()
		s.analysis.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.dispatcher.Close(ctx); err != nil {
			logger.Error("Failed to close normalized event analysis", "error", err)
		}
	}()
	if !pipelineOwned {
		s.radius, err = radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "local"})
		if err != nil {
			logger.Error("Failed to initialize RADIUS observations", "error", err)
			run(nil)
			return
		}
		restore := capture.SetPacketObserver(s.observe)
		defer restore()
	}
	run(s)
}

func newSniffEventSession(dir string, inputFiles []string, analysisProfile string, additionalSink events.Sink) (*sniffEventSession, error) {
	if err := validateSniffAnalysisPolicy(); err != nil {
		return nil, err
	}
	if dir == "" && additionalSink == nil && !viper.GetBool("files.extract") {
		return nil, nil
	}

	eventSize := viper.GetInt("events.queue_size")
	if eventSize <= 0 {
		eventSize = 20000
	}
	queueSize := viper.GetInt("logs.queue_size")
	if queueSize <= 0 {
		queueSize = 10000
	}
	producer, err := sniffEventProducer(inputFiles, analysisProfile)
	if err != nil {
		return nil, fmt.Errorf("initialize event identity: %w", err)
	}
	d, err := events.NewDispatcher(events.Config{QueueSize: eventSize, SinkQueueSize: eventSize, DropPolicy: events.DropPolicy(viper.GetString("events.drop_policy")), Producer: producer})
	if err != nil {
		return nil, err
	}
	if additionalSink != nil {
		if err := d.Register(additionalSink); err != nil {
			return nil, err
		}
	}
	analysis, err := eventanalysis.New(eventanalysis.Config{
		Dispatcher:              d,
		Policy:                  eventconfig.FromViper(viper.GetViper()),
		AnalysisEpoch:           producer.SessionID(),
		Flow:                    flowid.Config{MaxEntries: 100000, IdleTimeout: 5 * time.Minute},
		Connections:             conntrack.Config{MaxFlows: 100000, IdleTimeout: 5 * time.Minute, HalfOpenTimeout: 30 * time.Second},
		Files:                   fileanalysis.Config{MaxFileSize: viper.GetInt64("files.max_size"), MaxTotalSize: viper.GetInt64("files.total_size"), Extract: viper.GetBool("files.extract"), Directory: viper.GetString("files.extract_dir")},
		IncludeHTTPHeaders:      viper.GetBool("logs.include_http_headers"),
		IncludeEmailBodyPreview: viper.GetBool("logs.include_email_body_preview"),
		LiveExpiry:              len(inputFiles) == 0,
	})
	if err != nil {
		return nil, err
	}
	var startedSink *logstream.Sink
	if dir != "" {
		sink, sinkErr := registerSniffLogSink(d, dir, queueSize)
		if sinkErr != nil {
			analysis.Close()
			return nil, sinkErr
		}
		if sinkErr = sink.Start(context.Background()); sinkErr != nil {
			analysis.Close()
			return nil, sinkErr
		}
		startedSink = sink
	}
	if err := d.Start(context.Background()); err != nil {
		analysis.Close()
		if startedSink != nil {
			if closeErr := startedSink.Close(context.Background()); closeErr != nil {
				return nil, fmt.Errorf("start event dispatcher: %w; close structured log sink: %v", err, closeErr)
			}
		}
		return nil, err
	}
	return &sniffEventSession{dispatcher: d, analysis: analysis}, nil
}

func registerSniffLogSink(d *events.Dispatcher, dir string, queueSize int) (*logstream.Sink, error) {
	sink, err := logstream.New(logstream.Config{Directory: dir, Format: logstream.Format(viper.GetString("logs.format")), QueueSize: queueSize, RotateInterval: viper.GetDuration("logs.rotate_interval"), PostRotate: logstream.CommandHook(viper.GetString("logs.post_rotate_command"), 30*time.Second)})
	if err != nil {
		return nil, err
	}
	builders := map[string]struct {
		kind  events.Kind
		build logstream.Builder
	}{
		"dhcp": {events.KindDHCP, logrecords.DHCP}, "ntp": {events.KindNTP, logrecords.NTP},
		"known_hosts": {events.KindKnownHost, logrecords.KnownHosts}, "known_services": {events.KindKnownService, logrecords.KnownServices},
		"radius": {events.KindRADIUS, logrecords.RADIUS}, "dns": {events.KindDNS, logrecords.DNS}, "ssl": {events.KindTLS, logrecords.SSL}, "http": {events.KindHTTP, logrecords.HTTP}, "smtp": {events.KindSMTP, logrecords.SMTP}, "conn": {events.KindConn, logrecords.Conn}, "files": {events.KindFileMetadata, logrecords.Files},
	}
	for _, stream := range viper.GetStringSlice("logs.streams") {
		binding, ok := builders[strings.ToLower(stream)]
		if !ok {
			continue
		}
		if err := sink.Register(binding.kind, strings.ToLower(stream), binding.build); err != nil {
			return nil, err
		}
	}
	coalescedLogs, err := eventcoalesce.New(sink, eventcoalesce.Config{})
	if err != nil {
		return nil, err
	}
	if err := d.Register(coalescedLogs, events.KindDHCP, events.KindNTP, events.KindKnownHost, events.KindKnownService, events.KindRADIUS, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP, events.KindConn, events.KindFileMetadata); err != nil {
		return nil, err
	}
	return sink, nil
}

func sniffEventProducer(inputFiles []string, analysisProfile string) (*events.Producer, error) {
	if len(inputFiles) == 0 {
		return events.NewLiveProducer("local")
	}
	inputIdentity, err := events.OfflineInputIdentity(inputFiles)
	if err != nil {
		return nil, err
	}
	return events.NewOfflineProducer("local", events.OfflineSession{
		InputIdentity:   inputIdentity,
		AnalysisProfile: analysisProfile,
		SourceOrdering:  append([]string(nil), inputFiles...),
	})
}

func structuredLogAnalysisProfile(scope, effectiveFilter string) string {
	return fmt.Sprintf("events-v1|scope=%s|filter=%s|headers=%t|email-body=%t|file-max=%d|file-total=%d|extract=%t|extract-dir=%s|policy=%s",
		scope, effectiveFilter, viper.GetBool("logs.include_http_headers"), viper.GetBool("logs.include_email_body_preview"), viper.GetInt64("files.max_size"),
		viper.GetInt64("files.total_size"), viper.GetBool("files.extract"), viper.GetString("files.extract_dir"), eventconfig.FromViper(viper.GetViper()).Fingerprint())
}

func (s *sniffEventSession) observe(info *capture.PacketInfo) {
	// Protocol ingress uses the optional capture observer. The local packet
	// pipeline instead attaches its ordinary RADIUS observation before calling us,
	// so logs and packet sinks share one stateful decoding/association pass.
	if info.RADIUS == nil && s.radius != nil {
		info.RADIUS = s.radius.Process(info.Packet, info.LinkType, info.Interface, nil)
	}
	source := eventanalysis.Source{NodeID: "local", CaptureSource: info.Interface}
	if s.filtered {
		source.CaptureScope = events.CaptureScopeFiltered
		source.Partial = true
	}
	if info.SourcePath != "" {
		source.InputFile = info.SourcePath
	} else {
		source.InterfaceName = info.Interface
	}
	if err := s.analysis.ObservePacket(source, *info); err != nil {
		logger.Debug("Skipping invalid packet during normalized event analysis", "source", info.Interface, "error", err)
	}
}

// bindSniffEventFlags selects the active command after all role commands register.
func bindSniffEventFlags(cmd *cobra.Command) {
	logflags.Bind(cmd.InheritedFlags())
	logflags.Bind(cmd.Flags())
	logflags.Bind(cmd.PersistentFlags())
}

func validateSniffAnalysisPolicy() error {
	if dropPolicy := events.DropPolicy(viper.GetString("events.drop_policy")); dropPolicy != "" && dropPolicy != events.DropNew {
		return fmt.Errorf("unsupported event drop policy %q", dropPolicy)
	}
	policy := eventconfig.FromViper(viper.GetViper())
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("event analysis configuration: %w", err)
	}
	streams := viper.GetStringSlice("logs.streams")
	if _, err := protoadapter.RequiredKinds(streams); err != nil {
		return err
	}
	for _, stream := range streams {
		if (stream == "known_hosts" || stream == "known_services") && !policy.Inventory.Enabled {
			return fmt.Errorf("inventory log %q requires enabled inventory", stream)
		}
	}
	return nil
}
