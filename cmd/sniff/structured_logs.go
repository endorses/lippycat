//go:build cli || all

package sniff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/eventcoalesce"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/logflags"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	logrecords "github.com/endorses/lippycat/internal/pkg/logstream/records"
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
}

// withEventAnalysis keeps normalized event production active independently of
// optional structured-log output. The observer is best-effort and cannot block
// the packet display/output pipeline.
func withEventAnalysis(inputFiles []string, analysisProfile string, run func()) {
	dir := viper.GetString("logs.dir")
	s, err := newSniffEventSession(dir, inputFiles, analysisProfile, nil)
	if err != nil {
		logger.Error("Failed to initialize normalized event analysis", "error", err)
		run()
		return
	}
	restore := capture.SetPacketObserver(s.observe)
	defer restore()
	defer func() {
		s.analysis.EOF()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.dispatcher.Close(ctx); err != nil {
			logger.Error("Failed to close normalized event analysis", "error", err)
		}
	}()
	run()
}

func newSniffEventSession(dir string, inputFiles []string, analysisProfile string, additionalSink events.Sink) (*sniffEventSession, error) {
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
		Flow:                    flowid.Config{MaxEntries: 100000, IdleTimeout: 5 * time.Minute},
		Connections:             conntrack.Config{MaxFlows: 100000, IdleTimeout: 5 * time.Minute, HalfOpenTimeout: 30 * time.Second},
		Files:                   fileanalysis.Config{MaxFileSize: viper.GetInt64("files.max_size"), MaxTotalSize: viper.GetInt64("files.total_size"), Extract: viper.GetBool("files.extract"), Directory: viper.GetString("files.extract_dir")},
		IncludeHTTPHeaders:      viper.GetBool("logs.include_http_headers"),
		IncludeEmailBodyPreview: viper.GetBool("logs.include_email_body_preview"),
	})
	if err != nil {
		return nil, err
	}
	var startedSink *logstream.Sink
	if dir != "" {
		sink, sinkErr := registerSniffLogSink(d, dir, queueSize)
		if sinkErr != nil {
			return nil, sinkErr
		}
		if sinkErr = sink.Start(context.Background()); sinkErr != nil {
			return nil, sinkErr
		}
		startedSink = sink
	}
	if err := d.Start(context.Background()); err != nil {
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
		"dns": {events.KindDNS, logrecords.DNS}, "ssl": {events.KindTLS, logrecords.SSL}, "http": {events.KindHTTP, logrecords.HTTP}, "smtp": {events.KindSMTP, logrecords.SMTP}, "conn": {events.KindConn, logrecords.Conn}, "files": {events.KindFileMetadata, logrecords.Files},
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
	if err := d.Register(coalescedLogs, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP, events.KindConn, events.KindFileMetadata); err != nil {
		return nil, err
	}
	return sink, nil
}

func sniffEventProducer(inputFiles []string, analysisProfile string) (*events.Producer, error) {
	if len(inputFiles) == 0 {
		return events.NewLiveProducer("local")
	}
	h := sha256.New()
	for _, path := range inputFiles {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open offline event input %q: %w", path, err)
		}
		fileHash := sha256.New()
		_, copyErr := io.Copy(fileHash, file)
		closeErr := file.Close()
		if copyErr != nil {
			if closeErr != nil {
				return nil, fmt.Errorf("hash offline event input %q: copy: %w; close: %w", path, copyErr, closeErr)
			}
			return nil, fmt.Errorf("hash offline event input %q: %w", path, copyErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close offline event input %q: %w", path, closeErr)
		}
		// Each digest has a fixed width, so file boundaries remain part of the
		// identity even when adjacent files' bytes could otherwise concatenate
		// to the same stream.
		_, _ = h.Write(fileHash.Sum(nil))
	}
	return events.NewOfflineProducer("local", events.OfflineSession{
		InputIdentity:   "sha256:" + hex.EncodeToString(h.Sum(nil)),
		AnalysisProfile: analysisProfile,
		SourceOrdering:  append([]string(nil), inputFiles...),
	})
}

func structuredLogAnalysisProfile(scope, effectiveFilter string) string {
	return fmt.Sprintf("events-v1|scope=%s|filter=%s|headers=%t|file-max=%d|file-total=%d|extract=%t|extract-dir=%s",
		scope, effectiveFilter, viper.GetBool("logs.include_http_headers"), viper.GetInt64("files.max_size"),
		viper.GetInt64("files.total_size"), viper.GetBool("files.extract"), viper.GetString("files.extract_dir"))
}

func (s *sniffEventSession) observe(info capture.PacketInfo) {
	source := eventanalysis.Source{NodeID: "local", CaptureSource: info.Interface}
	if info.SourcePath != "" {
		source.InputFile = info.SourcePath
	} else {
		source.InterfaceName = info.Interface
	}
	if err := s.analysis.ObservePacket(source, info); err != nil {
		logger.Debug("Skipping invalid packet during normalized event analysis", "source", info.Interface, "error", err)
	}
}
