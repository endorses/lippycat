// Package logflags provides the common CLI flags for normalized protocol events
// and structured protocol log sinks.
package logflags

import (
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Values holds defaults populated by pflag. Callers may use these as fallbacks
// when resolving values from configuration.
type Values struct {
	EventQueueSize      int
	Directory           string
	Format              string
	Streams             []string
	IncludeHTTPHeaders  bool
	RotateInterval      time.Duration
	QueueSize           int
	EmitStage           string
	PostRotateCommand   string
	ExtractFiles        bool
	ExtractionDirectory string
	FileMaxSize         int64
	FileTotalSize       int64
}

// Register adds and binds the shared structured-log flags. includeEmitStage is
// false for sniff because a standalone capture cannot be an intermediate node.
func Register(flags *pflag.FlagSet, values *Values, includeEmitStage bool) {
	flags.IntVar(&values.EventQueueSize, "event-queue-size", 20000, "Normalized protocol event queue size")
	flags.StringVar(&values.Directory, "log-dir", "", "Write structured protocol logs to this directory")
	flags.StringVar(&values.Format, "log-format", "tsv", "Structured log format: tsv or json")
	flags.StringSliceVar(&values.Streams, "log-streams", []string{"conn", "dns", "ssl", "http", "smtp", "files"}, "Structured log streams")
	flags.BoolVar(&values.IncludeHTTPHeaders, "log-include-http-headers", false, "Include full HTTP header maps in structured logs")
	flags.DurationVar(&values.RotateInterval, "log-rotate-interval", time.Hour, "Structured log rotation interval")
	flags.IntVar(&values.QueueSize, "log-queue-size", 10000, "Per-stream structured log queue size")
	if includeEmitStage {
		flags.StringVar(&values.EmitStage, "log-emit-stage", "terminal", "Structured log emission stage: terminal, all, or none")
	}
	flags.StringVar(&values.PostRotateCommand, "log-post-rotate-command", "", "Command after log rotation (%log% is replaced with the file path)")
	flags.BoolVar(&values.ExtractFiles, "extract-files", false, "Extract bounded HTTP and SMTP files (disabled by default)")
	flags.StringVar(&values.ExtractionDirectory, "extract-files-dir", "", "Directory for extracted files")
	flags.Int64Var(&values.FileMaxSize, "extract-files-max-size", 10<<20, "Maximum bytes analyzed or extracted per file")
	flags.Int64Var(&values.FileTotalSize, "extract-files-total-size", 100<<20, "Maximum extracted bytes for this process")

	_ = viper.BindPFlag("events.queue_size", flags.Lookup("event-queue-size"))
	_ = viper.BindPFlag("logs.dir", flags.Lookup("log-dir"))
	_ = viper.BindPFlag("logs.format", flags.Lookup("log-format"))
	_ = viper.BindPFlag("logs.streams", flags.Lookup("log-streams"))
	_ = viper.BindPFlag("logs.include_http_headers", flags.Lookup("log-include-http-headers"))
	_ = viper.BindPFlag("logs.rotate_interval", flags.Lookup("log-rotate-interval"))
	_ = viper.BindPFlag("logs.queue_size", flags.Lookup("log-queue-size"))
	if includeEmitStage {
		_ = viper.BindPFlag("logs.emit_stage", flags.Lookup("log-emit-stage"))
	}
	_ = viper.BindPFlag("logs.post_rotate_command", flags.Lookup("log-post-rotate-command"))
	_ = viper.BindPFlag("files.extract", flags.Lookup("extract-files"))
	_ = viper.BindPFlag("files.extract_dir", flags.Lookup("extract-files-dir"))
	_ = viper.BindPFlag("files.max_size", flags.Lookup("extract-files-max-size"))
	_ = viper.BindPFlag("files.total_size", flags.Lookup("extract-files-total-size"))
}
