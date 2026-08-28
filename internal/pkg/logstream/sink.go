package logstream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/logschema"
)

type Format string

const (
	FormatTSV  Format = "tsv"
	FormatJSON Format = "json"
)

type PostRotateFunc func(context.Context, string) error
type Builder func(events.Event) (Record, bool, error)

type Config struct {
	Directory       string
	Format          Format
	QueueSize       int
	RotateInterval  time.Duration
	WarningInterval time.Duration
	PostRotate      PostRotateFunc
	Logger          *slog.Logger
	Now             func() time.Time
}
type Stats struct{ Enqueued, Written, Dropped, Errors, Rotations uint64 }
type binding struct {
	stream string
	build  Builder
}
type item struct {
	record *Record
	flush  chan error
	stop   chan error
}
type streamWriter struct {
	name    string
	sink    *Sink
	queue   chan item
	file    *os.File
	enc     encoder
	opened  time.Time
	dropped atomic.Uint64
}

type Sink struct {
	cfg                                             Config
	mu                                              sync.RWMutex
	bindings                                        map[events.Kind][]binding
	streams                                         map[string]*streamWriter
	started, stopped, closed                        bool
	ctx                                             context.Context
	cancel                                          context.CancelFunc
	wg                                              sync.WaitGroup
	enqueued, written, dropped, failures, rotations atomic.Uint64
}

func New(cfg Config) (*Sink, error) {
	if cfg.Directory == "" {
		return nil, fmt.Errorf("log directory is required")
	}
	if cfg.Format == "" {
		cfg.Format = FormatTSV
	}
	if cfg.Format != FormatTSV && cfg.Format != FormatJSON {
		return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
	}
	if cfg.QueueSize <= 0 {
		return nil, fmt.Errorf("log queue size must be positive")
	}
	if cfg.WarningInterval <= 0 {
		cfg.WarningInterval = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Get()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Sink{cfg: cfg, bindings: make(map[events.Kind][]binding), streams: make(map[string]*streamWriter)}, nil
}

func (s *Sink) Register(kind events.Kind, stream string, builder Builder) error {
	if builder == nil {
		return fmt.Errorf("register log builder: nil builder")
	}
	if _, ok := logschema.ByName(stream); !ok {
		return fmt.Errorf("register log builder: unknown stream %q", stream)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("register log builder after start")
	}
	s.bindings[kind] = append(s.bindings[kind], binding{stream, builder})
	return nil
}

func (s *Sink) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("log sink already started")
	}
	if s.closed {
		return fmt.Errorf("log sink cannot restart after close")
	}
	if err := os.MkdirAll(s.cfg.Directory, 0o750); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	return nil
}

func (s *Sink) HandleEvent(_ context.Context, ev events.Event) error {
	if ev == nil {
		return nil
	}
	s.mu.RLock()
	started, stopped, closed := s.started, s.stopped, s.closed
	bindings := append([]binding(nil), s.bindings[ev.Kind()]...)
	s.mu.RUnlock()
	if !started || stopped || closed {
		return fmt.Errorf("log sink is not running")
	}
	for _, b := range bindings {
		record, emit, err := b.build(ev)
		if err != nil {
			return fmt.Errorf("build %s record: %w", b.stream, err)
		}
		if !emit {
			continue
		}
		if record.Stream == "" {
			record.Stream = b.stream
		}
		if record.Stream != b.stream {
			return fmt.Errorf("builder for %s returned %s record", b.stream, record.Stream)
		}
		if _, err := NewRecord(record.Stream, record.Values...); err != nil {
			return err
		}
		writer, err := s.writer(b.stream)
		if err != nil {
			return err
		}
		select {
		case writer.queue <- item{record: &record}:
			s.enqueued.Add(1)
		default:
			s.dropped.Add(1)
			writer.dropped.Add(1)
		}
	}
	return nil
}

func (s *Sink) writer(name string) (*streamWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.closed {
		return nil, fmt.Errorf("log sink is not running")
	}
	if w := s.streams[name]; w != nil {
		return w, nil
	}
	w := &streamWriter{name: name, sink: s, queue: make(chan item, s.cfg.QueueSize)}
	s.streams[name] = w
	s.wg.Add(1)
	go w.run()
	return w, nil
}

func (w *streamWriter) run() {
	defer w.sink.wg.Done()
	warn := time.NewTicker(w.sink.cfg.WarningInterval)
	defer warn.Stop()
	var rotate <-chan time.Time
	var rotateTimer *time.Timer
	if w.sink.cfg.RotateInterval > 0 {
		rotateTimer = time.NewTimer(w.sink.cfg.RotateInterval)
		rotate = rotateTimer.C
		defer rotateTimer.Stop()
	}
	var prior uint64
	for {
		select {
		case it := <-w.queue:
			if it.record != nil {
				if err := w.write(*it.record); err != nil {
					w.sink.failures.Add(1)
					w.sink.cfg.Logger.Error("structured log write failed", "stream", w.name, "error", err)
				}
			}
			if it.flush != nil {
				it.flush <- w.flush()
			}
			if it.stop != nil {
				it.stop <- w.close()
				return
			}
		case <-rotate:
			if w.file != nil {
				if err := w.rotate(); err != nil {
					w.sink.failures.Add(1)
					w.sink.cfg.Logger.Error("structured log rotation failed", "stream", w.name, "error", err)
				}
			}
			rotateTimer.Reset(w.sink.cfg.RotateInterval)
		case <-warn.C:
			now := w.dropped.Load()
			if now > prior {
				w.sink.cfg.Logger.Warn("structured log records dropped", "stream", w.name, "dropped", now-prior)
			}
			prior = now
		}
	}
}

func (w *streamWriter) write(r Record) error {
	if w.file == nil {
		if err := w.open(); err != nil {
			return err
		}
	}
	if err := w.enc.Encode(r); err != nil {
		return err
	}
	// Keep the active log safe for line-oriented consumers to tail. Encoding is
	// buffered, so without this flush a low-volume stream can remain invisible
	// and a busy stream can expose the buffer's final, incomplete record.
	if err := w.enc.Flush(); err != nil {
		return fmt.Errorf("flush %s record: %w", w.name, err)
	}
	w.sink.written.Add(1)
	return nil
}
func (w *streamWriter) open() error {
	schema, _ := logschema.ByName(w.name)
	path := filepath.Join(w.sink.cfg.Directory, schema.Filename)
	existingFormat, err := detectLogFormat(path)
	if err != nil {
		return err
	}
	if existingFormat != "" && existingFormat != w.sink.cfg.Format {
		rotated, err := w.archiveActive(path, schema.Filename)
		if err != nil {
			return fmt.Errorf("rotate %s before changing format from %s to %s: %w", path, existingFormat, w.sink.cfg.Format, err)
		}
		w.sink.rotations.Add(1)
		w.runPostRotate(rotated)
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if existingFormat == "" {
		// Empty or whitespace-only remnants do not contain records worth
		// preserving and must not precede a Zeek header or JSONL record.
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o640)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	w.file = f
	w.opened = w.sink.cfg.Now()
	if w.sink.cfg.Format == FormatTSV {
		w.enc = newTSVEncoder(f, schema)
	} else {
		w.enc = newJSONEncoder(f, schema)
	}
	if err = w.enc.Open(w.opened); err != nil {
		_ = f.Close()
		w.file = nil
		return fmt.Errorf("write %s header: %w", path, err)
	}
	// Zeek readers need the header before they can interpret records. Publish it
	// immediately rather than leaving low-volume logs in the encoder buffer.
	if err = w.enc.Flush(); err != nil {
		closeErr := f.Close()
		w.file = nil
		return errors.Join(fmt.Errorf("flush %s header: %w", path, err), closeErr)
	}
	return nil
}
func (w *streamWriter) flush() error {
	if w.file == nil {
		return nil
	}
	if err := w.enc.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}
func (w *streamWriter) close() error {
	if w.file == nil {
		return nil
	}
	var result error
	if err := w.enc.Close(w.sink.cfg.Now()); err != nil {
		result = errors.Join(result, err)
	}
	if err := w.enc.Flush(); err != nil {
		result = errors.Join(result, err)
	}
	if err := w.file.Close(); err != nil {
		result = errors.Join(result, err)
	}
	w.file = nil
	return result
}
func (w *streamWriter) rotate() error {
	if err := w.close(); err != nil {
		return err
	}
	schema, _ := logschema.ByName(w.name)
	active := filepath.Join(w.sink.cfg.Directory, schema.Filename)
	rotated, err := w.archiveActive(active, schema.Filename)
	if err != nil {
		return fmt.Errorf("archive rotated log: %w", err)
	}
	w.sink.rotations.Add(1)
	w.runPostRotate(rotated)
	return nil
}

func (w *streamWriter) runPostRotate(rotated string) {
	if hook := w.sink.cfg.PostRotate; hook != nil {
		go func() {
			if err := hook(w.sink.ctx, rotated); err != nil {
				w.sink.failures.Add(1)
				w.sink.cfg.Logger.Error("structured log post-rotate hook failed", "file", rotated, "error", err)
			}
		}()
	}
}

// archiveActive preserves an active log under a collision-free rotation name.
// Link followed by remove avoids os.Rename's overwrite behavior when two
// rotations receive the same second-resolution timestamp.
func (w *streamWriter) archiveActive(active, filename string) (string, error) {
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext) + "-" + zeekClock(w.sink.cfg.Now())
	for sequence := 0; ; sequence++ {
		suffix := ""
		if sequence > 0 {
			suffix = fmt.Sprintf("-%d", sequence)
		}
		rotated := filepath.Join(w.sink.cfg.Directory, base+suffix+ext)
		if err := os.Link(active, rotated); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", fmt.Errorf("preserve active log as %s: %w", rotated, err)
		}
		if err := os.Remove(active); err != nil {
			cleanupErr := os.Remove(rotated)
			return "", errors.Join(fmt.Errorf("remove archived active log %s: %w", active, err), cleanupErr)
		}
		return rotated, nil
	}
}

// detectLogFormat identifies formats by their first non-whitespace byte: Zeek
// TSV files begin with a header comment and JSONL records begin with an object.
func detectLogFormat(path string) (format Format, result error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect existing log %s: %w", path, err)
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	r := bufio.NewReader(f)
	for {
		b, readErr := r.ReadByte()
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return "", nil
			}
			return "", fmt.Errorf("inspect existing log %s: %w", path, readErr)
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		switch b {
		case '#':
			return FormatTSV, nil
		case '{':
			return FormatJSON, nil
		default:
			return "", fmt.Errorf("inspect existing log %s: unrecognized format", path)
		}
	}
}

func (s *Sink) Flush(ctx context.Context) error { return s.each(ctx, false) }
func (s *Sink) Stop(ctx context.Context) error  { return s.each(ctx, true) }
func (s *Sink) each(ctx context.Context, stop bool) error {
	if stop {
		s.mu.Lock()
		if s.stopped || !s.started {
			s.stopped = true
			s.mu.Unlock()
			return nil
		}
		s.stopped = true
		s.mu.Unlock()
	}
	if !stop {
		s.mu.RLock()
		stopped := s.stopped
		s.mu.RUnlock()
		if stopped {
			return nil
		}
	}
	s.mu.RLock()
	writers := make([]*streamWriter, 0, len(s.streams))
	for _, w := range s.streams {
		writers = append(writers, w)
	}
	s.mu.RUnlock()
	var result error
	for _, w := range writers {
		response := make(chan error, 1)
		it := item{flush: response}
		if stop {
			it = item{stop: response}
		}
		select {
		case w.queue <- it:
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
		select {
		case err := <-response:
			result = errors.Join(result, err)
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
	}
	if stop {
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
	}
	return result
}
func (s *Sink) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	started := s.started && !s.stopped
	s.mu.Unlock()
	var err error
	if started {
		err = s.Stop(ctx)
	}
	if s.cancel != nil {
		s.cancel()
	}
	return err
}
func (s *Sink) QueueDepth() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, w := range s.streams {
		n += len(w.queue)
	}
	return n
}
func (s *Sink) QueueCapacity() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams) * s.cfg.QueueSize
}
func (s *Sink) Stats() Stats {
	return Stats{s.enqueued.Load(), s.written.Load(), s.dropped.Load(), s.failures.Load(), s.rotations.Load()}
}

var _ events.Sink = (*Sink)(nil)
