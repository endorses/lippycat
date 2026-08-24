// Package fileanalysis performs bounded, content-aware file observation.
package fileanalysis

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"  // #nosec G501 -- compatibility hashes are intentionally emitted alongside SHA-256.
	"crypto/sha1" // #nosec G505 -- compatibility hashes are intentionally emitted alongside SHA-256.
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/events"
)

type Config struct {
	MaxFileSize, MaxTotalSize int64
	Extract                   bool
	Directory                 string
}

type Observation struct {
	Envelope                                       events.Envelope
	Source, Filename, ContentType, ContentEncoding string
	Content                                        []byte
	TotalBytes                                     uint64
	Truncated                                      bool
	IsOrigin                                       bool
}

type Analyzer struct {
	cfg   Config
	total atomic.Int64
	mu    sync.Mutex
	seen  map[string]string
}

func New(cfg Config) (*Analyzer, error) {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 10 << 20
	}
	if cfg.MaxTotalSize <= 0 {
		cfg.MaxTotalSize = 100 << 20
	}
	if cfg.Extract && cfg.Directory == "" {
		return nil, fmt.Errorf("file extraction directory is required")
	}
	if cfg.Extract {
		if err := os.MkdirAll(cfg.Directory, 0o750); err != nil {
			return nil, fmt.Errorf("create extraction directory: %w", err)
		}
	}
	return &Analyzer{cfg: cfg, seen: make(map[string]string)}, nil
}

// Analyze hashes at most MaxFileSize bytes and emits metadata unconditionally.
// Content is returned only when extraction was explicitly enabled.
func (a *Analyzer) Analyze(obs Observation) (events.FileMetadataEvent, *events.FileContentEvent, error) {
	content, decodeErr := decodeContent(obs.Content, obs.ContentEncoding, a.cfg.MaxFileSize+1)
	if decodeErr != nil {
		content = obs.Content
	}
	total := obs.TotalBytes
	if total == 0 {
		total = uint64(len(content))
	}
	overflow := uint64(0)
	if int64(len(content)) > a.cfg.MaxFileSize {
		overflow = uint64(int64(len(content)) - a.cfg.MaxFileSize)
		content = content[:a.cfg.MaxFileSize]
	}
	hMD5, hSHA1, hSHA256 := md5.New(), sha1.New(), sha256.New() // #nosec G401 -- compatibility identifiers, not security decisions.
	w := io.MultiWriter(hMD5, hSHA1, hSHA256)
	if _, err := io.Copy(w, bytes.NewReader(content)); err != nil {
		return events.FileMetadataEvent{}, nil, fmt.Errorf("hash file: %w", err)
	}
	sha256Text := hex.EncodeToString(hSHA256.Sum(nil))
	fuid, duplicate := a.fileID(sha256Text)
	mimeType := sniffMIME(content, obs.ContentType)
	ev := events.NewFileMetadataEvent(obs.Envelope)
	ev.FileID, ev.Source, ev.MIMEType, ev.Filename = fuid, obs.Source, mimeType, filepath.Base(obs.Filename)
	ev.Analyzers = []string{"MD5", "SHA1", "SHA256"}
	ev.IsOrigin, ev.SeenBytes, ev.TotalBytes, ev.OverflowBytes = obs.IsOrigin, uint64(len(content)), total, overflow
	ev.MissingBytes = total - min(total, uint64(len(content)))
	ev.MD5, ev.SHA1, ev.SHA256 = hex.EncodeToString(hMD5.Sum(nil)), hex.EncodeToString(hSHA1.Sum(nil)), sha256Text
	ev.TimedOut = obs.Truncated
	ev.HashComplete = !obs.Truncated && ev.MissingBytes == 0 && ev.OverflowBytes == 0 && decodeErr == nil
	var contentEvent *events.FileContentEvent
	if a.cfg.Extract && duplicate {
		path := filepath.Join(a.cfg.Directory, fuid)
		if _, err := os.Stat(path); err == nil {
			ev.ExtractedPath = path
		}
	} else if a.cfg.Extract && a.reserve(int64(len(content))) {
		path := filepath.Join(a.cfg.Directory, fuid)
		if err := os.WriteFile(path, content, 0o640); err != nil {
			return ev, nil, fmt.Errorf("extract file: %w", err)
		}
		ev.ExtractedPath = path
		ce := events.NewFileContentEvent(obs.Envelope)
		ce.FileID, ce.MIMEType, ce.Filename, ce.Content = fuid, mimeType, ev.Filename, append([]byte(nil), content...)
		contentEvent = &ce
	}
	return ev, contentEvent, nil
}

func (a *Analyzer) fileID(sum string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id := a.seen[sum]; id != "" {
		return id, true
	}
	id := "F" + strings.ToUpper(sum[:20])
	a.seen[sum] = id
	return id, false
}
func (a *Analyzer) reserve(n int64) bool {
	for {
		old := a.total.Load()
		if n > a.cfg.MaxTotalSize-old {
			return false
		}
		if a.total.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func decodeContent(content []byte, encoding string, limit int64) ([]byte, error) {
	if !strings.Contains(strings.ToLower(encoding), "gzip") {
		return content, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("open gzip body: %w", err)
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, fmt.Errorf("decode gzip body: %w", err)
	}
	return b, nil
}
func sniffMIME(content []byte, declared string) string {
	detected := http.DetectContentType(content)
	if detected != "application/octet-stream" || declared == "" {
		return detected
	}
	if mt, _, err := mime.ParseMediaType(declared); err == nil {
		return mt
	}
	return detected
}

// SMTPAttachments walks a bounded MIME message and returns decoded attachments.
func SMTPAttachments(body []byte, contentType string, max int64) ([]Observation, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parse MIME content type: %w", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("multipart boundary is missing")
	}
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []Observation
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("read MIME part: %w", err)
		}
		name := p.FileName()
		disposition, _, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if name == "" && !strings.EqualFold(disposition, "attachment") {
			p.Close()
			continue
		}
		b, readErr := io.ReadAll(io.LimitReader(p, max+1))
		closeErr := p.Close()
		if readErr != nil {
			return out, fmt.Errorf("read MIME attachment: %w", readErr)
		}
		if closeErr != nil {
			return out, fmt.Errorf("close MIME attachment: %w", closeErr)
		}
		out = append(out, Observation{Source: "SMTP", Filename: name, ContentType: p.Header.Get("Content-Type"), Content: b, TotalBytes: uint64(len(b)), Truncated: int64(len(b)) > max})
	}
	return out, nil
}
