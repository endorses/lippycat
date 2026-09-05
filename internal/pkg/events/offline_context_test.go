package events

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineIdentityContextParityAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, bytes.Repeat([]byte("capture"), 20000), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := OfflineInputIdentity([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	got, err := OfflineInputIdentityContext(context.Background(), []string{path})
	if err != nil || got != legacy {
		t.Fatalf("identity mismatch: %q %q %v", legacy, got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OfflineInputIdentityContext(ctx, []string{path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v", err)
	}
	if _, err := OfflineInputIdentityContext(context.Background(), []string{t.TempDir()}); err == nil {
		t.Fatal("directory accepted as capture input")
	}
}

type cancellingIdentityReader struct {
	cancel context.CancelFunc
	reads  int
}

func (r *cancellingIdentityReader) Read(p []byte) (int, error) {
	r.reads++
	r.cancel()
	return len(p), nil
}

func TestOfflineIdentityReaderCancelsBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &cancellingIdentityReader{cancel: cancel}
	_, err := io.CopyBuffer(io.Discard, offlineIdentityReader{ctx: ctx, reader: source}, make([]byte, 64<<10))
	if !errors.Is(err, context.Canceled) || source.reads != 1 {
		t.Fatalf("reads=%d err=%v", source.reads, err)
	}
}
