package offline

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func backingFixture(t *testing.T) (*Storage, *BackingRegistry, string) {
	t.Helper()
	s, err := NewStorage(ResourceLimits{Directory: t.TempDir(), DiskBytes: 1 << 20, CacheBytes: 1 << 20, MaxRecordBytes: 1 << 16, MaxSources: 4})
	if err != nil {
		t.Fatal(err)
	}
	r := s.NewBackingRegistry()
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, []byte("original packet content"), 0600); err != nil {
		t.Fatal(err)
	}
	return s, r, p
}
func TestBackingSourceOwnedHandle(t *testing.T) {
	for _, op := range []string{"rename", "replace", "unlink"} {
		t.Run(op, func(t *testing.T) {
			_, r, p := backingFixture(t)
			input, err := r.Open(context.Background(), p, 0, BackingSource, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			loc, err := r.Locator(input.ID, 0, []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			switch op {
			case "rename", "replace":
				err = os.Rename(p, p+".old")
				if err == nil && op == "replace" {
					err = os.WriteFile(p, []byte("replacement file"), 0600)
				}
			case "unlink":
				err = os.Remove(p)
			}
			if err != nil {
				t.Skipf("platform does not permit operation on open file: %v", err)
			}
			lease, err := r.Read(context.Background(), loc)
			if err != nil {
				t.Fatal(err)
			}
			if string(lease.Bytes) != "original" {
				t.Fatal("read replacement")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestBackingMutation(t *testing.T) {
	for _, mode := range []string{"truncate", "same-size", "restored-time"} {
		t.Run(mode, func(t *testing.T) {
			_, r, p := backingFixture(t)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			input, err := r.Open(context.Background(), p, 3, BackingSource, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			loc, err := r.Locator(input.ID, 0, []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "truncate" {
				err = os.Truncate(p, 2)
			} else {
				err = os.WriteFile(p, []byte("mutated! packet content"), 0600)
				if err == nil && mode == "restored-time" {
					err = os.Chtimes(p, info.ModTime(), info.ModTime())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			lease, err := r.Read(context.Background(), loc)
			if !errors.Is(err, ErrSourceChanged) || lease != nil {
				t.Fatalf("got %v %v", lease, err)
			}
			var change *SourceChangeError
			if !errors.As(err, &change) || change.SourceIndex != 3 {
				t.Fatal(err)
			}
			if mode == "restored-time" && change.Reason != "digest" {
				t.Fatal(change)
			}
		})
	}
}
func TestBackingSnapshotAndGzip(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{true: "gzip", false: "plain"}[compressed], func(t *testing.T) {
			s, r, p := backingFixture(t)
			raw := []byte("original packet content")
			original := raw
			if compressed {
				var out bytes.Buffer
				w := gzip.NewWriter(&out)
				if _, err := w.Write(raw); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				original = out.Bytes()
				if err := os.WriteFile(p, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			input, err := r.Open(context.Background(), p, 0, BackingSnapshot, false)
			if err != nil {
				t.Fatal(err)
			}
			if input.Digest != sha256.Sum256(original) {
				t.Fatal("wrong source identity")
			}
			if s.Resources().DiskBytes != uint64(len(raw)) {
				t.Fatal(s.Resources())
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			loc, err := r.Locator(input.ID, 0, raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			lease, err := r.Read(context.Background(), loc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(lease.Bytes, raw) {
				t.Fatal("snapshot changed")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestBackingLeaseShutdownAndBounds(t *testing.T) {
	s, r, _ := backingFixture(t)
	loc, err := r.AppendDerived(context.Background(), 0, []byte("derived"))
	if err != nil {
		t.Fatal(err)
	}
	bad := loc
	bad.Offset = 1 << 62
	if _, err := r.Read(context.Background(), bad); !errors.Is(err, ErrInvalidLocator) {
		t.Fatal(err)
	}
	lease, err := r.Read(context.Background(), loc)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case <-done:
		t.Fatal("closed pinned registry")
	case <-time.After(20 * time.Millisecond):
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease close did not unblock")
	}
	if s.Resources().DiskBytes != 0 || s.Resources().InFlightBytes != 0 {
		t.Fatal(s.Resources())
	}
}
func TestBackingFailedCopyAndCancelled(t *testing.T) {
	for _, kind := range []string{"budget", "cancel", "gzip"} {
		t.Run(kind, func(t *testing.T) {
			s, r, p := backingFixture(t)
			ctx := context.Background()
			switch kind {
			case "budget":
				s.limits.DiskBytes = 4
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "gzip":
				if err := os.WriteFile(p, []byte{0x1f, 0x8b, 0, 0}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.Open(ctx, p, 0, BackingSnapshot, false); err == nil {
				t.Fatal("expected error")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if s.Resources().DiskBytes != 0 || s.Resources().InFlightBytes != 0 {
				t.Fatal(s.Resources())
			}
		})
	}
}

func TestBackingCleanupRetryRetainsBudget(t *testing.T) {
	s, r, _ := backingFixture(t)
	if _, err := r.AppendDerived(context.Background(), 0, []byte("owned")); err != nil {
		t.Fatal(err)
	}
	scratch := r.entries[0].scratch
	actual := scratch.path
	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	scratch.path = blocked
	before := s.Resources()
	if err := r.Close(); err == nil {
		t.Fatal("expected cleanup failure")
	}
	if got := s.Resources(); got.DiskBytes != before.DiskBytes || got.InFlightBytes != before.InFlightBytes {
		t.Fatalf("released failed cleanup reservation: before=%+v after=%+v", before, got)
	}
	scratch.path = actual
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.Resources(); got.DiskBytes != 0 || got.InFlightBytes != 0 {
		t.Fatal(got)
	}
}

func TestBackingGzipChecksumAndScanLease(t *testing.T) {
	_, r, p := backingFixture(t)
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := out.Bytes()
	data[len(data)-8] ^= 1
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(context.Background(), p, 0, BackingSource, false); err == nil {
		t.Fatal("accepted bad gzip checksum")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, r, p = backingFixture(t)
	input, err := r.Open(context.Background(), p, 0, BackingSource, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case <-done:
		t.Fatal("closed active parser")
	case <-time.After(20 * time.Millisecond):
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("parser close did not release registry")
	}
}

func TestBackingSnapshotGzipPeakBudget(t *testing.T) {
	s, r, p := backingFixture(t)
	raw := bytes.Repeat([]byte("packet"), 100)
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// Either completed representation fits independently, but their mandatory
	// coexistence while validating decompression exceeds the shared disk budget.
	s.limits.DiskBytes = uint64(len(raw))
	if uint64(out.Len()) >= s.limits.DiskBytes {
		t.Fatal("fixture does not compress")
	}
	if _, err := r.Open(context.Background(), p, 0, BackingSnapshot, false); err == nil {
		t.Fatal("ignored compressed snapshot plus spool peak")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.Resources(); got.DiskBytes != 0 || got.InFlightBytes != 0 {
		t.Fatal(got)
	}
}

func TestBackingOriginalIdentityAndKinds(t *testing.T) {
	_, r, p := backingFixture(t)
	input, err := r.Open(context.Background(), p, 2, BackingSnapshot, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	desc, err := r.Describe(input.ID)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Kind != BackingKindSnapshot || desc.Source.SourceID != 3 || desc.Source.Info == nil || desc.Source.Info.Size() != desc.Source.Size {
		t.Fatalf("lost original metadata: %+v", desc)
	}
	loc, err := r.AppendDerived(context.Background(), 2, []byte("derived"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := r.Describe(loc.BackingID)
	if err != nil {
		t.Fatal(err)
	}
	if derived.Kind != BackingKindDerived || derived.Source != desc.Source {
		t.Fatalf("lost derived source identity: %+v", derived)
	}
}
