package offline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

type constructorResult struct {
	builder *Builder
	err     error
}

// The existing admission/registry locks let these tests stop a constructor at
// an actual filesystem boundary without adding production fault hooks.
func waitConstructorDirectory(t *testing.T, parent string, previous map[string]bool, ready func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(parent)
		require.NoError(t, err)
		for _, entry := range entries {
			if !entry.IsDir() || previous[entry.Name()] || !strings.HasPrefix(entry.Name(), "lippycat-offline-") {
				continue
			}
			path := filepath.Join(parent, entry.Name())
			if ready(path) {
				return path
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("constructor did not reach its filesystem boundary")
	return ""
}

func receiveConstructor(t *testing.T, done <-chan constructorResult) constructorResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("constructor did not return after releasing its boundary lock")
		return constructorResult{}
	}
}

func TestBuilderConstructorFailedCleanupRetainsRetryOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires filesystem permissions to deny directory writes")
	}
	s := newTestStorage(t)
	s.mu.Lock()
	locked := true
	done := make(chan constructorResult, 1)
	go func() {
		builder, err := s.NewBuilder(1, []SourcePosition{{Path: "retained-source"}})
		done <- constructorResult{builder, err}
	}()
	var result *constructorResult
	var dir string
	defer func() {
		if locked {
			s.mu.Unlock()
		}
		if result == nil {
			value := receiveConstructor(t, done)
			result = &value
		}
		if dir != "" {
			require.NoError(t, os.Chmod(dir, 0700))
		}
		if result.builder != nil {
			require.NoError(t, result.builder.Close())
		}
		require.NoError(t, s.Close())
	}()
	dir = waitConstructorDirectory(t, s.limits.Directory, nil, func(path string) bool {
		_, err := os.Stat(filepath.Join(path, "summaries"))
		return err == nil
	})
	// The summaries descriptor is already open, but its first disk reservation
	// is blocked. It can write its header; opening details and removing the
	// nonempty directory will both fail after write permission is withdrawn.
	require.NoError(t, os.Chmod(dir, 0500))
	s.mu.Unlock()
	locked = false
	value := receiveConstructor(t, done)
	result = &value
	require.ErrorIs(t, value.err, os.ErrPermission)
	require.NotNil(t, value.builder, "failed removal must retain its cleanup owner")
	require.EqualValues(t, streamHeaderBytes, s.Resources().DiskBytes)
	require.Empty(t, value.builder.sources)
	require.Nil(t, value.builder.accumulator)
	require.Error(t, value.builder.Append(context.Background(), Detail{}))
	dataset, err := value.builder.Finish(context.Background())
	require.Error(t, err)
	require.Nil(t, dataset)
	require.Error(t, s.Close(), "charged metadata remains owned until cleanup succeeds")
	require.NoError(t, os.Chmod(dir, 0700))
	require.NoError(t, value.builder.Close())
	require.NoError(t, value.builder.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
	_, err = os.Stat(dir)
	require.True(t, os.IsNotExist(err))
	dir = ""
}

func TestCompactConstructorsFailedCleanupRetainRetryOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires filesystem permissions to deny directory writes")
	}
	for _, kind := range []string{"completed", "base", "revision"} {
		t.Run(kind, func(t *testing.T) {
			var s *Storage
			var registry *BackingRegistry
			var base *diskDataset
			var sources []SourcePosition
			if kind == "revision" {
				s, base, _, _ = normalizedRevisionFixture(t, BackingSnapshot, false, false)
				registry = base.compact.registry
				sources = base.compact.sources
			} else {
				var path string
				s, registry, path = backingFixture(t)
				input, err := registry.Open(context.Background(), path, 0, BackingSnapshot, false)
				require.NoError(t, err)
				require.NoError(t, input.Close())
				sources = []SourcePosition{{Path: path}}
			}
			decode := func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
				packet := summary.DisplayFields()
				packet.RawData = raw
				return packet, ctx.Err()
			}
			before := s.Resources()
			previous := make(map[string]bool)
			entries, err := os.ReadDir(s.limits.Directory)
			require.NoError(t, err)
			for _, entry := range entries {
				previous[entry.Name()] = true
			}
			registry.mu.Lock()
			locked := true
			previousFailure := registry.failure
			owners := registry.compactOwners
			done := make(chan constructorResult, 1)
			go func() {
				var builder *Builder
				var err error
				switch kind {
				case "completed":
					builder, err = s.NewCompactBuilder(7, sources, registry, decode)
				case "base":
					builder, err = s.NewCompactBaseBuilder(7, sources, registry)
				case "revision":
					builder, err = s.NewCompactRevisionBuilder(base, CompletedRevision, decode)
				}
				done <- constructorResult{builder, err}
			}()
			var result *constructorResult
			var dir string
			defer func() {
				if locked {
					registry.mu.Unlock()
				}
				if result == nil {
					value := receiveConstructor(t, done)
					result = &value
				}
				registry.mu.Lock()
				registry.failure = previousFailure
				registry.mu.Unlock()
				if dir != "" {
					require.NoError(t, os.Chmod(dir, 0700))
				}
				if result.builder != nil {
					require.NoError(t, result.builder.Close())
				}
			}()
			dir = waitConstructorDirectory(t, s.limits.Directory, previous, func(path string) bool {
				for _, name := range []string{"summaries", "details", "offsets"} {
					info, err := os.Stat(filepath.Join(path, name))
					if err != nil || info.Size() != compactHeaderBytes {
						return false
					}
				}
				return true
			})
			// All compact headers exist; retainCompact cannot proceed while its
			// lock is held. Fail that ownership handoff and the first removal.
			require.NoError(t, os.Chmod(dir, 0500))
			unavailable := errors.New("source owner became unavailable during construction")
			registry.failure = unavailable
			registry.mu.Unlock()
			locked = false
			value := receiveConstructor(t, done)
			result = &value
			require.ErrorIs(t, value.err, unavailable)
			require.ErrorIs(t, value.err, os.ErrPermission)
			require.NotNil(t, value.builder, "constructor layers must preserve failed cleanup ownership")
			require.Nil(t, value.builder.d.compact, "failed handoff must not claim a backing lease")
			require.Empty(t, value.builder.sources)
			require.Nil(t, value.builder.accumulator)
			require.Equal(t, before.DiskBytes+3*compactHeaderBytes, s.Resources().DiskBytes)
			require.Equal(t, before.InFlightBytes, s.Resources().InFlightBytes, "source memory reservation is released on failure")
			registry.mu.Lock()
			currentOwners := registry.compactOwners
			registry.failure = previousFailure
			registry.mu.Unlock()
			require.Equal(t, owners, currentOwners)
			require.NoError(t, registry.Validate(), "constructor failure must not transfer the source owner")
			if base != nil {
				detail, err := base.Detail(context.Background(), Token{Dataset: base.Generation(), Revision: BaseRevision}, 0)
				require.NoError(t, err)
				require.Equal(t, []byte{0, 1}, detail.Packet.RawData)
			}
			require.Error(t, value.builder.AppendCompact(context.Background(), Detail{}, PacketProvenance{}))
			dataset, err := value.builder.Finish(context.Background())
			require.Error(t, err)
			require.Nil(t, dataset)
			require.NoError(t, os.Chmod(dir, 0700))
			require.NoError(t, value.builder.Close())
			require.NoError(t, value.builder.Close())
			require.Equal(t, before.DiskBytes, s.Resources().DiskBytes)
			require.Equal(t, before.InFlightBytes, s.Resources().InFlightBytes)
			_, err = os.Stat(dir)
			require.True(t, os.IsNotExist(err))
			dir = ""
			if base != nil {
				require.NoError(t, base.Close())
			}
			require.NoError(t, registry.Close())
			require.NoError(t, s.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}
