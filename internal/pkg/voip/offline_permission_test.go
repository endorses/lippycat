//go:build cli || all

package voip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/stretchr/testify/require"
)

type permissionVIFManager struct {
	recordingVIFManager
	startErr, shutdownErr error
	starts, shutdowns     int
}

func (m *permissionVIFManager) Start() error    { m.starts++; return m.startErr }
func (m *permissionVIFManager) Shutdown() error { m.shutdowns++; return m.shutdownErr }

func TestOfflineVoIPPermissionFailureStopsBeforeReplay(t *testing.T) {
	previous := GetConfig()
	t.Cleanup(func() { SetConfig(previous) })
	cleanupErr := errors.New("mock manager cleanup failed")
	for _, count := range []int{1, 0} {
		for _, denied := range []struct {
			name string
			err  error
		}{
			{"capability", vinterface.ErrPermissionDenied},
			{"namespace", fmt.Errorf("enter namespace: %w", vinterface.ErrNetNSPermissionDenied)},
			{"kernel eperm", &os.SyscallError{Syscall: "ioctl", Err: syscall.EPERM}},
			{"kernel eacces", &os.PathError{Op: "open", Path: "/dev/net/tun", Err: syscall.EACCES}},
		} {
			for _, failure := range []string{"create", "partial create", "start", "start with cleanup failure", "partial create with cleanup failure"} {
				t.Run(fmt.Sprintf("count-%d/%s/%s", count, denied.name, failure), func(t *testing.T) {
					dir := t.TempDir()
					cfg := DefaultConfig()
					cfg.WriteVoIP = true
					cfg.OutputFile = filepath.Join(dir, "capture.pcap")
					cfg.VirtualInterface = true
					SetConfig(cfg)
					manager := &permissionVIFManager{}
					if failure == "start" || failure == "start with cleanup failure" {
						manager.startErr = denied.err
					}
					if failure == "start with cleanup failure" || failure == "partial create with cleanup failure" {
						manager.shutdownErr = cleanupErr
					}
					factoryCalls, passes := 0, 0
					err := startVoipSessionWithManager(context.Background(), nil, "", true, capture.OfflineReplayOptions{
						Count: count,
						BeforePass: func(uint64) error {
							passes++
							return errors.New("replay must not begin after permission failure")
						},
					}, func(vinterface.Config) (vinterface.Manager, error) {
						factoryCalls++
						switch failure {
						case "create":
							return nil, denied.err
						case "partial create", "partial create with cleanup failure":
							return manager, denied.err
						default:
							return manager, nil
						}
					})
					require.ErrorIs(t, err, denied.err)
					require.True(t, vinterface.IsPermissionDenied(err))
					require.Equal(t, 1, factoryCalls)
					require.Zero(t, passes)
					require.Empty(t, manager.packets)
					files, globErr := filepath.Glob(filepath.Join(dir, "*.pcap"))
					require.NoError(t, globErr)
					require.Empty(t, files, "no packet output is created after permission failure")
					if failure == "create" {
						require.Zero(t, manager.starts)
						require.Zero(t, manager.shutdowns)
					} else {
						require.Equal(t, 1, manager.shutdowns)
						if failure != "partial create" && failure != "partial create with cleanup failure" {
							require.Equal(t, 1, manager.starts)
						}
					}
					if failure == "start with cleanup failure" || failure == "partial create with cleanup failure" {
						require.ErrorIs(t, err, cleanupErr)
					}
				})
			}
		}
	}
}

func TestOfflineVoIPOtherVirtualInterfaceFailureKeepsFallback(t *testing.T) {
	previous := GetConfig()
	cfg := DefaultConfig()
	cfg.VirtualInterface = true
	SetConfig(cfg)
	t.Cleanup(func() { SetConfig(previous) })
	stopPass := errors.New("test pass reached")
	for _, failure := range []string{"create", "start"} {
		t.Run(failure, func(t *testing.T) {
			manager := &permissionVIFManager{startErr: vinterface.ErrInterfaceExists}
			passes := 0
			err := startVoipSessionWithManager(context.Background(), nil, "", true, capture.OfflineReplayOptions{
				Count:      1,
				BeforePass: func(uint64) error { passes++; return stopPass },
			}, func(vinterface.Config) (vinterface.Manager, error) {
				if failure == "create" {
					return nil, vinterface.ErrInterfaceExists
				}
				return manager, nil
			})
			require.ErrorIs(t, err, stopPass)
			require.Equal(t, 1, passes)
			if failure == "start" {
				require.Equal(t, 1, manager.shutdowns)
			}
		})
	}
}
