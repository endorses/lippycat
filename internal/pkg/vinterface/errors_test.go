package vinterface

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPermissionDenied(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"capability", ErrPermissionDenied, true},
		{"namespace", fmt.Errorf("switch namespace: %w", ErrNetNSPermissionDenied), true},
		{"os permission", os.ErrPermission, true},
		{"kernel eperm", fmt.Errorf("create TAP: %w", &os.SyscallError{Syscall: "ioctl", Err: syscall.EPERM}), true},
		{"kernel eacces", &os.PathError{Op: "open", Path: "/dev/net/tun", Err: syscall.EACCES}, true},
		{"joined", errors.Join(errors.New("cleanup failed"), fmt.Errorf("start: %w", ErrPermissionDenied)), true},
		{"other interface failure", ErrInterfaceExists, false},
		{"namespace absent", ErrNetNSNotFound, false},
		{"ordinary failure", errors.New("operation not permitted"), false},
		{"nil", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, IsPermissionDenied(test.err))
		})
	}
}
