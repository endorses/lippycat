package vinterface

import "errors"

var (
	// ErrPlatformUnsupported indicates the platform doesn't support virtual interfaces.
	ErrPlatformUnsupported = errors.New("virtual interfaces not supported on this platform")

	// ErrInvalidName indicates the interface name is invalid.
	ErrInvalidName = errors.New("invalid interface name")

	// ErrInvalidType indicates the interface type is invalid.
	ErrInvalidType = errors.New("invalid interface type (must be 'tap' or 'tun')")

	// ErrInvalidBufferSize indicates the buffer size is invalid.
	ErrInvalidBufferSize = errors.New("invalid buffer size (must be > 0)")

	// ErrInvalidMTU indicates the MTU is invalid.
	ErrInvalidMTU = errors.New("invalid MTU (must be 1-65535)")

	// ErrInterfaceExists indicates an interface with the same name already exists.
	ErrInterfaceExists = errors.New("interface already exists")

	// ErrPermissionDenied indicates insufficient privileges (CAP_NET_ADMIN required).
	ErrPermissionDenied = errors.New("permission denied: CAP_NET_ADMIN capability required")

	// ErrNotStarted indicates the manager hasn't been started.
	ErrNotStarted = errors.New("manager not started")

	// ErrAlreadyStarted indicates the manager is already started.
	ErrAlreadyStarted = errors.New("manager already started")

	// ErrShuttingDown indicates the manager is shutting down.
	ErrShuttingDown = errors.New("manager is shutting down")
)
