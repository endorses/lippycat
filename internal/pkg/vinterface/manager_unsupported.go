//go:build !linux

package vinterface

import (
	"github.com/endorses/lippycat/internal/pkg/types"
)

// unsupportedManager is a stub for platforms that don't support virtual interfaces.
type unsupportedManager struct {
	config Config
}

// NewManager returns an error on unsupported platforms.
func NewManager(config Config) (Manager, error) {
	return &unsupportedManager{config: config}, nil
}

func (m *unsupportedManager) Name() string {
	return m.config.Name
}

func (m *unsupportedManager) Start() error {
	return ErrPlatformUnsupported
}

func (m *unsupportedManager) InjectPacket(packet []byte) error {
	return ErrPlatformUnsupported
}

func (m *unsupportedManager) InjectPacketBatch(packets []types.PacketDisplay) error {
	return ErrPlatformUnsupported
}

func (m *unsupportedManager) Shutdown() error {
	return nil // No-op on unsupported platforms
}

func (m *unsupportedManager) Stats() Stats {
	return Stats{}
}
