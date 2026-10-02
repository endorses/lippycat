//go:build !linux

package admissionintegration

import (
	"context"
	"errors"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func newSession(_ context.Context, config mediaadmission.Config, _ ...SessionOptions) (*Session, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Enabled {
		return nil, errors.New("RTP eBPF media admission requires Linux")
	}
	return &Session{Config: config}, nil
}
