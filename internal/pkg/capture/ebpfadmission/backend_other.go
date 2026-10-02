//go:build !linux

package ebpfadmission

import (
	"context"
	"errors"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"net/netip"
)

var ErrUnsupported = errors.New("RTP eBPF admission requires Linux")

type Backend struct{}

func NewBackend(Options) (*Backend, error)                                     { return nil, ErrUnsupported }
func (*Backend) Close() error                                                  { return nil }
func (*Backend) PutEndpoint(context.Context, mediaadmission.EndpointKey) error { return ErrUnsupported }
func (*Backend) DeleteEndpoint(context.Context, mediaadmission.EndpointKey) error {
	return ErrUnsupported
}
func (*Backend) ListEndpoints(context.Context, mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	return nil, ErrUnsupported
}
func (*Backend) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return ErrUnsupported
}
func (*Backend) ReplaceSelectors(context.Context, mediaadmission.DomainID, []netip.Prefix, bool) error {
	return ErrUnsupported
}
