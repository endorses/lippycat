package admissionintegration

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// Session owns a process's shared admission maps/controller. Call Close only
// after capture readers and SIP lifecycle producers have stopped.
type PortRange struct{ Start, End uint16 }
type SessionOptions struct {
	SIPPorts      []uint16
	RTPPortRanges []PortRange
	UDPOnly       bool
	ESPEnabled    bool
}

func NewSession(ctx context.Context, config mediaadmission.Config, options ...SessionOptions) (*Session, error) {
	return newSession(ctx, config, options...)
}
func New(ctx context.Context, config mediaadmission.Config) (*Session, error) {
	return newSession(ctx, config)
}

type Session struct {
	telemetry    *sessionTelemetry
	Config       mediaadmission.Config
	Controller   *mediaadmission.Controller
	Metadata     *mediaadmission.MetadataStore
	installer    capture.FilterInstaller
	closeBackend func() error
	cancel       context.CancelFunc
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

func (s *Session) Installer() capture.FilterInstaller { return s.installer }

// UpdateSelectors publishes the same independent packet selectors in every
// observation domain. Domain isolation concerns endpoint/call identity, not the
// processor's configured packet-filter policy.
func (s *Session) UpdateSelectors(ctx context.Context, selectors []netip.Prefix, noFilters bool) error {
	if !s.Config.Enabled {
		return nil
	}
	var errs []error
	for _, domain := range s.Config.Domains() {
		if err := s.Controller.ReplaceSelectors(ctx, domain, selectors, noFilters); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (s *Session) start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(s.Config.RetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Metadata.Expire(time.Now())
				s.logTransitions()
				for _, domain := range s.Config.Domains() {
					// Controller status records each failure and the effective mode;
					// periodic retries must not emit one log per failed endpoint.
					if err := s.Controller.Reconcile(ctx, domain); err != nil {
						logger.Debug("Admission reconciliation remains incomplete", "domain", domain)
					}
				}
			}
		}
	}()
}
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
			<-s.done
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.Controller != nil {
			s.closeErr = s.Controller.Close(ctx)
		}
		s.closeErr = errors.Join(s.closeErr, s.closeTelemetry())
		if s.closeBackend != nil {
			s.closeErr = errors.Join(s.closeErr, s.closeBackend())
		}
	})
	return s.closeErr
}
