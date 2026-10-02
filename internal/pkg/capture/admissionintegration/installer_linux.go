//go:build linux

// Package admissionintegration connects shared admission maps to libpcap sessions.
package admissionintegration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/ebpfadmission"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// Installer shares backend maps but owns only the programs of each prepared
// socket. The caller closes the backend after capture and controller shutdown.
type Installer struct {
	status       mediaadmission.StatusProvider
	backend      *ebpfadmission.Backend
	domains      map[string]mediaadmission.DomainID
	drainTimeout time.Duration
}

// NewInstaller snapshots interface-to-domain assignment. An empty assignment
// places every interface in domain zero; named assignments override that default.
func NewInstaller(backend *ebpfadmission.Backend, domains map[string]mediaadmission.DomainID, drainTimeout time.Duration) (*Installer, error) {
	if backend == nil {
		return nil, errors.New("socket admission backend is required")
	}
	if drainTimeout <= 0 {
		return nil, errors.New("socket admission drain timeout must be positive")
	}
	assignments := make(map[string]mediaadmission.DomainID, len(domains))
	for name, domain := range domains {
		assignments[name] = domain
	}
	return &Installer{backend: backend, domains: assignments, drainTimeout: drainTimeout}, nil
}

var vlanKeyword = regexp.MustCompile(`(?i)\bvlan\b`)

func (i *Installer) Prepare(ctx context.Context, handle *pcap.Handle, name, filter string) (capture.PreparedFilter, error) {
	// A live libpcap VLAN predicate can depend on ancillary offload metadata.
	// The supported translator does not yet reproduce those fixups.
	if vlanKeyword.MatchString(filter) {
		return nil, errors.New("explicit VLAN capture expressions are not supported by socket admission")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	domain := i.domains[name]
	// Compile only: never install classic BPF on this fresh handle. libpcap's
	// compile operation retains no userspace packet-filter state.
	compiled, err := handle.CompileBPFFilter(filter)
	if err != nil {
		return nil, errors.New("explicit capture restriction cannot be compiled for this interface")
	}
	raw := make([]bpf.RawInstruction, len(compiled))
	for j, instruction := range compiled {
		raw[j] = bpf.RawInstruction{Op: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	program, err := i.backend.NewProgram(domain, uint32(handle.SnapLen()), uint32(handle.LinkType()), raw)
	if err != nil {
		// A verifier report can contain selector literals in instruction dumps.
		return nil, errors.New("cannot load composed socket admission policy; check supported link type, kernel features, and BPF privileges")
	}
	prepared := &preparedFilter{handle: handle, program: program}
	fail := func(err error) (capture.PreparedFilter, error) { return nil, errors.Join(err, prepared.Close()) }
	prepared.drop, err = ebpfadmission.DropProgram()
	if err != nil {
		return fail(fmt.Errorf("load startup rejection program: %w", err))
	}
	if err := handle.SetSocketFilter(prepared.drop.FD()); err != nil {
		return fail(err)
	}
	drainCtx, cancel := context.WithTimeout(ctx, i.drainTimeout)
	defer cancel()
	if err := handle.DrainSocketBuffer(drainCtx); err != nil {
		return fail(err)
	}
	return prepared, nil
}

type preparedFilter struct {
	mu      sync.Mutex
	handle  *pcap.Handle
	program *ebpf.Program
	drop    *ebpf.Program
	closed  bool
	active  bool
}

func (p *preparedFilter) Activate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("socket admission attachment is closed")
	}
	if p.active {
		return nil
	}
	if err := p.handle.SetSocketFilter(p.program.FD()); err != nil {
		return err
	}
	p.active = true
	return nil
}

func (p *preparedFilter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var errs []error
	if p.drop != nil {
		errs = append(errs, p.drop.Close())
	}
	if p.program != nil {
		errs = append(errs, p.program.Close())
	}
	return errors.Join(errs...)
}

var _ capture.FilterInstaller = (*Installer)(nil)

func (i *Installer) CaptureScope(name string) uint32 { return uint32(i.domains[name]) }

var _ capture.FilterScopeProvider = (*Installer)(nil)

func (i *Installer) Status() mediaadmission.Snapshot {
	if i.status == nil {
		return mediaadmission.Snapshot{}
	}
	return i.status.Status()
}
