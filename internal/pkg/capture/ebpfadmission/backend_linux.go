//go:build linux

// Package ebpfadmission owns shared socket-filter maps. It never owns capture FDs.
package ebpfadmission

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"golang.org/x/net/bpf"
)

type Backend struct {
	controlMu sync.Mutex
	mu        sync.RWMutex
	maps      map[string]*ebpf.Map
	spec      *ebpf.CollectionSpec
	opts      Options
	controls  map[mediaadmission.DomainID]kernelControl
}
type endpoint struct {
	Domain  uint32
	Address [16]byte
	Port    uint16
	Family  uint8
	Pad     uint8
}
type address struct {
	Domain  uint32
	Family  uint8
	Pad     [3]byte
	Address [16]byte
}
type prefix struct {
	Bits    uint32
	Address address
}
type kernelControl struct {
	Generation uint64
	Mode       uint32
	NoFilters  uint32
}

func NewBackend(opts Options) (*Backend, error) {
	opts.SIPPorts = append([]uint16(nil), opts.SIPPorts...)
	opts.RTPPortRanges = append([]PortRange(nil), opts.RTPPortRanges...)
	if opts.EndpointCapacity == 0 || opts.SelectorCapacity == 0 || opts.Domains == 0 || opts.Domains > 4096 {
		return nil, fmt.Errorf("invalid eBPF map capacity/domain count")
	}
	if opts.EvidenceBytes < 4096 || opts.EvidenceBytes&(opts.EvidenceBytes-1) != 0 {
		return nil, fmt.Errorf("evidence bytes must be a power of two at least 4096")
	}
	spec, err := loadAdmission()
	if err != nil {
		return nil, fmt.Errorf("load embedded admission object: %w", err)
	}
	spec.Maps["endpoints"].MaxEntries = opts.EndpointCapacity
	spec.Maps["addresses"].MaxEntries = opts.SelectorCapacity
	spec.Maps["prefixes"].MaxEntries = opts.SelectorCapacity
	spec.Maps["controls"].MaxEntries = opts.Domains
	spec.Maps["counters"].MaxEntries = opts.Domains * 16
	spec.Maps["decisions"].MaxEntries = opts.EvidenceBytes
	b := &Backend{maps: make(map[string]*ebpf.Map), spec: spec, opts: opts, controls: make(map[mediaadmission.DomainID]kernelControl)}
	for _, name := range []string{"endpoints", "addresses", "prefixes", "controls", "counters", "decisions", "port_policy"} {
		m, e := ebpf.NewMap(spec.Maps[name])
		if e != nil {
			return nil, errors.Join(fmt.Errorf("create %s map: %w", name, e), b.Close())
		}
		b.maps[name] = m
	}
	// Prepopulate controls separately from endpoint capacity. Hash replacement
	// publishes the whole mode/generation value, avoiding torn array-value reads.
	for domain := uint32(0); domain < opts.Domains; domain++ {
		if err := b.maps["controls"].Update(domain, kernelControl{}, ebpf.UpdateNoExist); err != nil {
			return nil, errors.Join(fmt.Errorf("initialize domain control: %w", err), b.Close())
		}
	}

	ports := make(map[uint32]uint32)
	if opts.SIPPort != 0 {
		opts.SIPPorts = append(opts.SIPPorts, opts.SIPPort)
		b.opts.SIPPorts = opts.SIPPorts
	}
	for _, p := range opts.SIPPorts {
		if p == 0 {
			return nil, errors.Join(fmt.Errorf("invalid SIP port zero"), b.Close())
		}
		ports[uint32(p)] |= 1
	}
	for _, r := range opts.RTPPortRanges {
		if r.Start == 0 || r.End < r.Start {
			return nil, errors.Join(fmt.Errorf("invalid RTP range"), b.Close())
		}
		for p := uint32(r.Start); p <= uint32(r.End); p++ {
			ports[p] |= 2
		}
	}
	for p, flags := range ports {
		if err := b.maps["port_policy"].Update(p, flags, ebpf.UpdateExist); err != nil {
			return nil, errors.Join(fmt.Errorf("initialize port policy: %w", err), b.Close())
		}
	}
	return b, nil
}
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var errs []error
	for name, m := range b.maps {
		if err := m.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", name, err))
		}
		delete(b.maps, name)
	}
	return errors.Join(errs...)
}
func pack(e mediaadmission.EndpointKey) (endpoint, error) {
	e, err := mediaadmission.NewEndpoint(e.Domain, e.Addr, e.Port)
	if err != nil {
		return endpoint{}, err
	}
	k := endpoint{Domain: uint32(e.Domain), Port: e.Port, Family: 6}
	if e.Addr.Is4() {
		a := e.Addr.As4()
		copy(k.Address[:], a[:])
		k.Family = 4
	} else {
		k.Address = e.Addr.As16()
	}
	return k, nil
}
func unpack(k endpoint) mediaadmission.EndpointKey {
	a := netip.AddrFrom16(k.Address)
	if k.Family == 4 {
		a = netip.AddrFrom4([4]byte(k.Address[:4]))
	}
	return mediaadmission.EndpointKey{Domain: mediaadmission.DomainID(k.Domain), Addr: a, Port: k.Port}
}
func (b *Backend) PutEndpoint(ctx context.Context, e mediaadmission.EndpointKey) error {
	if err := b.readLock(); err != nil {
		return err
	}
	defer b.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	k, err := pack(e)
	if err != nil {
		return err
	}
	return b.maps["endpoints"].Update(k, uint8(1), ebpf.UpdateAny)
}
func (b *Backend) DeleteEndpoint(ctx context.Context, e mediaadmission.EndpointKey) error {
	if err := b.readLock(); err != nil {
		return err
	}
	defer b.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	k, err := pack(e)
	if err != nil {
		return err
	}
	err = b.maps["endpoints"].Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
func (b *Backend) ListEndpoints(ctx context.Context, d mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	if err := b.readLock(); err != nil {
		return nil, err
	}
	defer b.mu.RUnlock()
	var out []mediaadmission.EndpointKey
	it := b.maps["endpoints"].Iterate()
	var k endpoint
	var v uint8
	for it.Next(&k, &v) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if k.Domain == uint32(d) {
			out = append(out, unpack(k))
		}
	}
	return out, it.Err()
}
func (b *Backend) SetControl(ctx context.Context, d mediaadmission.DomainID, c mediaadmission.Control) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if uint32(d) >= b.opts.Domains {
		return fmt.Errorf("domain %d outside preallocated control map", d)
	}
	if err := b.readLock(); err != nil {
		return err
	}
	defer b.mu.RUnlock()
	b.controlMu.Lock()
	defer b.controlMu.Unlock()
	if b.maps["controls"] == nil {
		return mediaadmission.ErrClosed
	}
	v := b.controls[d]
	v.Mode = uint32(c.Mode)
	v.Generation = c.Generation
	if err := b.maps["controls"].Update(uint32(d), v, ebpf.UpdateExist); err != nil {
		return err
	}
	b.controls[d] = v
	return nil
}

// ReplaceSelectors must be called while this domain is degraded or stopped. The
// caller restores enforcement only after complete selector/endpoint reconciliation.
func (b *Backend) ReplaceSelectors(ctx context.Context, d mediaadmission.DomainID, selectors []netip.Prefix, noFilters bool) error {
	if err := b.readLock(); err != nil {
		return err
	}
	defer b.mu.RUnlock()
	b.controlMu.Lock()
	defer b.controlMu.Unlock()
	if b.maps["controls"] == nil {
		return mediaadmission.ErrClosed
	}
	if uint32(d) >= b.opts.Domains {
		return fmt.Errorf("unknown domain %d", d)
	}
	if len(selectors) > int(b.opts.SelectorCapacity) {
		return fmt.Errorf("selector capacity exceeded")
	}
	for _, p := range selectors {
		if !p.IsValid() || p.Addr().Is4In6() {
			return fmt.Errorf("invalid or mapped selector %s", p)
		}
	}
	var ak address
	var pk prefix
	var value uint8
	ai := b.maps["addresses"].Iterate()
	var addresses []address
	for ai.Next(&ak, &value) {
		if ak.Domain == uint32(d) {
			addresses = append(addresses, ak)
		}
	}
	if err := ai.Err(); err != nil {
		return err
	}
	pi := b.maps["prefixes"].Iterate()
	var prefixes []prefix
	for pi.Next(&pk, &value) {
		if pk.Address.Domain == uint32(d) {
			prefixes = append(prefixes, pk)
		}
	}
	if err := pi.Err(); err != nil {
		return err
	}
	for _, k := range addresses {
		if err := b.maps["addresses"].Delete(k); err != nil {
			return err
		}
	}
	for _, k := range prefixes {
		if err := b.maps["prefixes"].Delete(k); err != nil {
			return err
		}
	}
	for _, p := range selectors {
		if err := ctx.Err(); err != nil {
			return err
		}
		p = p.Masked()
		a := address{Domain: uint32(d), Family: 6, Address: p.Addr().As16()}
		if p.Addr().Is4() {
			a.Family = 4
			a.Address = [16]byte{}
			v := p.Addr().As4()
			copy(a.Address[:], v[:])
		}
		name := "prefixes"
		var key any = prefix{Bits: uint32(64 + p.Bits()), Address: a}
		if p.Bits() == p.Addr().BitLen() {
			name = "addresses"
			key = a
		}
		if err := b.maps[name].Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	c := b.controls[d]
	c.NoFilters = 0
	if noFilters {
		c.NoFilters = 1
	}
	if err := b.maps["controls"].Update(uint32(d), c, ebpf.UpdateExist); err != nil {
		return err
	}
	b.controls[d] = c
	return nil
}
func (b *Backend) NewProgram(d mediaadmission.DomainID, snaplen uint32, linkType uint32, filter []bpf.RawInstruction) (*ebpf.Program, error) {
	if err := b.readLock(); err != nil {
		return nil, err
	}
	defer b.mu.RUnlock()
	if linkType != 1 {
		return nil, fmt.Errorf("RTP eBPF requires Ethernet capture, link type %d is unsupported", linkType)
	}
	if uint32(d) >= b.opts.Domains || snaplen == 0 {
		return nil, fmt.Errorf("invalid domain or snap length")
	}
	spec := b.spec.Copy()
	esp := uint32(0)
	if b.opts.ESPEnabled {
		esp = 1
	}
	for name, value := range map[string]uint32{"domain": uint32(d), "capture_length": snaplen, "restrict_sip_ports": boolWord(len(b.opts.SIPPorts) > 0), "restrict_rtp_ports": boolWord(len(b.opts.RTPPortRanges) > 0), "udp_only": boolWord(b.opts.UDPOnly), "esp_enabled": esp, "shadow_sample_every": b.opts.ShadowSampleEvery} {
		if err := spec.Variables[name].Set(value); err != nil {
			return nil, err
		}
	}
	program := spec.Programs["admit"]
	if len(filter) > 0 {
		prefix, err := translate(filter, uint32(d))
		if err != nil {
			return nil, err
		}
		prefix[0].Metadata = program.Instructions[0].Metadata
		program.Instructions[0].Metadata = asm.Metadata{}
		program.Instructions = append(prefix, program.Instructions...)
	}
	// Load the rodata map and shared replacements through Collection to resolve ELF
	// constants and map references. Collection closes only its cloned map handles.
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: b.maps})
	if err != nil {
		return nil, fmt.Errorf("load socket admission program: %w", err)
	}
	p := collection.DetachProgram("admit")
	collection.Close()
	return p, nil
}
func DropProgram() (*ebpf.Program, error) {
	return ebpf.NewProgram(&ebpf.ProgramSpec{Name: "admit_startup", Type: ebpf.SocketFilter, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
}
func (b *Backend) Counters(d mediaadmission.DomainID) ([16]uint64, error) {
	if err := b.readLock(); err != nil {
		return [16]uint64{}, err
	}
	defer b.mu.RUnlock()
	var result [16]uint64
	for i := range result {
		var cpus []uint64
		if err := b.maps["counters"].Lookup(uint32(d)*16+uint32(i), &cpus); err != nil {
			return result, err
		}
		for _, v := range cpus {
			result[i] += v
		}
	}
	return result, nil
}
func (b *Backend) DecisionReader() (*ringbuf.Reader, error) {
	if err := b.readLock(); err != nil {
		return nil, err
	}
	defer b.mu.RUnlock()
	return ringbuf.NewReader(b.maps["decisions"])
}

func boolWord(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

func (b *Backend) readLock() error {
	b.mu.RLock()
	if b.maps["endpoints"] == nil {
		b.mu.RUnlock()
		return mediaadmission.ErrClosed
	}
	return nil
}
