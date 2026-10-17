package failover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// Exclusions tracks numeric transport peers. A TCP transport on port 443 must
// not exclude other hosts' HTTPS or UDP traffic on the same port.
type Exclusions struct {
	mu      sync.Mutex
	peers   map[string][]netip.Addr
	listen  []string
	Resolve func(context.Context, string) ([]netip.Addr, error)
}

func NewExclusions(listen string, endpoints []Endpoint) (*Exclusions, error) {
	e := &Exclusions{peers: make(map[string][]netip.Addr), Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
	for _, endpoint := range endpoints {
		host, _, err := net.SplitHostPort(endpoint.Address)
		if err != nil {
			return nil, err
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			e.peers[endpoint.Address] = []netip.Addr{ip.Unmap().WithZone("")}
		}
	}
	if listen != "" {
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, fmt.Errorf("listen capture exclusion: %w", err)
		}
		ip, parseErr := netip.ParseAddr(host)
		if host == "" || parseErr == nil && ip.IsUnspecified() {
			addresses, err := net.InterfaceAddrs()
			if err != nil {
				return nil, fmt.Errorf("local capture exclusions: %w", err)
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil {
					e.listen = append(e.listen, fmt.Sprintf("(tcp and host %s and port %s)", prefix.Addr().Unmap().WithZone(""), port))
				}
			}
		} else if parseErr == nil {
			e.listen = append(e.listen, fmt.Sprintf("(tcp and host %s and port %s)", ip.Unmap().WithZone(""), port))
		} else if host == "localhost" {
			e.listen = append(e.listen, fmt.Sprintf("(tcp and host 127.0.0.1 and port %s)", port), fmt.Sprintf("(tcp and host ::1 and port %s)", port))
		} else {
			return nil, fmt.Errorf("listen capture exclusion requires a numeric address or localhost")
		}
	}
	return e, nil
}

func (e *Exclusions) filter() string {
	clauses := append([]string(nil), e.listen...)
	for address, ips := range e.peers {
		_, port, _ := net.SplitHostPort(address)
		for _, ip := range ips {
			clauses = append(clauses, fmt.Sprintf("(tcp and host %s and port %s)", ip, port))
		}
	}
	sort.Strings(clauses)
	unique := clauses[:0]
	for _, clause := range clauses {
		if len(unique) == 0 || clause != unique[len(unique)-1] {
			unique = append(unique, clause)
		}
	}
	if len(unique) == 0 {
		return ""
	}
	return "not (" + strings.Join(unique, " or ") + ")"
}
func (e *Exclusions) Filter() string { e.mu.Lock(); defer e.mu.Unlock(); return e.filter() }

func (e *Exclusions) Prepare(ctx context.Context, endpoint Endpoint, apply func(string) error) error {
	host, _, err := net.SplitHostPort(endpoint.Address)
	if err != nil {
		return err
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = e.Resolve(ctx, host)
		if err != nil {
			return fmt.Errorf("resolve capture exclusion: %w", err)
		}
	}
	var normalized []netip.Addr
	for _, ip := range addresses {
		if ip.IsValid() {
			normalized = append(normalized, ip.Unmap().WithZone(""))
		}
	}
	if len(normalized) == 0 {
		return fmt.Errorf("capture exclusion peer resolved no addresses")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	previous := e.peers[endpoint.Address]
	before := e.filter()
	e.peers[endpoint.Address] = normalized
	after := e.filter()
	if before != after && apply != nil {
		if err := apply(after); err != nil {
			e.peers[endpoint.Address] = previous
			return fmt.Errorf("apply transport capture exclusion: %w", err)
		}
	}
	return nil
}
