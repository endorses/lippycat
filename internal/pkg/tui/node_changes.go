//go:build tui || all

package tui

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

// Registration originates at the parent; reconnect notifications can originate
// at the child itself. The envelope is therefore not always a parent identity.
func (m *Model) connectedNodeParent(source, origin string, node *management.ProcessorNode) string {
	addr := m.nodeProcessorAddress(node.Address)
	if parent := m.nodeProcessorAddress(node.UpstreamProcessor); parent != "" && parent != addr {
		return parent
	}
	if origin != "" && origin != addr && origin != node.ProcessorId {
		return origin
	}
	if existing := m.connectionMgr.Processors[addr]; existing != nil {
		if parent := m.nodeProcessorAddress(existing.UpstreamAddr); parent != "" && parent != addr {
			return parent
		}
	}
	if source = m.nodeProcessorAddress(source); source != addr {
		return source
	}
	return ""
}

// nodeProcessorAddress resolves topology processor IDs at the model boundary.
func (m *Model) nodeProcessorAddress(identity string) string {
	if _, ok := m.connectionMgr.Processors[identity]; ok {
		return identity
	}
	for addr, p := range m.connectionMgr.Processors {
		if identity != "" && p.ProcessorID == identity {
			return addr
		}
	}
	return identity
}

func (m *Model) nodeWithinSource(addr, source string) bool {
	seen := make(map[string]bool)
	for addr != "" && !seen[addr] {
		if addr == source {
			return true
		}
		seen[addr] = true
		p := m.connectionMgr.Processors[addr]
		if p == nil {
			return false
		}
		addr = m.nodeProcessorAddress(p.UpstreamAddr)
	}
	return false
}

// Status responses may aggregate descendants without carrying their owning
// processor. Resolve only an unambiguous identity in the reporting subtree;
// never let a matching ID on another root overwrite that hunter's metrics.
func (m *Model) hunterStatusOwner(source string, h components.HunterInfo) (string, bool) {
	source = m.nodeProcessorAddress(source)
	owner := m.nodeProcessorAddress(h.ProcessorAddr)
	if owner != "" && owner != "Direct" && owner != source && m.nodeWithinSource(owner, source) {
		return owner, true
	}
	var candidates, addressMatches []string
	for addr, hunters := range m.connectionMgr.HuntersByProcessor {
		if !m.nodeWithinSource(addr, source) {
			continue
		}
		for _, existing := range hunters {
			if existing.ID != h.ID {
				continue
			}
			candidates = append(candidates, addr)
			if h.RemoteAddr != "" && existing.RemoteAddr == h.RemoteAddr {
				addressMatches = append(addressMatches, addr)
			}
			break
		}
	}
	if len(addressMatches) == 1 {
		return addressMatches[0], true
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	if len(candidates) > 1 {
		return "", false
	}
	return source, true
}

func (m *Model) nodeHunterVisible(owner, id string) bool {
	p := m.connectionMgr.Processors[owner]
	if p == nil {
		return false
	}
	if p.SubscribedHunters == nil {
		return true
	}
	for _, subscribed := range p.SubscribedHunters {
		if subscribed == id {
			return true
		}
	}
	return false
}

func (m *Model) nodeSourceEstablished(addr string) bool {
	p := m.connectionMgr.Processors[m.nodeProcessorAddress(addr)]
	return p != nil && p.State == store.ProcessorStateConnected
}
