package filtering

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/phonematcher"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"google.golang.org/protobuf/proto"
)

var (
	ErrSIPFilter = errors.New("invalid SIP filter snapshot")
	ErrSIPSource = errors.New("SIP matching requires an authenticated capture source")
	ErrSIPEvent  = errors.New("invalid normalized SIP event")
)

type compiledSIPFilter struct {
	id          string
	kind        management.FilterType
	local       bool
	targets     []string
	pattern     string
	patternType PatternType
	phoneSuffix bool
	prefix      netip.Prefix
	address     netip.Addr
}

// SIPMatcher is an immutable snapshot of currently enabled SIP/phone/IP filters.
// It can be shared across packet workers. Recompile and swap it when managed
// policy changes; matching never relies on filter IDs supplied by a hunter.
// The shared managed-filter limits bound compilation; no capture backend or
// output-specific package is required in processor-only builds.
type SIPMatcher struct {
	filters []compiledSIPFilter
	hasIP   bool
}

// CompileSIPFilters prepares patterns and IP ranges once. Unsupported filter
// families do not select SIP calls. Call-ID selectors match exact case-sensitive
// opaque IDs; SIP identity patterns retain the hunter's contains/edge semantics.
// Caller-owned protobufs are never retained.
func CompileSIPFilters(filters []*management.Filter) (*SIPMatcher, error) {
	if len(filters) > MaxManagedFilters {
		return nil, fmt.Errorf("%w: filter count limit exceeded", ErrSIPFilter)
	}
	matcher := &SIPMatcher{}
	seen := make(map[string]struct{}, len(filters))
	bytes := 0
	targets := 0
	for _, filter := range filters {
		if filter == nil {
			return nil, fmt.Errorf("%w: nil filter", ErrSIPFilter)
		}
		if !filter.Enabled || !sipFilterKind(filter.Type) {
			continue
		}
		if len(filter.TargetHunters) > maxManagedTotalHunters-targets {
			return nil, fmt.Errorf("%w: target count limit exceeded", ErrSIPFilter)
		}
		targets += len(filter.TargetHunters)
		size := proto.Size(filter)
		if size > MaxManagedSnapshotBytes-bytes {
			return nil, fmt.Errorf("%w: snapshot byte limit exceeded", ErrSIPFilter)
		}
		bytes += size
		if err := ValidateManagedFilter(filter); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSIPFilter, err)
		}
		if _, duplicate := seen[filter.Id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate filter identifier", ErrSIPFilter)
		}
		seen[filter.Id] = struct{}{}
		compiled := compiledSIPFilter{id: strings.Clone(filter.Id), kind: filter.Type, local: !IsDistributedFilter(filter)}
		compiled.targets = make([]string, len(filter.TargetHunters))
		for i, target := range filter.TargetHunters {
			compiled.targets[i] = strings.Clone(target)
		}
		pattern := filter.Pattern
		if filter.Type == management.FilterType_FILTER_PHONE_NUMBER {
			pattern = NormalizePhonePattern(pattern)
		}
		compiled.pattern, compiled.patternType = ParsePattern(pattern)
		// Pre-fold patterns; Match's edge/contains semantics remain unchanged.
		compiled.pattern = strings.Clone(strings.ToLower(compiled.pattern))
		compiled.phoneSuffix = filter.Type == management.FilterType_FILTER_PHONE_NUMBER && compiled.patternType == PatternTypeContains && phonematcher.IsDigitsOnly(compiled.pattern)
		switch filter.Type {
		case management.FilterType_FILTER_IP_ADDRESS:
			matcher.hasIP = true
			if prefix, err := netip.ParsePrefix(filter.Pattern); err == nil {
				compiled.prefix = prefix.Masked()
				if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
					compiled.prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
				}
			} else if address, err := netip.ParseAddr(filter.Pattern); err == nil {
				compiled.address = address.Unmap()
			} else {
				return nil, fmt.Errorf("%w: invalid IP selector", ErrSIPFilter)
			}
		case management.FilterType_FILTER_CALL_ID:
			// Call-ID is opaque and case-sensitive. It is an exact call selector,
			// independent of wildcard SIP identity/phone matching.
			compiled.pattern = strings.Clone(filter.Pattern)
		}
		matcher.filters = append(matcher.filters, compiled)
	}
	return matcher, nil
}

func sipFilterKind(kind management.FilterType) bool {
	switch kind {
	case management.FilterType_FILTER_SIP_USER, management.FilterType_FILTER_SIP_URI, management.FilterType_FILTER_PHONE_NUMBER, management.FilterType_FILTER_IP_ADDRESS, management.FilterType_FILTER_CALL_ID:
		return true
	default:
		return false
	}
}

// MatchSIP is a convenience for one-off policy snapshots. High-volume callers
// should compile once per policy revision and use SIPMatcher.Match instead.
func MatchSIP(event sip.Event, filters []*management.Filter, sourceID string) ([]string, error) {
	matcher, err := CompileSIPFilters(filters)
	if err != nil {
		return nil, err
	}
	return matcher.Match(event, sourceID)
}

// Match returns each matching current filter ID once, in snapshot order. The
// caller authenticates sourceID and validates its observation domain before
// calling. Distributed target lists apply to that originating hunter; local-only
// selectors apply centrally regardless of their retained target list.
func (matcher *SIPMatcher) Match(event sip.Event, sourceID string) ([]string, error) {
	if sourceID == "" {
		return nil, ErrSIPSource
	}
	if matcher == nil {
		return nil, ErrSIPFilter
	}
	identities, err := sipMatchIdentities(event)
	if err != nil {
		return nil, err
	}
	var users, uris, digits [6]string
	for i, value := range identities {
		uri := sip.URI(value)
		users[i] = strings.ToLower(sip.User(uri))
		digits[i] = phonematcher.NormalizeToDigits(users[i])
		// Match the hunter's URI extraction: remove sip:/sips: without altering
		// header parameters retained by the shared URI parser.
		if strings.HasPrefix(uri, "sips:") {
			uri = uri[5:]
		} else if strings.HasPrefix(uri, "sip:") {
			uri = uri[4:]
		}
		uris[i] = strings.ToLower(uri)
	}
	var source, destination netip.Addr
	if matcher.hasIP {
		if event.SourceIP != "" {
			source, err = netip.ParseAddr(event.SourceIP)
			if err != nil {
				return nil, ErrSIPEvent
			}
			source = source.Unmap()
		}
		if event.DestinationIP != "" {
			destination, err = netip.ParseAddr(event.DestinationIP)
			if err != nil {
				return nil, ErrSIPEvent
			}
			destination = destination.Unmap()
		}
	}
	var ids []string
	for _, filter := range matcher.filters {
		if !filter.matchesSource(sourceID) {
			continue
		}
		matched := false
		switch filter.kind {
		case management.FilterType_FILTER_IP_ADDRESS:
			matched = filter.matchesIP(source) || filter.matchesIP(destination)
		case management.FilterType_FILTER_CALL_ID:
			matched = event.CallID != "" && event.CallID == filter.pattern
		case management.FilterType_FILTER_SIP_USER, management.FilterType_FILTER_PHONE_NUMBER:
			for i, user := range users {
				if user == "" {
					continue
				}
				if filter.phoneSuffix {
					matched = len(digits[i]) >= phonematcher.DefaultMinLength && len(filter.pattern) >= phonematcher.DefaultMinLength && strings.HasSuffix(digits[i], filter.pattern)
				} else {
					matched = matchFoldedSIP(user, filter.pattern, filter.patternType)
				}
				if matched {
					break
				}
			}
		case management.FilterType_FILTER_SIP_URI:
			for _, uri := range uris {
				if uri != "" && matchFoldedSIP(uri, filter.pattern, filter.patternType) {
					matched = true
					break
				}
			}
		}
		if matched {
			ids = append(ids, filter.id)
		}
	}
	return ids, nil
}
func (filter compiledSIPFilter) matchesSource(source string) bool {
	if filter.local || len(filter.targets) == 0 {
		return true
	}
	for _, target := range filter.targets {
		if target == source {
			return true
		}
	}
	return false
}
func (filter compiledSIPFilter) matchesIP(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	if filter.address.IsValid() {
		return filter.address == address
	}
	return filter.prefix.IsValid() && filter.prefix.Contains(address)
}
func matchFoldedSIP(value, pattern string, kind PatternType) bool {
	switch kind {
	case PatternTypePrefix:
		return strings.HasPrefix(value, pattern)
	case PatternTypeSuffix:
		return strings.HasSuffix(value, pattern)
	default:
		return strings.Contains(value, pattern)
	}
}
func sipMatchIdentities(event sip.Event) ([6]string, error) {
	from, to := event.From, event.To
	if from == "" {
		from = event.FromURI
	}
	if to == "" {
		to = event.ToURI
	}
	asserted := event.PAssertedIdentity
	if asserted == "" {
		asserted = event.Headers["p-asserted-identity"]
	}
	identities := [6]string{from, to, asserted, event.Headers["p-preferred-identity"], event.Headers["p-called-party-id"], event.RequestURI}
	total := len(event.CallID) + len(event.SourceIP) + len(event.DestinationIP)
	for _, identity := range identities {
		if len(identity) > sip.MaxMessageSize-total {
			return [6]string{}, ErrSIPEvent
		}
		total += len(identity)
	}
	return identities, nil
}
