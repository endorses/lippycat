//go:build tui || all

package filters

import offline "github.com/endorses/lippycat/internal/pkg/offline/filterexpr"

// OfflineExpression snapshots a packet filter chain into storage expressions.
// Unknown external filter implementations retain the caller's opaque fallback.
func (fc *FilterChain) OfflineExpression() (*offline.Expression, error) {
	children := make([]*offline.Expression, 0, len(fc.filters))
	for _, f := range fc.filters {
		e, err := CompileOffline(f.filter)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, nil
		}
		children = append(children, e)
	}
	return offline.NewExpression(offline.ExpressionSpec{Op: "and", Children: children})
}

// CompileOffline translates constructed filters, not their display strings, so
// parser aliases and accepted BPF quirks remain exactly those of live filtering.
func CompileOffline(filter Filter) (*offline.Expression, error) {
	s := offline.ExpressionSpec{}
	switch f := filter.(type) {
	case *BooleanFilter:
		left, err := CompileOffline(f.left)
		if err != nil || left == nil {
			return nil, err
		}
		s.Children = []*offline.Expression{left}
		switch f.operator {
		case OpNOT:
			s.Op = "not"
		case OpAND:
			s.Op = "and"
		case OpOR:
			s.Op = "or"
		default:
			s = offline.ExpressionSpec{Op: "none"}
		}
		if f.operator == OpAND || f.operator == OpOR {
			right, err := CompileOffline(f.right)
			if err != nil || right == nil {
				return nil, err
			}
			s.Children = append(s.Children, right)
		}
	case *TextFilter:
		s.Op = "text"
		s.Text = f.searchText
		if f.searchAll {
			s.Fields = GetCommonFields("packet")
		} else {
			if f.searchSrc {
				s.Fields = append(s.Fields, "src", "srcport")
			}
			if f.searchDst {
				s.Fields = append(s.Fields, "dst", "dstport")
			}
			if f.searchInfo {
				s.Fields = append(s.Fields, "info")
			}
			if f.searchProto {
				s.Fields = append(s.Fields, "protocol")
			}
			s.Fields = append(s.Fields, f.genericFields...)
		}
	case *NumericComparisonFilter:
		s.Op = "numeric"
		s.Fields = []string{f.field}
		s.Number = f.value
		s.Comparison = f.operator
	case *NodeFilter:
		s.Op = "node"
		s.Fields = []string{"node"}
		s.Text = f.nodePattern
	case *VoIPFilter:
		s.Op = "voip"
		s.Fields = []string{"protocol", "info", "sip.user", "sip.from", "sip.to", "sip.fromtag", "sip.totag", "sip.method", "sip.callid", "sip.codec"}
		s.Text = f.value
		s.Comparison = f.field
	case *MetadataFilter:
		switch f.metadataType {
		case "voip":
			present, err := offline.NewExpression(offline.ExpressionSpec{Op: "has", Fields: []string{"voip"}})
			if err != nil {
				return nil, err
			}
			sip, err := offline.NewExpression(offline.ExpressionSpec{Op: "equal", Fields: []string{"protocol"}, Text: "SIP"})
			if err != nil {
				return nil, err
			}
			rtp, err := offline.NewExpression(offline.ExpressionSpec{Op: "equal", Fields: []string{"protocol"}, Text: "RTP"})
			if err != nil {
				return nil, err
			}
			s.Op = "or"
			s.Children = []*offline.Expression{present, sip, rtp}
		case "dns", "tls", "http", "email":
			s.Op = "has"
			s.Fields = []string{f.metadataType}
		default:
			s.Op = "none"
		}
	case *BPFFilter:
		s.Text = f.value
		switch f.matchType {
		case "protocol":
			s.Op = "equal"
			s.Text = f.protocol
			s.Fields = []string{"protocol"}
		case "port":
			s.Op = "equal"
			s.Fields = offlineDirection(f.direction, "srcport", "dstport")
		case "host", "net":
			s.Op = "contains"
			s.Fields = offlineDirection(f.direction, "src", "dst")
			if f.ipnet != nil {
				s.Op = "cidr"
				s.Text = f.ipnet.String()
			}
		default:
			s.Op = "all"
		}
	case *CallStateFilter:
		s.Op = "none" // Offline summaries are packet records.
	default:
		return nil, nil
	}
	return offline.NewExpression(s)
}
func offlineDirection(direction, src, dst string) []string {
	switch direction {
	case "src":
		return []string{src}
	case "dst":
		return []string{dst}
	default:
		return []string{src, dst}
	}
}
