//go:build (processor || tap || all) && li

package processor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
)

const maxIRIProfileBytes = 1 << 20

// iriPolicyProfile maps explicitly agreed national dictionary values to facts
// observable at this POI. It never assigns invented values to ETSI dictionaries.
type iriPolicyProfile struct {
	Version        int                         `json:"version"`
	NFTypes        []iripolicy.DictionaryEntry `json:"nf_types,omitempty"`
	HandoverFormat *iripolicy.DictionaryEntry  `json:"handover_format,omitempty"`
	Events         []iriEventMapping           `json:"events,omitempty"`
}

type iriEventMapping struct {
	Entry  iripolicy.DictionaryEntry `json:"entry"`
	SIP    *iriSIPSelector           `json:"sip,omitempty"`
	RADIUS *iriRADIUSSelector        `json:"radius,omitempty"`
}

type iriSIPSelector struct {
	Method    string `json:"method,omitempty"`
	Response  bool   `json:"response,omitempty"`
	StatusMin int    `json:"status_min,omitempty"`
	StatusMax int    `json:"status_max,omitempty"`
}

type iriRADIUSSelector struct {
	Code uint8 `json:"code"`
}

func loadIRIPolicyProfile(path string) (iriPolicyProfile, iripolicy.Profile, string, error) {
	profile := iriPolicyProfile{Version: 1}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return profile, iripolicy.Profile{}, "", errors.New("open IRI policy profile failed")
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > maxIRIProfileBytes {
			closeErr := file.Close()
			return profile, iripolicy.Profile{}, "", errors.Join(errors.New("IRI policy profile must be a bounded regular file"), closeErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxIRIProfileBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > maxIRIProfileBytes {
			return profile, iripolicy.Profile{}, "", errors.New("read IRI policy profile failed")
		}
		if err := validateIRIProfileJSON(data); err != nil {
			return profile, iripolicy.Profile{}, "", err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		// Require the version explicitly when reading an operator-supplied file.
		profile.Version = 0
		if err := decoder.Decode(&profile); err != nil {
			return profile, iripolicy.Profile{}, "", errors.New("invalid IRI policy profile structure")
		}
	}
	capabilities, err := profile.validate()
	if err != nil {
		return profile, iripolicy.Profile{}, "", err
	}
	canonical, err := json.Marshal(profile)
	if err != nil {
		return profile, iripolicy.Profile{}, "", errors.New("encode IRI policy profile revision failed")
	}
	revision := sha256.Sum256(canonical)
	return profile, capabilities, hex.EncodeToString(revision[:]), nil
}

// Reject duplicate keys (including case aliases), trailing values, and excessive
// nesting before decoding. Error text deliberately contains no profile content.
func validateIRIProfileJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("IRI policy profile nesting limit exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid IRI policy profile JSON")
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		if delimiter != '{' && delimiter != '[' {
			return errors.New("invalid IRI policy profile JSON")
		}
		keys := make(map[string]bool)
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				if err != nil {
					return errors.New("invalid IRI policy profile JSON")
				}
				name, ok := key.(string)
				if !ok || keys[strings.ToLower(name)] {
					return errors.New("duplicate IRI policy profile field")
				}
				keys[strings.ToLower(name)] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return errors.New("invalid IRI policy profile JSON")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("IRI policy profile requires one JSON object")
	}
	return nil
}

func (p *iriPolicyProfile) validate() (iripolicy.Profile, error) {
	if p.Version != 1 || len(p.Events) > 256 || len(p.NFTypes) > 256 {
		return iripolicy.Profile{}, errors.New("unsupported IRI policy profile version or limits")
	}
	capabilities := iripolicy.Profile{NFTypes: slices.Clone(p.NFTypes)}
	if p.HandoverFormat != nil {
		capabilities.HandoverFormats = []iripolicy.DictionaryEntry{*p.HandoverFormat}
	}
	for i := range p.Events {
		mapping := &p.Events[i]
		if mapping.Entry.Owner == "ETSI" || (mapping.SIP == nil) == (mapping.RADIUS == nil) {
			return iripolicy.Profile{}, fmt.Errorf("IRI event mapping %d requires a national dictionary and exactly one selector", i)
		}
		if mapping.SIP != nil {
			selector := mapping.SIP
			if selector.Method != "" && (!sip.IsRequestMethod(selector.Method) || strings.ToUpper(selector.Method) != selector.Method) {
				return iripolicy.Profile{}, fmt.Errorf("IRI event mapping %d has an invalid SIP method", i)
			}
			if selector.Response {
				if selector.StatusMin == 0 && selector.StatusMax == 0 {
					selector.StatusMin, selector.StatusMax = 100, 699
				}
				if selector.StatusMin < 100 || selector.StatusMax > 699 || selector.StatusMax < selector.StatusMin {
					return iripolicy.Profile{}, fmt.Errorf("IRI event mapping %d has an invalid SIP response range", i)
				}
			} else if selector.StatusMin != 0 || selector.StatusMax != 0 {
				return iripolicy.Profile{}, fmt.Errorf("IRI event mapping %d uses response status on a request", i)
			}
		}
		if mapping.RADIUS != nil {
			switch mapping.RADIUS.Code {
			case 1, 2, 3, 4, 5, 11:
			default:
				return iripolicy.Profile{}, fmt.Errorf("IRI event mapping %d uses an unsupported RADIUS code", i)
			}
		}
		if !slices.Contains(capabilities.Events, mapping.Entry) {
			capabilities.Events = append(capabilities.Events, mapping.Entry)
		}
	}
	if err := iripolicy.ValidateProfile(capabilities); err != nil {
		return iripolicy.Profile{}, fmt.Errorf("invalid IRI policy dictionary profile: %w", err)
	}
	// Set and mapping order have no effect on classification. Canonical order
	// keeps whitespace and equivalent reordering from changing task authority.
	slices.SortFunc(p.NFTypes, func(a, b iripolicy.DictionaryEntry) int {
		return strings.Compare(a.Owner+"\x00"+a.Name+"\x00"+a.Value, b.Owner+"\x00"+b.Name+"\x00"+b.Value)
	})
	slices.SortFunc(p.Events, func(a, b iriEventMapping) int { return strings.Compare(a.sortKey(), b.sortKey()) })
	p.Events = slices.CompactFunc(p.Events, func(a, b iriEventMapping) bool {
		return a.Entry == b.Entry && ((a.SIP != nil && b.SIP != nil && *a.SIP == *b.SIP) || (a.RADIUS != nil && b.RADIUS != nil && *a.RADIUS == *b.RADIUS))
	})
	if len(p.Events) == 0 {
		p.Events = nil
	}
	if len(p.NFTypes) == 0 {
		p.NFTypes = nil
	}
	return capabilities, nil
}

func (m iriEventMapping) sortKey() string {
	key := m.Entry.Owner + "\x00" + m.Entry.Name + "\x00" + m.Entry.Value + "\x00"
	if m.SIP != nil {
		return key + "sip/" + m.SIP.Method + "/" + strconv.FormatBool(m.SIP.Response) + "/" + strconv.Itoa(m.SIP.StatusMin) + "/" + strconv.Itoa(m.SIP.StatusMax)
	}
	return key + "radius/" + strconv.Itoa(int(m.RADIUS.Code))
}

func (p iriPolicyProfile) baseFacts() iripolicy.Facts {
	return iripolicy.Facts{NFTypes: p.NFTypes, NFTypesKnown: len(p.NFTypes) > 0, HandoverFormat: p.HandoverFormat}
}

func (p iriPolicyProfile) sipFacts(packet *types.PacketDisplay) iripolicy.Facts {
	facts := p.baseFacts()
	if packet == nil || packet.VoIPData == nil || packet.VoIPData.IsRTP {
		return facts
	}
	message := packet.VoIPData.RawSIP
	if len(message) > 0 {
		if x2x3.FindSIPStart(message) != 0 {
			return facts
		}
	} else {
		message = packet.RawData
	}
	parsed, err := sip.Parse(x2x3.FindSIPMessage(message), sip.ParseOptions{})
	if err != nil {
		return facts
	}
	facts.EventsKnown = true
	for _, mapping := range p.Events {
		selector := mapping.SIP
		if selector == nil || selector.Response != (parsed.ResponseCode != 0) {
			continue
		}
		method := parsed.Method
		if selector.Response {
			if parsed.ResponseCode < selector.StatusMin || parsed.ResponseCode > selector.StatusMax {
				continue
			}
			if selector.Method != "" && (parsed.CSeqMethod == "" || parsed.DuplicateReliableHeaders.CSeq) {
				facts.Events, facts.EventsKnown = nil, false
				return facts
			}
			method = parsed.CSeqMethod
		}
		if selector.Method == "" || selector.Method == method {
			if !slices.Contains(facts.Events, mapping.Entry) {
				facts.Events = append(facts.Events, mapping.Entry)
			}
		}
	}
	return facts
}

func (p iriPolicyProfile) radiusFacts(observation *radius.Observation) iripolicy.Facts {
	facts := p.baseFacts()
	if observation == nil || observation.Message == nil {
		return facts
	}
	facts.EventsKnown = true
	for _, mapping := range p.Events {
		if mapping.RADIUS != nil && mapping.RADIUS.Code == observation.Message.Code && !slices.Contains(facts.Events, mapping.Entry) {
			facts.Events = append(facts.Events, mapping.Entry)
		}
	}
	return facts
}

// allowIRI is the single accounting boundary for explicit policy suppression
// and unavailable policy facts. These outcomes are separate from delivery loss.
func (p *Processor) allowIRI(task *li.InterceptTask, facts iripolicy.Facts) bool {
	if len(task.IRIPolicyReferences) == 0 {
		return true
	}
	deliver, err := p.liManager.EvaluateIRIPolicy(task.XID, task.ActivationGeneration, facts)
	if err != nil {
		liIRIPolicyErrors.Add(1)
		return false
	}
	if !deliver {
		liIRIPolicySuppressed.Add(1)
	}
	return deliver
}
