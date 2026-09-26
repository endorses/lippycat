//go:build li

package delivery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const maxX3ReplayManifestBytes = 16 << 20

type X3ReplayManifest struct {
	Version int                     `json:"version"`
	Records []X3ReplayAuthorization `json:"records"`
}
type X3ReplayAuthorization struct {
	Interface             string                `json:"interface"`
	JournalUUID           uuid.UUID             `json:"journal_uuid"`
	ID                    uint64                `json:"id"`
	ContentSHA256         string                `json:"content_sha256"`
	StateIncarnation      uuid.UUID             `json:"state_incarnation"`
	XID                   uuid.UUID             `json:"xid"`
	TaskGeneration        uint64                `json:"task_generation"`
	DID                   uuid.UUID             `json:"did"`
	DestinationGeneration uint64                `json:"destination_generation"`
	AdmittedAt            *li.StateTimestamp    `json:"admitted_at"`
	CapturedAt            *li.StateTimestamp    `json:"captured_at"`
	Deadline              *li.StateTimestamp    `json:"deadline"`
	Provenance            li.DeliveryProvenance `json:"provenance"`
}

func x3ManifestProvenance(p li.DeliveryProvenance) map[string]any {
	if p.Kind == "call" {
		return map[string]any{"kind": p.Kind, "call_incarnation": p.CallIncarnation, "call_generation": p.CallGeneration, "call_id": p.CallID}
	}
	return map[string]any{"kind": p.Kind, "source_kind": p.SourceKind, "origin_node_id": p.OriginNodeID, "source_id": p.SourceID, "capture_epoch": p.CaptureEpoch, "observation_sequence": p.ObservationSequence, "transport": p.Transport, "source_address": p.SourceAddress, "destination_address": p.DestinationAddress, "source_port": p.SourcePort, "destination_port": p.DestinationPort, "ssrc": p.SSRC}
}
func (a X3ReplayAuthorization) MarshalJSON() ([]byte, error) {
	type alias X3ReplayAuthorization
	return json.Marshal(struct {
		alias
		Provenance map[string]any `json:"provenance"`
	}{alias(a), x3ManifestProvenance(a.Provenance)})
}
func decodeX3Authorization(raw []byte) (X3ReplayAuthorization, error) {
	var a X3ReplayAuthorization
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return a, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return a, err
	}
	if len(fields) != 13 {
		return a, fmt.Errorf("X3 approval requires every immutable metadata field")
	}
	for _, name := range []string{"interface", "journal_uuid", "id", "content_sha256", "state_incarnation", "xid", "task_generation", "did", "destination_generation", "admitted_at", "captured_at", "deadline", "provenance"} {
		if fields[name] == nil || bytes.Equal(fields[name], []byte("null")) {
			return a, fmt.Errorf("missing or null X3 metadata")
		}
	}
	var provenance map[string]json.RawMessage
	if err := json.Unmarshal(fields["provenance"], &provenance); err != nil {
		return a, err
	}
	expected := x3ManifestProvenance(a.Provenance)
	if len(provenance) != len(expected) {
		return a, fmt.Errorf("X3 provenance fields do not match variant")
	}
	for key := range expected {
		if provenance[key] == nil || bytes.Equal(provenance[key], []byte("null")) {
			return a, fmt.Errorf("missing or null X3 provenance")
		}
	}
	for _, name := range []string{"admitted_at", "captured_at", "deadline"} {
		var ts map[string]json.RawMessage
		if err := json.Unmarshal(fields[name], &ts); err != nil || len(ts) != 2 || ts["seconds"] == nil || ts["nanos"] == nil || bytes.Equal(ts["seconds"], []byte("null")) || bytes.Equal(ts["nanos"], []byte("null")) {
			return a, fmt.Errorf("invalid X3 timestamp fields")
		}
	}
	if !a.valid() {
		return a, fmt.Errorf("invalid X3 approval identity")
	}
	return a, nil
}

func x3Authorization(r JournalRecord) X3ReplayAuthorization {
	admitted, captured, deadline := li.NewStateTimestamp(r.AdmittedAt), li.NewStateTimestamp(r.CapturedAt), li.NewStateTimestamp(r.Deadline)
	return X3ReplayAuthorization{Interface: "x3", JournalUUID: r.JournalUUID, ID: r.ID, ContentSHA256: hex.EncodeToString(r.ContentSHA256[:]), StateIncarnation: r.StateIncarnation, XID: r.XID, TaskGeneration: r.TaskGeneration, DID: r.DID, DestinationGeneration: r.DestinationGeneration, AdmittedAt: &admitted, CapturedAt: &captured, Deadline: &deadline, Provenance: r.Provenance}
}
func validManifestTime(t *li.StateTimestamp) bool {
	return t != nil && t.Nanos < 1_000_000_000 && t.Seconds >= -62135596800 && t.Seconds <= 253402300799
}
func (a X3ReplayAuthorization) valid() bool {
	if a.Interface != "x3" || a.JournalUUID == uuid.Nil || a.ID == 0 || a.StateIncarnation == uuid.Nil || a.XID == uuid.Nil || a.DID == uuid.Nil || a.TaskGeneration == 0 || a.DestinationGeneration == 0 || len(a.ContentSHA256) != 64 || strings.ToLower(a.ContentSHA256) != a.ContentSHA256 || !validManifestTime(a.AdmittedAt) || !validManifestTime(a.CapturedAt) || !validManifestTime(a.Deadline) {
		return false
	}
	if _, err := hex.DecodeString(a.ContentSHA256); err != nil {
		return false
	}
	if !time.Unix(a.Deadline.Seconds, int64(a.Deadline.Nanos)).After(time.Unix(a.AdmittedAt.Seconds, int64(a.AdmittedAt.Nanos))) {
		return false
	}
	_, err := provenanceBytes(a.Provenance, PDUTypeX3)
	return err == nil
}
func (a X3ReplayAuthorization) matches(r JournalRecord) bool {
	b := x3Authorization(r)
	return a.Interface == b.Interface && a.JournalUUID == b.JournalUUID && a.ID == b.ID && a.ContentSHA256 == b.ContentSHA256 && a.StateIncarnation == b.StateIncarnation && a.XID == b.XID && a.TaskGeneration == b.TaskGeneration && a.DID == b.DID && a.DestinationGeneration == b.DestinationGeneration && a.AdmittedAt != nil && *a.AdmittedAt == *b.AdmittedAt && a.CapturedAt != nil && *a.CapturedAt == *b.CapturedAt && a.Deadline != nil && *a.Deadline == *b.Deadline && a.Provenance == b.Provenance
}

// Reject duplicate properties before typed decoding. Object depth is bounded;
// record count is checked before each allocation by the streaming decoder below.
func manifestValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("manifest nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate manifest field")
			}
			seen[key] = true
			if len(seen) > 64 {
				return fmt.Errorf("manifest field limit")
			}
			if err := manifestValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := manifestValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid manifest framing")
	}
	_, err = d.Token()
	return err
}
func decodeX3Manifest(raw []byte) (X3ReplayManifest, error) {
	var out X3ReplayManifest
	if !validJournalJSONUnicode(raw) {
		return out, fmt.Errorf("invalid manifest Unicode")
	}
	if len(raw) > maxX3ReplayManifestBytes {
		return out, fmt.Errorf("X3 manifest exceeds byte limit")
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	if err := manifestValue(scan, 0); err != nil {
		return out, err
	}
	if _, err := scan.Token(); err != io.EOF {
		return out, fmt.Errorf("manifest trailing data")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, fmt.Errorf("manifest object required")
	}
	gotVersion, gotRecords := false, false
	seen := make(map[struct {
		Journal uuid.UUID
		ID      uint64
	}]bool)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return out, err
		}
		switch key {
		case "version":
			if err := d.Decode(&out.Version); err != nil {
				return out, err
			}
			gotVersion = true
		case "records":
			token, err := d.Token()
			if err != nil || token != json.Delim('[') {
				return out, fmt.Errorf("manifest records array required")
			}
			gotRecords = true
			for d.More() {
				if len(out.Records) >= 10_000 {
					return out, fmt.Errorf("X3 manifest exceeds record limit")
				}
				var rawRecord json.RawMessage
				if err := d.Decode(&rawRecord); err != nil {
					return out, err
				}
				a, err := decodeX3Authorization(rawRecord)
				if err != nil {
					return out, err
				}
				identity := struct {
					Journal uuid.UUID
					ID      uint64
				}{a.JournalUUID, a.ID}
				if seen[identity] {
					return out, fmt.Errorf("duplicate X3 approval identity")
				}
				seen[identity] = true
				out.Records = append(out.Records, a)
			}
			if _, err := d.Token(); err != nil {
				return out, err
			}
		default:
			return out, fmt.Errorf("unknown manifest field")
		}
	}
	if _, err := d.Token(); err != nil {
		return out, err
	}
	if !gotVersion || !gotRecords || out.Version != 2 {
		return out, fmt.Errorf("X3 manifest version 2 required")
	}
	return out, nil
}
func (c *Client) ReplayX3JournalManifest(path string, authorize func(JournalRecord) bool) error {
	if c.x3Journal == nil {
		return fmt.Errorf("X3 journal disabled")
	}
	if authorize == nil {
		return fmt.Errorf("current X3 authorization required")
	}
	raw, err := securestore.ReadFile(path, maxX3ReplayManifestBytes)
	if err != nil {
		return err
	}
	manifest, err := decodeX3Manifest(raw)
	if err != nil {
		return err
	}
	approvals := make(map[uint64]X3ReplayAuthorization, len(manifest.Records))
	for _, a := range manifest.Records {
		if a.JournalUUID != c.x3Journal.UUID() || a.StateIncarnation != c.config.StateIncarnation {
			return fmt.Errorf("X3 manifest journal/state mismatch")
		}
		approvals[a.ID] = a
	}
	return c.ReplayHeldX3(func(r JournalRecord) bool { a, ok := approvals[r.ID]; return ok && a.matches(r) && authorize(r) })
}
func (c *Client) ReplayHeldX3(authorize func(JournalRecord) bool) error {
	j := c.x3Journal
	if j == nil {
		return nil
	}
	if authorize == nil {
		return fmt.Errorf("current X3 replay authorization required")
	}
	j.controlMu.Lock()
	defer j.controlMu.Unlock()
	blocked := make(map[uuid.UUID]bool)
	var approved []uint64
	if err := j.VisitHeld(func(r JournalRecord) error {
		if !time.Now().Before(r.Deadline) {
			return j.Expire(r.ID)
		}
		if blocked[r.DID] {
			return nil
		}
		dest, err := c.manager.GetDestination(r.DID)
		item := &deliveryItem{pduType: PDUTypeX3, xid: r.XID, metadata: DeliveryMetadata{StateIncarnation: r.StateIncarnation, TaskGeneration: r.TaskGeneration, DestinationGeneration: r.DestinationGeneration, CallIncarnation: r.CallIncarnation, CallGeneration: r.CallGeneration, CallID: r.CallID, Deadline: r.Deadline}}
		if r.StateIncarnation != c.config.StateIncarnation || err != nil || li.DestinationDeliveryGeneration(dest) != r.DestinationGeneration || !destinationAcceptsPDU(dest, PDUTypeX3) || !c.itemEligible(r.DID, item, false) || !authorize(r) {
			blocked[r.DID] = true
			return nil
		}
		approved = append(approved, r.ID)
		return nil
	}); err != nil {
		return err
	}
	j.mu.Lock()
	for _, id := range approved {
		if e := j.entries[id]; e != nil && e.held && !e.authorized {
			e.authorized = true
			j.stats.ReplayPending++
		}
	}
	j.replayRevision++
	j.mu.Unlock()
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if !j.replayStarted {
		j.replayStarted = true
		c.wg.Add(1)
		go c.replayJournalFor(j, PDUTypeX3)
	}
	return nil
}
func (c *Client) ExportHeldX3JournalManifest(path string) error {
	if c.x3Journal == nil {
		return fmt.Errorf("X3 journal disabled")
	}
	manifest := X3ReplayManifest{Version: 2, Records: []X3ReplayAuthorization{}}
	size := len(`{"version":2,"records":[]}`)
	continuation := false
	err := c.x3Journal.VisitHeld(func(r JournalRecord) error {
		a := x3Authorization(r)
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		next := len(raw)
		if len(manifest.Records) > 0 {
			next++
		}
		if len(manifest.Records) >= 10_000 || size+next > maxX3ReplayManifestBytes {
			continuation = true
			return errManifestBatchComplete
		}
		size += next
		manifest.Records = append(manifest.Records, a)
		return nil
	})
	if err != nil && !errors.Is(err, errManifestBatchComplete) {
		return err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := c.writeReplayManifest(path, raw); err != nil {
		return err
	}
	logger.Info("X3 replay manifest exported", "records", len(manifest.Records), "continuation", continuation)
	return nil
}
