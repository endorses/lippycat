package packetreceipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

type StoreConfig struct {
	Directory     string `mapstructure:"dir"`
	DestinationID string `mapstructure:"destination_id"`
	// Both profiles require explicit selection. Private is plaintext.
	Keys           securestore.KeyConfig `mapstructure:"keys"`
	Protection     string                `mapstructure:"protection"`
	MaxBytes       int64                 `mapstructure:"max_bytes"`
	MaxRecordBytes int                   `mapstructure:"max_record_bytes"`
	MaxSessions    int                   `mapstructure:"max_sessions"`
	MaxRecords     int                   `mapstructure:"max_records"`
	MaxLossRanges  int                   `mapstructure:"max_loss_ranges"`
	fs             *fileOps
}

func (c StoreConfig) Validate() error {
	if c.Directory == "" || ValidIdentity(&data.RawPacketIdentity{SourceId: "validation", ProducerSessionId: "validation", CaptureEpoch: "validation", DestinationId: c.DestinationID, AckScope: "receiver"}) != nil || (c.Protection != "private" && c.Protection != "encrypted") {
		return errors.New("raw custody storage requires dir, bounded destination_id and explicit protection: private or encrypted")
	}
	hasKeys := c.Keys.Active.ID != "" || c.Keys.Active.File != "" || len(c.Keys.Prior) > 0 || c.Keys.LegacyID != ""
	if (c.Protection == "encrypted") != hasKeys {
		return errors.New("encrypted custody requires keys; private custody forbids keys")
	}
	if c.Protection == "encrypted" && (c.Keys.Active.ID == "" || c.Keys.Active.File == "" || len(c.Keys.Prior) > securestore.MaxPriorKeys) {
		return errors.New("encrypted custody requires an active key ID and file and at most four prior keys")
	}
	if c.MaxBytes <= 0 || c.MaxBytes > 64<<20 || c.MaxRecordBytes <= 0 || int64(c.MaxRecordBytes) > c.MaxBytes || c.MaxSessions <= 0 || c.MaxSessions > 65536 || c.MaxRecords <= 0 || c.MaxRecords > 1<<20 || c.MaxLossRanges <= 0 || c.MaxLossRanges > 65536 {
		return errors.New("raw custody storage requires positive bounded bytes, record, session and loss-range limits (snapshot <=64 MiB)")
	}
	return nil
}

type acceptedRecord struct {
	Sequence   uint64 `json:"sequence"`
	Digest     string `json:"sha256"`
	Payload    []byte `json:"payload,omitempty"`
	AcceptedNS int64  `json:"accepted_ns"`
	Processed  bool   `json:"processed"`
}
type custodySession struct {
	Identity       *data.RawPacketIdentity    `json:"identity"`
	Records        []acceptedRecord           `json:"records"`
	Losses         []*data.RawPacketLossRange `json:"losses,omitempty"`
	LossGeneration uint64                     `json:"loss_generation"`
	LastLossDigest string                     `json:"last_loss_digest,omitempty"`
	Retired        bool                       `json:"retired"`
}
type custodyState struct {
	Version     int                        `json:"version"`
	StoreID     string                     `json:"store_id"`
	Protection  string                     `json:"protection"`
	Destination string                     `json:"destination"`
	Sessions    map[string]*custodySession `json:"sessions"`
}

// Store persists accepted payload and duplicate receipts in a single bounded
// transaction. Processed payload is removed only after a processing checkpoint;
// hashes and explicit retirement tombstones remain until operator migration.
type Store struct {
	mu           sync.Mutex
	config       StoreConfig
	dir          *securestore.Dir
	lock         *securestore.Lock
	state        custodyState
	identity     storeIdentity
	keys         *securestore.Keyring
	usage        *securestore.Usage
	writer       *securestore.Writer
	fs           fileOps
	fault        error
	closed       bool
	replayCursor string
}

func sessionKey(id *data.RawPacketIdentity) (string, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(id)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Store) validateState() error {
	if s.state.Version != 1 || s.state.StoreID != s.identity.StoreID || s.state.Protection != s.config.Protection || s.state.Destination != s.config.DestinationID || s.state.Sessions == nil || len(s.state.Sessions) > s.config.MaxSessions {
		return errors.New("raw custody checkpoint identity or bounds rejected")
	}
	count := 0
	for key, session := range s.state.Sessions {
		if session == nil || ValidIdentity(session.Identity) != nil || session.Identity.DestinationId != s.config.DestinationID || len(session.Losses) > s.config.MaxLossRanges {
			return errors.New("invalid raw custody session")
		}
		actualKey, err := sessionKey(session.Identity)
		if err != nil || actualKey != key {
			return errors.New("raw custody session identity mismatch")
		}
		if err := validLosses(session.Losses); err != nil {
			return err
		}
		if session.LossGeneration == 0 && (len(session.Losses) > 0 || session.LastLossDigest != "") || session.LossGeneration > 0 && len(session.Losses) == 0 {
			return errors.New("invalid raw custody loss generation")
		}
		if session.LossGeneration > 0 {
			if digest, err := hex.DecodeString(session.LastLossDigest); err != nil || len(digest) != sha256.Size {
				return errors.New("invalid raw custody loss digest")
			}
		}
		var previous uint64
		for _, record := range session.Records {
			count++
			if record.Sequence == 0 || record.Sequence <= previous || record.AcceptedNS <= 0 || len(record.Payload) > s.config.MaxRecordBytes || record.Processed != (len(record.Payload) == 0) {
				return errors.New("invalid raw custody record")
			}
			previous = record.Sequence
			if digest, err := hex.DecodeString(record.Digest); err != nil || len(digest) != sha256.Size {
				return errors.New("invalid raw custody digest")
			}
			if !record.Processed {
				batch := &data.PacketBatch{}
				if err := validateBatchWire(record.Payload, s.config.MaxRecordBytes); err != nil {
					return err
				}
				if err := (proto.UnmarshalOptions{RecursionLimit: 32}).Unmarshal(record.Payload, batch); err != nil {
					return errors.New("corrupt accepted raw payload")
				}
				hash, err := BatchDigest(batch)
				if err != nil || hex.EncodeToString(hash) != record.Digest || !batchMatches(session.Identity, batch) || record.Sequence != batch.Sequence {
					return errors.New("raw custody payload identity or integrity mismatch")
				}
			}
		}
		if session.Retired {
			for _, record := range session.Records {
				if !record.Processed {
					return errors.New("retired raw session has unfinished custody")
				}
			}
		}
	}
	if count > s.config.MaxRecords {
		return errors.New("raw custody record limit exceeded")
	}
	return nil
}

func validLosses(ranges []*data.RawPacketLossRange) error {
	var last uint64
	for _, r := range ranges {
		if r == nil || r.First == 0 || r.First > r.Last || r.First <= last {
			return errors.New("raw loss ranges must be bounded, ordered and disjoint")
		}
		last = r.Last
	}
	return nil
}
func batchMatches(id *data.RawPacketIdentity, b *data.PacketBatch) bool {
	return b != nil && b.HunterId == id.SourceId && b.ProducerSessionId == id.ProducerSessionId && b.CaptureEpoch == id.CaptureEpoch && b.Sequence > 0
}

func (s *Store) clone() custodyState {
	state := custodyState{Version: 1, StoreID: s.state.StoreID, Protection: s.state.Protection, Destination: s.state.Destination, Sessions: make(map[string]*custodySession, len(s.state.Sessions))}
	for key, session := range s.state.Sessions {
		copy := *session
		copy.Records = append([]acceptedRecord(nil), session.Records...)
		copy.Losses = append([]*data.RawPacketLossRange(nil), session.Losses...)
		state.Sessions[key] = &copy
	}
	return state
}
func (s *Store) commit(next custodyState) error {
	encoded, err := s.encodeState(next)
	if err != nil {
		return err
	}
	out, err := s.fs.replace(custodyName, encoded)
	if out == securestore.Committed {
		s.state = next
	}
	if out == securestore.Uncertain {
		s.fault = errors.Join(errors.New("raw custody durability uncertain; reopen required"), err)
	}
	if out != securestore.Committed && err == nil {
		err = errors.New("raw custody mutation was not committed")
	}
	return err
}

func (s *Store) ready() error {
	if s.closed {
		return os.ErrClosed
	}
	return s.fault
}

// Accept returns a selective unsigned receipt only after durable publication.
// The service signs it with the configured destination authority.
func (s *Store) Accept(message *data.ReliablePacketMessage) (*data.RawPacketReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, false, err
	}
	if message == nil || message.ProtocolVersion != ProtocolVersion || ValidIdentity(message.Identity) != nil || message.Identity.DestinationId != s.config.DestinationID {
		return nil, false, errors.New("invalid raw custody identity")
	}
	id := message.Identity
	key, err := sessionKey(id)
	if err != nil {
		return nil, false, err
	}
	old := s.state.Sessions[key]
	if old != nil && old.Retired {
		if message.RetireSession && message.Batch == nil && len(message.Losses) == 0 && message.LossGeneration == 0 {
			return &data.RawPacketReceipt{Identity: proto.Clone(id).(*data.RawPacketIdentity), Retired: true}, true, nil
		}
		return nil, false, errors.New("raw producer session is retired")
	}
	next := s.clone()
	session := next.Sessions[key]
	if session == nil {
		if len(next.Sessions) >= s.config.MaxSessions {
			return nil, false, errors.New("raw custody session history limit reached")
		}
		session = &custodySession{Identity: proto.Clone(id).(*data.RawPacketIdentity)}
		next.Sessions[key] = session
	}
	receipt := &data.RawPacketReceipt{Identity: proto.Clone(id).(*data.RawPacketIdentity)}
	if message.Batch != nil {
		if len(message.Losses) > 0 || message.LossGeneration != 0 || message.RetireSession || !batchMatches(id, message.Batch) {
			return nil, false, errors.New("raw payload and identity contract mismatch")
		}
		if proto.Size(message.Batch) > s.config.MaxRecordBytes {
			return nil, false, errors.New("raw payload record limit exceeded")
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message.Batch)
		if err != nil {
			return nil, false, err
		}
		if len(encoded) > s.config.MaxRecordBytes {
			return nil, false, errors.New("raw payload record limit exceeded")
		}
		if err := validateBatchWire(encoded, s.config.MaxRecordBytes); err != nil {
			return nil, false, err
		}
		digest, err := BatchDigest(message.Batch)
		if err != nil {
			return nil, false, err
		}
		receipt.Sequence = message.Batch.Sequence
		receipt.ContentSha256 = digest
		for _, record := range session.Records {
			if record.Sequence == message.Batch.Sequence {
				if record.Digest != hex.EncodeToString(digest) {
					return nil, false, errors.New("conflicting raw packet identity reuse")
				}
				return receipt, true, nil
			}
		}
		for _, r := range session.Losses {
			if message.Batch.Sequence >= r.First && message.Batch.Sequence <= r.Last {
				return nil, false, errors.New("raw sequence was already retired by accounted loss")
			}
		}
		count := 0
		for _, session := range next.Sessions {
			count += len(session.Records)
		}
		if count >= s.config.MaxRecords {
			return nil, false, errors.New("raw custody duplicate history limit reached")
		}
		session.Records = append(session.Records, acceptedRecord{Sequence: message.Batch.Sequence, Digest: hex.EncodeToString(digest), Payload: encoded, AcceptedNS: time.Now().UnixNano()})
		sort.Slice(session.Records, func(i, j int) bool { return session.Records[i].Sequence < session.Records[j].Sequence })
	} else if len(message.Losses) > 0 {
		if len(message.Losses) > s.config.MaxLossRanges || message.LossGeneration == 0 || message.RetireSession {
			return nil, false, errors.New("invalid raw loss coverage")
		}
		if err := validLosses(message.Losses); err != nil {
			return nil, false, err
		}
		if message.LossGeneration < session.LossGeneration {
			return nil, false, errors.New("stale raw loss coverage")
		}
		encodedLoss, err := proto.MarshalOptions{Deterministic: true}.Marshal(&data.ReliablePacketMessage{Losses: message.Losses})
		if err != nil {
			return nil, false, err
		}
		lossDigest := sha256.Sum256(encodedLoss)
		if message.LossGeneration == session.LossGeneration {
			if session.LastLossDigest != hex.EncodeToString(lossDigest[:]) {
				return nil, false, errors.New("conflicting raw loss generation")
			}
			receipt.LossGeneration = session.LossGeneration
			receipt.Losses = message.Losses
			return proto.Clone(receipt).(*data.RawPacketReceipt), true, nil
		} else {
			merged := append(append([]*data.RawPacketLossRange(nil), session.Losses...), message.Losses...)
			sort.Slice(merged, func(i, j int) bool { return merged[i].First < merged[j].First })
			var coverage []*data.RawPacketLossRange
			for _, r := range merged {
				if len(coverage) > 0 {
					last := coverage[len(coverage)-1]
					if r.First <= last.Last || last.Last != ^uint64(0) && r.First == last.Last+1 {
						if r.Last > last.Last {
							last.Last = r.Last
						}
						continue
					}
				}
				coverage = append(coverage, proto.Clone(r).(*data.RawPacketLossRange))
			}
			if len(coverage) > s.config.MaxLossRanges {
				return nil, false, errors.New("raw custody loss-history limit reached")
			}
			session.Losses = coverage
			session.LossGeneration = message.LossGeneration
			session.LastLossDigest = hex.EncodeToString(lossDigest[:])
		}
		receipt.LossGeneration = session.LossGeneration
		receipt.Losses = message.Losses
	} else if message.RetireSession {
		for _, record := range session.Records {
			if !record.Processed {
				return nil, false, errors.New("cannot retire unfinished raw custody")
			}
		}
		session.Retired = true
		receipt.Retired = true
	} else {
		return nil, false, errors.New("empty raw acceptance request")
	}
	if err := s.commit(next); err != nil {
		return nil, false, err
	}
	return proto.Clone(receipt).(*data.RawPacketReceipt), false, nil
}

type Pending struct {
	Identity   *data.RawPacketIdentity
	Batch      *data.PacketBatch
	AcceptedAt time.Time
}

func (s *Store) Pending(limit int) ([]Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("raw replay limit must be positive")
	}
	keys := make([]string, 0, len(s.state.Sessions))
	for key := range s.state.Sessions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if s.replayCursor != "" && len(keys) > 0 {
		start := sort.SearchStrings(keys, s.replayCursor)
		if start < len(keys) && keys[start] == s.replayCursor {
			start++
		}
		if start < len(keys) {
			keys = append(append([]string(nil), keys[start:]...), keys[:start]...)
		}
	}
	var result []Pending
	for _, key := range keys {
		session := s.state.Sessions[key]
		for _, record := range session.Records {
			if !record.Processed {
				batch := &data.PacketBatch{}
				if err := (proto.UnmarshalOptions{RecursionLimit: 32}).Unmarshal(record.Payload, batch); err != nil {
					return nil, err
				}
				result = append(result, Pending{proto.Clone(session.Identity).(*data.RawPacketIdentity), batch, time.Unix(0, record.AcceptedNS)})
				s.replayCursor = key
				if len(result) >= limit {
					return result, nil
				}
			}
		}
	}
	return result, nil
}

func (s *Store) Processed(id *data.RawPacketIdentity, sequence uint64, digest []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return err
	}
	if err := ValidIdentity(id); err != nil {
		return err
	}
	key, err := sessionKey(id)
	if err != nil {
		return err
	}
	next := s.clone()
	session := next.Sessions[key]
	if session == nil {
		return errors.New("unknown raw custody session")
	}
	for i := range session.Records {
		record := &session.Records[i]
		if record.Sequence == sequence {
			expected, err := hex.DecodeString(record.Digest)
			if err != nil || !bytes.Equal(expected, digest) {
				return errors.New("raw processing receipt digest mismatch")
			}
			if record.Processed {
				return nil
			}
			record.Payload = nil
			record.Processed = true
			return s.commit(next)
		}
	}
	return errors.New("unknown raw custody record")
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.usage != nil {
		err = errors.Join(err, s.usage.Close())
	}
	if s.lock != nil {
		err = errors.Join(err, s.lock.Close())
	}
	if s.dir != nil {
		err = errors.Join(err, s.dir.Close())
	}
	return err
}
