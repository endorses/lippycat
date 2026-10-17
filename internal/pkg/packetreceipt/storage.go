package packetreceipt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

const custodyName = "custody.json"
const identityName = "identity.custody"
const frameBytes = 48
const envelopeOverhead = securestore.MaxHeaderBytes + securestore.MaxObjectIDBytes + 64

type storeIdentity struct {
	Version     int    `json:"version"`
	StoreID     string `json:"store_id"`
	Destination string `json:"destination"`
	Protection  string `json:"protection"`
}
type fileOps struct {
	replace func(string, []byte) (securestore.Outcome, error)
}

func openStore(c StoreConfig, initialize bool) (*Store, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if initialize {
		if err := securestore.EnsureDir(c.Directory); err != nil {
			return nil, err
		}
	}
	dir, err := securestore.OpenDir(c.Directory)
	if err != nil {
		return nil, err
	}
	lock, err := dir.Lock(custodyName)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	s := &Store{config: c, dir: dir, lock: lock, fs: fileOps{replace: dir.Replace}}
	if c.fs != nil && c.fs.replace != nil {
		s.fs.replace = c.fs.replace
	}
	if c.Protection == "encrypted" {
		s.keys, err = securestore.LoadKeyring(c.Keys)
		if err != nil {
			return nil, errors.Join(err, s.Close())
		}
	}
	return s, nil
}

// Initialize explicitly provisions a new store. Evidence of any previous or
// interrupted initialization is preserved; neither identity nor usage accounting
// may be silently recreated by runtime Open or by reinitialization.
func Initialize(c StoreConfig) (retErr error) {
	s, err := openStore(c, true)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, s.Close()) }()
	if err := s.dir.WalkEntries(func(name string) error {
		if strings.HasPrefix(name, ".securestore-lock-") {
			return nil
		}
		return fmt.Errorf("raw custody initialization requires an empty directory; existing object %q preserved", name)
	}); err != nil {
		return err
	}
	var store [16]byte
	if _, err := rand.Read(store[:]); err != nil {
		return fmt.Errorf("generate raw custody store identity: %w", err)
	}
	s.identity = storeIdentity{Version: 1, StoreID: hex.EncodeToString(store[:]), Destination: c.DestinationID, Protection: c.Protection}
	if s.keys != nil {
		if _, err := securestore.InitializeUsage(s.dir, s.keys, store); err != nil {
			return err
		}
		if err := s.openCrypto(store); err != nil {
			return err
		}
	}
	s.state = custodyState{Version: 1, StoreID: s.identity.StoreID, Protection: c.Protection, Destination: c.DestinationID, Sessions: map[string]*custodySession{}}
	identity, err := json.Marshal(s.identity)
	if err != nil {
		return err
	}
	protected, err := s.protect(identityName, identity)
	if err != nil {
		return err
	}
	if out, err := s.dir.Create(identityName, protected); err != nil {
		return err
	} else if out != securestore.Committed {
		return errors.New("raw custody identity was not committed")
	}
	encoded, err := s.encodeState(s.state)
	if err != nil {
		return err
	}
	if out, err := s.dir.Create(custodyName, encoded); err != nil {
		return err
	} else if out != securestore.Committed {
		return errors.New("raw custody checkpoint was not committed")
	}
	return nil
}

func Open(c StoreConfig) (_ *Store, retErr error) {
	s, err := openStore(c, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, s.Close())
		}
	}()
	if s.keys != nil {
		if err := s.openCrypto([16]byte{}); err != nil {
			return nil, err
		}
	}
	encoded, err := s.read(identityName, 4096)
	if err != nil {
		return nil, fmt.Errorf("open initialized raw custody identity: %w", err)
	}
	if err := decodeJSON(encoded, &s.identity); err != nil {
		return nil, fmt.Errorf("decode raw custody identity: %w", err)
	}
	store, err := hex.DecodeString(s.identity.StoreID)
	if err != nil || len(store) != 16 || s.identity.StoreID == strings.Repeat("0", 32) || hex.EncodeToString(store) != s.identity.StoreID || s.identity.Version != 1 || s.identity.Destination != c.DestinationID || s.identity.Protection != c.Protection {
		return nil, errors.New("raw custody identity mismatch")
	}
	ledgerID := [16]byte{}
	if s.usage != nil {
		ledgerID = s.usage.StoreID()
	}
	if s.usage != nil && !bytes.Equal(store, ledgerID[:]) {
		return nil, errors.New("raw custody identity differs from encryption ledger")
	}
	encoded, err = s.read(custodyName, c.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("open initialized raw custody checkpoint: %w", err)
	}
	if err := validateJSONBounds(encoded, c); err != nil {
		return nil, err
	}
	if err := decodeJSON(encoded, &s.state); err != nil {
		return nil, fmt.Errorf("decode raw custody checkpoint: %w", err)
	}
	if err := s.validateState(); err != nil {
		return nil, err
	}
	if err := s.dir.Sync(); err != nil {
		return nil, fmt.Errorf("settle raw custody recovery: %w", err)
	}
	return s, nil
}

func (s *Store) openCrypto(expected [16]byte) error {
	usage, err := securestore.OpenUsage(s.dir, s.keys, expected)
	if err != nil {
		return fmt.Errorf("open required raw custody encryption ledger: %w", err)
	}
	s.usage = usage
	s.writer, err = securestore.NewWriter(usage)
	return err
}
func (s *Store) protect(name string, payload []byte) ([]byte, error) {
	framed := make([]byte, frameBytes+len(payload))
	copy(framed, "LCRCPT01")
	binary.BigEndian.PutUint64(framed[8:16], uint64(len(payload)))
	digest := sha256.Sum256(payload)
	copy(framed[16:frameBytes], digest[:])
	copy(framed[frameBytes:], payload)
	if s.writer == nil {
		return framed, nil
	}
	// Snapshots contain raw captured product. They never draw from control reserve.
	return s.writer.Seal(securestore.PacketCustodyState, securestore.Binding{Store: s.usage.StoreID(), Object: name}, framed)
}
func (s *Store) read(name string, limit int64) ([]byte, error) {
	// MaxBytes bounds the complete snapshot on disk, including framing/encryption.
	maxSize := limit
	if name == identityName {
		maxSize += frameBytes + envelopeOverhead
	}
	encoded, err := s.dir.Read(name, maxSize)
	if err != nil {
		return nil, err
	}
	if s.keys != nil {
		// The envelope's own limit includes its authenticated binding overhead.
		bound := min(int(limit)+frameBytes, securestore.MaxPlaintextBytes-18-len(name))
		encoded, err = s.keys.Open(securestore.PacketCustodyState, securestore.Binding{Store: s.usage.StoreID(), Object: name}, encoded, bound)
		if err != nil {
			return nil, err
		}
	}
	if len(encoded) < frameBytes || string(encoded[:8]) != "LCRCPT01" {
		return nil, errors.New("invalid raw custody framing")
	}
	size := binary.BigEndian.Uint64(encoded[8:16])
	if size > uint64(limit) || size != uint64(len(encoded)-frameBytes) {
		return nil, errors.New("invalid raw custody frame size")
	}
	digest := sha256.Sum256(encoded[frameBytes:])
	if !bytes.Equal(digest[:], encoded[16:frameBytes]) {
		return nil, errors.New("raw custody checksum mismatch")
	}
	return encoded[frameBytes:], nil
}
func (s *Store) encodeState(next custodyState) ([]byte, error) {
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	if int64(len(payload))+frameBytes > s.config.MaxBytes {
		return nil, errors.New("raw custody byte limit reached")
	}
	encoded, err := s.protect(custodyName, payload)
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > s.config.MaxBytes {
		return nil, errors.New("raw custody byte limit reached")
	}
	return encoded, nil
}
func decodeJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("raw custody JSON contains trailing data")
	}
	return nil
}
