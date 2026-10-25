package offline

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"reflect"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	eventFrameBytes        = 32
	eventStreamHeaderBytes = 40
	eventOffsetBytes       = 16
	eventManifestBytes     = 64
)

var (
	eventFrameMagic    = [8]byte{'L', 'C', 'E', 'V', 'R', 'O', 'W', 1}
	eventDataMagic     = [8]byte{'L', 'C', 'E', 'V', 'D', 'A', 'T', 1}
	eventOffsetMagic   = [8]byte{'L', 'C', 'E', 'V', 'O', 'F', 'F', 1}
	eventManifestMagic = [8]byte{'L', 'C', 'E', 'V', 'M', 'A', 'N', 1}
)

func eventObjectMemory(ev events.Event, limit uint64) (uint64, error) {
	if ev == nil {
		return 0, errors.New("offline event is nil")
	}
	v := reflect.ValueOf(ev)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, errors.New("offline event is a nil pointer")
		}
		v = v.Elem()
	}
	n := uint64(v.Type().Size()) + uint64(reflect.TypeOf(EventRecord{}).Size())
	if n > limit {
		return 0, errors.New("offline event exceeds decoded record limit")
	}
	if err := measureMemory(v, &n, limit); err != nil {
		return 0, fmt.Errorf("offline event memory: %w", err)
	}
	return n, nil
}

// eventDecodeMemory walks wire bytes without allocating messages. Its charge
// covers protobuf objects, growing repeated fields/maps, decoder-owned strings,
// DecodeEvent's cloned wire, and the final typed metadata. This prevents a tiny
// encoded repeated-field payload from allocating outside the shared cache budget
// before collection validation. The payload allocation is charged separately.
func eventDecodeMemory(payload []byte, desc protoreflect.MessageDescriptor, limit uint64) (uint64, error) {
	var size uint64
	var walk func([]byte, protoreflect.MessageDescriptor, int) error
	walk = func(data []byte, message protoreflect.MessageDescriptor, depth int) error {
		if depth > 32 {
			return errors.New("offline event protobuf nesting exceeds schema limit")
		}
		// Current metadata messages each fit within 1024 bytes. Three copies
		// include unmarshal, compatibility-preserving clone, and typed output.
		if err := addBudget(&size, 3*1024, limit); err != nil {
			return err
		}
		for len(data) > 0 {
			number, typ, tag := protowire.ConsumeTag(data)
			if tag < 0 || number < 1 {
				return errors.New("malformed offline event protobuf tag")
			}
			data = data[tag:]
			field := message.Fields().ByNumber(protoreflect.FieldNumber(number))
			if err := addBudget(&size, 128, limit); err != nil {
				return err
			}
			if typ == protowire.BytesType {
				value, n := protowire.ConsumeBytes(data)
				if n < 0 {
					return errors.New("malformed offline event protobuf bytes")
				}
				if field != nil && field.Kind() == protoreflect.MessageKind {
					if err := walk(value, field.Message(), depth+1); err != nil {
						return err
					}
				} else if err := addProduct(&size, uint64(len(value)), 3, limit); err != nil {
					return err
				}
				data = data[n:]
				continue
			}
			if typ == protowire.StartGroupType || typ == protowire.EndGroupType {
				return errors.New("offline event protobuf groups are unsupported")
			}
			n := protowire.ConsumeFieldValue(number, typ, data)
			if n < 0 {
				return errors.New("malformed offline event protobuf value")
			}
			data = data[n:]
		}
		return nil
	}
	if err := walk(payload, desc, 0); err != nil {
		return 0, fmt.Errorf("offline event decode allocation: %w", err)
	}
	return size, nil
}

func eventChecksum(prefix, payload []byte) uint32 {
	h := crc32.NewIEEE()
	_, _ = h.Write(prefix) // hash.Hash writes never fail.
	_, _ = h.Write(payload)
	return h.Sum32()
}

func eventStreamHeader(magic [8]byte, generation DatasetGeneration, count uint64) [eventStreamHeaderBytes]byte {
	var h [eventStreamHeaderBytes]byte
	copy(h[:8], magic[:])
	binary.LittleEndian.PutUint16(h[8:10], EventSchemaVersion)
	binary.LittleEndian.PutUint64(h[16:24], uint64(generation))
	binary.LittleEndian.PutUint64(h[24:32], count)
	binary.LittleEndian.PutUint64(h[32:40], uint64(CompletedRevision))
	return h
}

func eventFrame(id EventRowID, payload []byte) [eventFrameBytes]byte {
	var h [eventFrameBytes]byte
	copy(h[:8], eventFrameMagic[:])
	binary.LittleEndian.PutUint16(h[8:10], EventSchemaVersion)
	binary.LittleEndian.PutUint32(h[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint64(h[16:24], uint64(id))
	binary.LittleEndian.PutUint32(h[24:28], eventChecksum(h[:24], payload))
	return h
}

func (d *diskEventDataset) readRecord(ctx context.Context, id EventRowID) (record EventRecord, retained uint64, err error) {
	if err = ctx.Err(); err != nil {
		return record, 0, err
	}
	if id == 0 || uint64(id) > d.count {
		return record, 0, fmt.Errorf("offline event row %d outside dataset", id)
	}
	var entry [eventOffsetBytes]byte
	if _, err = d.offsets.ReadAt(entry[:], int64(eventStreamHeaderBytes+(uint64(id)-1)*eventOffsetBytes)); err != nil {
		return record, 0, fmt.Errorf("read offline event offset: %w", err)
	}
	offset, length := binary.LittleEndian.Uint64(entry[:8]), binary.LittleEndian.Uint64(entry[8:])
	if offset < eventStreamHeaderBytes || length < eventFrameBytes || length > d.storage.limits.MaxRecordBytes || offset > d.dataBytes || length > d.dataBytes-offset {
		return record, 0, errors.New("corrupt offline event offset or length")
	}
	var header [eventFrameBytes]byte
	if _, err = d.data.ReadAt(header[:], int64(offset)); err != nil {
		return record, 0, fmt.Errorf("read offline event frame: %w", err)
	}
	payloadBytes := uint64(binary.LittleEndian.Uint32(header[12:16]))
	if string(header[:8]) != string(eventFrameMagic[:]) || binary.LittleEndian.Uint16(header[8:10]) != EventSchemaVersion || binary.LittleEndian.Uint16(header[10:12]) != 0 || binary.LittleEndian.Uint32(header[28:32]) != 0 || binary.LittleEndian.Uint64(header[16:24]) != uint64(id) || payloadBytes != length-eventFrameBytes {
		return record, 0, errors.New("corrupt offline event frame header")
	}
	if err = d.storage.reserveMemory(ctx, payloadBytes); err != nil {
		return record, 0, err
	}
	held := payloadBytes
	defer func() {
		if err != nil {
			d.storage.releaseMemory(held)
		} else {
			d.storage.releaseMemory(held - retained)
		}
	}()
	payload := make([]byte, int(payloadBytes))
	if _, err = d.data.ReadAt(payload, int64(offset+eventFrameBytes)); err != nil {
		return record, 0, fmt.Errorf("read offline event payload: %w", err)
	}
	if eventChecksum(header[:24], payload) != binary.LittleEndian.Uint32(header[24:28]) {
		return record, 0, errors.New("corrupt offline event checksum")
	}
	wire := &eventsv1.ProtocolEvent{}
	allocation, allocationErr := eventDecodeMemory(payload, wire.ProtoReflect().Descriptor(), d.storage.limits.CacheBytes)
	if allocationErr != nil {
		return record, 0, allocationErr
	}
	if err = d.storage.reserveMemory(ctx, allocation); err != nil {
		return record, 0, err
	}
	held += allocation
	if err = proto.Unmarshal(payload, wire); err != nil {
		return record, 0, fmt.Errorf("decode offline event protobuf: %w", err)
	}
	var decoded protoadapter.DecodedEvent
	if decoded, err = protoadapter.DecodeEvent(wire); err != nil {
		return record, 0, fmt.Errorf("decode offline event metadata: %w", err)
	}
	if decoded.Omission != nil || decoded.Event == nil || decoded.Event.Kind() == events.KindFileContent {
		return record, 0, errors.New("unsupported offline event payload")
	}
	if retained, err = eventObjectMemory(decoded.Event, d.storage.limits.MaxRecordBytes); err != nil {
		return record, 0, err
	}
	if retained > held {
		return record, 0, errors.New("offline event decoder exceeded allocation reservation")
	}
	if err = ctx.Err(); err != nil {
		return record, 0, err
	}
	return EventRecord{ID: id, Event: decoded.Event}, retained, nil
}
