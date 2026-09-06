package offline

import (
	"context"
	"errors"
	"reflect"
	"strings"
)

// Low-cardinality registries stop interning at a fixed byte/entry cap. Unique
// high-cardinality text stays in bounded row blocks instead of a growing map.
const compactRegistryEntries = 256
const compactLabelBytes = 64 << 10

type compactRegistries struct {
	Labels    []string
	Contexts  []CaptureContext
	memory    uint64
	textBytes uint64
}

func (b *Builder) internCompactRow(ctx context.Context, row *compactRow) error {
	c := b.d.compact
	registry := &c.registries
	if registry.Labels == nil {
		cost := uint64(compactRegistryEntries) * (uint64(reflect.TypeOf("").Size()) + uint64(reflect.TypeOf(CaptureContext{}).Size()))
		if err := b.reserveCompactMemory(ctx, cost); err != nil {
			return err
		}
		registry.Labels = make([]string, 0, compactRegistryEntries)
		registry.Contexts = make([]CaptureContext, 0, compactRegistryEntries)
		registry.memory += cost
	}
	intern := func(value *string, ref *uint32) error {
		if *value == "" {
			return nil
		}
		for i, label := range registry.Labels {
			if label == *value {
				*ref = uint32(i + 1)
				*value = ""
				return nil
			}
		}
		if len(registry.Labels) == compactRegistryEntries || uint64(len(*value)) > compactLabelBytes-registry.textBytes {
			return nil
		}
		cost := uint64(len(*value))
		if err := b.reserveCompactMemory(ctx, cost); err != nil {
			return err
		}
		registry.Labels = append(registry.Labels, strings.Clone(*value))
		registry.textBytes += cost
		registry.memory += cost
		*ref = uint32(len(registry.Labels))
		*value = ""
		return nil
	}
	if err := intern(&row.Node, &row.NodeRef); err != nil {
		return err
	}
	if err := intern(&row.Device, &row.DeviceRef); err != nil {
		return err
	}
	// Timestamp absence is a per-packet property and remains in the row context;
	// all parser-domain fields share one bounded entry.
	missing := row.Context.TimestampMissing
	key := row.Context
	key.TimestampMissing = false
	for i, existing := range registry.Contexts {
		if existing == key {
			row.ContextRef = uint32(i + 1)
			row.Context = CaptureContext{TimestampMissing: missing}
			return nil
		}
	}
	if len(registry.Contexts) < compactRegistryEntries {
		registry.Contexts = append(registry.Contexts, key)
		row.ContextRef = uint32(len(registry.Contexts))
		row.Context = CaptureContext{TimestampMissing: missing}
	}
	return nil
}

func (c *compactState) resolveCompactRow(row *compactRow) error {
	resolve := func(value *string, ref *uint32) error {
		if *ref == 0 {
			return nil
		}
		if *value != "" || uint64(*ref) > uint64(len(c.registries.Labels)) {
			return errors.New("compact invalid label reference")
		}
		*value = c.registries.Labels[*ref-1]
		*ref = 0
		return nil
	}
	if err := resolve(&row.Node, &row.NodeRef); err != nil {
		return err
	}
	if err := resolve(&row.Device, &row.DeviceRef); err != nil {
		return err
	}
	if row.ContextRef != 0 {
		missing := row.Context.TimestampMissing
		if row.Context != (CaptureContext{TimestampMissing: missing}) || uint64(row.ContextRef) > uint64(len(c.registries.Contexts)) {
			return errors.New("compact invalid context reference")
		}
		row.Context = c.registries.Contexts[row.ContextRef-1]
		row.Context.TimestampMissing = missing
		row.ContextRef = 0
	}
	return nil
}

func (d *diskDataset) releaseCompactRegistries() {
	r := &d.compact.registries
	d.storage.releaseMemory(r.memory)
	*r = compactRegistries{}
}
