package offline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// This manifest is deliberately completion-only. No reader opens persisted
// sessions, and a source registry always refers to the initially owned handles.
type compactCompletion struct {
	SchemaMajor, SchemaMinor                                                      uint16
	NormalizationVersion, AnalyzerVersion, DecoderVersion, FilterSemanticsVersion string
	BaseComplete, AnalysisComplete                                                bool
	AnalysisRevision                                                              uint64
	FileSHA256                                                                    map[string]string
	Backings                                                                      []compactBackingManifest
}

type compactBackingManifest struct {
	ID           uint32
	Kind         BackingKind
	Size         int64
	SourceID     uint32
	SourceIndex  int
	SourceSize   int64
	SourceSHA256 string
	OwnedSHA256  string `json:",omitempty"`
	Policy       BackingPolicy
	Compressed   bool
}

func (b *Builder) compactCompletion(ctx context.Context) (completion *compactCompletion, held uint64, resultErr error) {
	if b.d.compact == nil {
		return nil, 0, nil
	}
	b.d.releaseCompactCompressor()
	b.d.releaseCompactBuffers()
	if err := b.d.validateCompactStreams(); err != nil {
		return nil, 0, err
	}
	// Narrow VoIP amendments encode rows and overrides separately. Validate the
	// combined decoded detail before publication, including raw bytes and other
	// protocol metadata. A constant-sized ID range avoids an unbounded amended-ID
	// set; sparse amendments may also validate intervening unchanged records.
	for id := b.d.compact.amendmentFirst; id < b.d.compact.amendmentEnd; id++ {
		_, memory, err := b.d.readDetail(ctx, id)
		if err != nil {
			return nil, 0, fmt.Errorf("validate amended compact detail %d: %w", id, err)
		}
		b.d.storage.releaseMemory(memory)
	}
	registry := b.d.compact.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	// Charge DTO slices, digests and map bookkeeping before construction.
	held = uint64(len(registry.entries))*512 + 4096
	if held > b.d.storage.limits.MaxRecordBytes {
		return nil, 0, fmt.Errorf("compact manifest identities exceed record budget")
	}
	if err := b.d.storage.reserveMemory(ctx, held); err != nil {
		return nil, 0, err
	}
	reservation := held
	defer func() {
		if resultErr != nil {
			b.d.storage.releaseMemory(reservation)
		}
	}()
	const scratchBytes = 32 << 10
	if err := b.d.storage.reserveMemory(ctx, scratchBytes); err != nil {
		return nil, 0, err
	}
	defer b.d.storage.releaseMemory(scratchBytes)
	buffer := make([]byte, scratchBytes)
	result := &compactCompletion{SchemaMajor: 2, SchemaMinor: compactSchemaMinor, NormalizationVersion: "1", AnalyzerVersion: "1", DecoderVersion: "1", FilterSemanticsVersion: "1", BaseComplete: true, AnalysisComplete: true, AnalysisRevision: 1, FileSHA256: make(map[string]string, 3)}
	hashFile := func(f *os.File, size int64) (string, error) {
		hash := sha256.New()
		reader := io.NewSectionReader(f, 0, size)
		for {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			n, err := reader.Read(buffer)
			if n > 0 {
				if _, hashErr := hash.Write(buffer[:n]); hashErr != nil {
					return "", hashErr
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", fmt.Errorf("hash completed compact stream: %w", err)
			}
		}
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	for _, f := range []*os.File{b.d.summaries, b.d.details, b.d.offsets} {
		info, err := f.Stat()
		if err != nil {
			return nil, 0, err
		}
		digest, err := hashFile(f, info.Size())
		if err != nil {
			return nil, 0, err
		}
		result.FileSHA256[filepath.Base(f.Name())] = digest
	}
	// Registry cardinality and entry allocations are already bounded by the
	// source/backing owner; only compact nonsecret identity DTOs are serialized.
	for i, entry := range registry.entries {
		if entry == nil {
			continue
		}
		identity := entry.identity
		ownedDigest := ""
		if entry.scratch != nil {
			var err error
			ownedDigest, err = hashFile(entry.file, entry.size)
			if err != nil {
				return nil, 0, err
			}
		}
		result.Backings = append(result.Backings, compactBackingManifest{OwnedSHA256: ownedDigest, ID: uint32(i + 1), Kind: entry.kind, Size: entry.size, SourceID: identity.SourceID, SourceIndex: identity.SourceIndex, SourceSize: identity.Size, SourceSHA256: hex.EncodeToString(identity.Digest[:]), Policy: identity.Policy, Compressed: identity.Compressed})
	}
	return result, held, nil
}
