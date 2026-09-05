package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// OfflineInputIdentity returns a stable identity for the ordered contents of
// inputFiles. Each file is hashed separately so file boundaries remain part of
// the identity.
func OfflineInputIdentity(inputFiles []string) (string, error) {
	return OfflineInputIdentityContext(context.Background(), inputFiles)
}

// OfflineInputIdentityContext computes the same identity with bounded reads and
// cancellation between reads. Only regular files are accepted, preventing an
// input FIFO or device from blocking opening before capture validation.
func OfflineInputIdentityContext(ctx context.Context, inputFiles []string) (string, error) {
	h := sha256.New()
	for _, path := range inputFiles {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("stat offline event input %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("offline event input %q must be a regular capture file", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open offline event input %q: %w", path, err)
		}
		fileHash := sha256.New()
		_, copyErr := io.CopyBuffer(fileHash, offlineIdentityReader{ctx: ctx, reader: file}, make([]byte, 64<<10))
		closeErr := file.Close()
		if copyErr != nil {
			if closeErr != nil {
				return "", fmt.Errorf("hash offline event input %q: copy: %w; close: %w", path, copyErr, closeErr)
			}
			return "", fmt.Errorf("hash offline event input %q: %w", path, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close offline event input %q: %w", path, closeErr)
		}
		_, _ = h.Write(fileHash.Sum(nil))
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// The wrapper suppresses os.File.WriteTo so cancellation is checked for each
// bounded chunk rather than only at whole-file boundaries.
type offlineIdentityReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r offlineIdentityReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
