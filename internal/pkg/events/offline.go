package events

import (
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
	h := sha256.New()
	for _, path := range inputFiles {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open offline event input %q: %w", path, err)
		}
		fileHash := sha256.New()
		_, copyErr := io.Copy(fileHash, file)
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
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
