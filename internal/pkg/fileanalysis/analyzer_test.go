package fileanalysis

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeHashesMIMETruncationAndDedup(t *testing.T) {
	a, err := New(Config{MaxFileSize: 5, MaxTotalSize: 100})
	require.NoError(t, err)
	one, content, err := a.Analyze(Observation{Source: "HTTP", Filename: "../note.txt", Content: []byte("hello world"), TotalBytes: 11})
	require.NoError(t, err)
	require.Nil(t, content)
	require.Equal(t, uint64(5), one.SeenBytes)
	require.Equal(t, uint64(6), one.MissingBytes)
	require.Equal(t, uint64(6), one.OverflowBytes)
	require.Equal(t, "note.txt", one.Filename)
	require.Equal(t, "5d41402abc4b2a76b9719d911017c592", one.MD5)
	require.Equal(t, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", one.SHA1)
	require.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", one.SHA256)
	require.False(t, one.HashComplete)
	two, _, err := a.Analyze(Observation{Content: []byte("hello")})
	require.NoError(t, err)
	require.NotEqual(t, one.FileID, two.FileID)
	require.True(t, two.HashComplete)
}

func TestAnalyzeGzipAndExtractionTotalLimit(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	dir := t.TempDir()
	a, err := New(Config{MaxFileSize: 100, MaxTotalSize: 5, Extract: true, Directory: dir})
	require.NoError(t, err)
	ev, content, err := a.Analyze(Observation{Content: compressed.Bytes(), ContentEncoding: "gzip"})
	require.NoError(t, err)
	require.NotNil(t, content)
	require.FileExists(t, ev.ExtractedPath)
	b, err := os.ReadFile(filepath.Clean(ev.ExtractedPath))
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), b)
	ev2, content2, err := a.Analyze(Observation{Content: []byte("x")})
	require.NoError(t, err)
	require.Nil(t, content2)
	require.Empty(t, ev2.ExtractedPath)
}

func TestAnalyzeDuplicateContentHasUniqueFUIDAndSharedExtraction(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{MaxFileSize: 100, MaxTotalSize: 100, Extract: true, Directory: dir})
	require.NoError(t, err)

	one, contentOne, err := a.Analyze(Observation{Source: "HTTP", Filename: "one.txt", Content: []byte("same")})
	require.NoError(t, err)
	two, contentTwo, err := a.Analyze(Observation{Source: "SMTP", Filename: "two.txt", Content: []byte("same")})
	require.NoError(t, err)

	require.NotEqual(t, one.FileID, two.FileID)
	require.Equal(t, one.ExtractedPath, two.ExtractedPath)
	require.NotEmpty(t, one.ExtractedPath)
	require.NotNil(t, contentOne)
	require.Equal(t, one.FileID, contentOne.FileID)
	require.Nil(t, contentTwo)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestAnalyzeFUIDIsUniqueAcrossAnalyzers(t *testing.T) {
	oneAnalyzer, err := New(Config{})
	require.NoError(t, err)
	twoAnalyzer, err := New(Config{})
	require.NoError(t, err)

	one, _, err := oneAnalyzer.Analyze(Observation{Content: []byte("same")})
	require.NoError(t, err)
	two, _, err := twoAnalyzer.Analyze(Observation{Content: []byte("same")})
	require.NoError(t, err)
	require.NotEqual(t, one.FileID, two.FileID)
}

func TestSMTPAttachments(t *testing.T) {
	body := []byte("--b\r\nContent-Disposition: attachment; filename=hello.txt\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n")
	items, err := SMTPAttachments(body, "multipart/mixed; boundary=b", 100)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "hello.txt", items[0].Filename)
	require.Equal(t, []byte("hello"), items[0].Content)
}
