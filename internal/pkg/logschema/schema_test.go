package logschema

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTSVHeaderFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/headers.golden")
	require.NoError(t, err)
	var got strings.Builder
	for _, stream := range Streams {
		fmt.Fprintf(&got, "[%s]\n#path\t%s\n#fields", stream.Filename, stream.Name)
		for _, field := range stream.Fields {
			fmt.Fprintf(&got, "\t%s", field.Name)
		}
		got.WriteString("\n#types")
		for _, field := range stream.Fields {
			fmt.Fprintf(&got, "\t%s", field.Type)
		}
		got.WriteString("\n")
	}
	require.Equal(t, string(data), got.String())
}

func TestJSONLFixturesMatchSchemas(t *testing.T) {
	file, err := os.Open("testdata/records.jsonl")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var fixture struct {
			Stream string         `json:"_stream"`
			Record map[string]any `json:"record"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &fixture))
		stream, ok := ByName(fixture.Stream)
		require.True(t, ok, fixture.Stream)
		require.Len(t, fixture.Record, len(stream.Fields))
		for _, field := range stream.Fields {
			require.Contains(t, fixture.Record, field.Name)
		}
		seen[fixture.Stream] = true
	}
	require.NoError(t, scanner.Err())
	require.Len(t, seen, len(Streams))
}

func TestSchemaHasUniqueNamesAndFields(t *testing.T) {
	streams := make(map[string]bool)
	for _, stream := range Streams {
		require.False(t, streams[stream.Name])
		streams[stream.Name] = true
		fields := make(map[string]bool)
		for _, field := range stream.Fields {
			require.NotEmpty(t, field.Name)
			require.NotEmpty(t, field.Type)
			require.False(t, fields[field.Name], "%s.%s", stream.Name, field.Name)
			fields[field.Name] = true
		}
	}
}
