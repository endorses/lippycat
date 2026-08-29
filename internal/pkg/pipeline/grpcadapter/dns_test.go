package grpcadapter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDNSMetadataToProto(t *testing.T) {
	domain := &types.DNSMetadata{
		TransactionID: 42, IsResponse: true, Opcode: "QUERY", ResponseCode: "NOERROR",
		Authoritative: true, Truncated: true, RecursionDesired: true,
		RecursionAvailable: true, AuthenticatedData: true, CheckingDisabled: true,
		QuestionCount: 1, AnswerCount: 2, AuthorityCount: 3, AdditionalCount: 4,
		QueryName: "example.test", QueryType: "A", QueryClass: "IN",
		QueryResponseTimeMs: 15, CorrelatedQuery: true,
		TunnelingScore: 0.75, EntropyScore: 0.5,
		Answers: []types.DNSAnswer{{Name: "example.test", Type: "A", Class: "IN", TTL: 60, Data: "192.0.2.1"}},
	}

	got := DNSMetadataToProto(domain)
	require.Equal(t, uint32(42), got.TransactionId)
	require.True(t, got.IsResponse)
	require.Equal(t, "QUERY", got.Opcode)
	require.Equal(t, "NOERROR", got.ResponseCode)
	require.True(t, got.Authoritative)
	require.True(t, got.Truncated)
	require.True(t, got.RecursionDesired)
	require.True(t, got.RecursionAvailable)
	require.True(t, got.AuthenticatedData)
	require.True(t, got.CheckingDisabled)
	require.Equal(t, uint32(1), got.QuestionCount)
	require.Equal(t, uint32(2), got.AnswerCount)
	require.Equal(t, uint32(3), got.AuthorityCount)
	require.Equal(t, uint32(4), got.AdditionalCount)
	require.Equal(t, "example.test", got.QueryName)
	require.Equal(t, "A", got.QueryType)
	require.Equal(t, "IN", got.QueryClass)
	require.Equal(t, int64(15), got.QueryResponseTimeMs)
	require.True(t, got.CorrelatedQuery)
	require.Equal(t, 0.75, got.TunnelingScore)
	require.Equal(t, 0.5, got.EntropyScore)
	require.Len(t, got.Answers, 1)
	require.Equal(t, "192.0.2.1", got.Answers[0].Data)
}

func TestDNSMetadataToProtoNil(t *testing.T) {
	require.Nil(t, DNSMetadataToProto(nil))
}
