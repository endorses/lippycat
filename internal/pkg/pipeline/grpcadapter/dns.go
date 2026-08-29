package grpcadapter

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// DNSMetadataToProto converts domain DNS metadata at a protobuf boundary.
func DNSMetadataToProto(m *types.DNSMetadata) *data.DNSMetadata {
	if m == nil {
		return nil
	}

	result := &data.DNSMetadata{
		TransactionId:       uint32(m.TransactionID),
		IsResponse:          m.IsResponse,
		Opcode:              m.Opcode,
		ResponseCode:        m.ResponseCode,
		Authoritative:       m.Authoritative,
		Truncated:           m.Truncated,
		RecursionDesired:    m.RecursionDesired,
		RecursionAvailable:  m.RecursionAvailable,
		AuthenticatedData:   m.AuthenticatedData,
		CheckingDisabled:    m.CheckingDisabled,
		QuestionCount:       uint32(m.QuestionCount),
		AnswerCount:         uint32(m.AnswerCount),
		AuthorityCount:      uint32(m.AuthorityCount),
		AdditionalCount:     uint32(m.AdditionalCount),
		QueryName:           m.QueryName,
		QueryType:           m.QueryType,
		QueryClass:          m.QueryClass,
		QueryResponseTimeMs: m.QueryResponseTimeMs,
		CorrelatedQuery:     m.CorrelatedQuery,
		TunnelingScore:      m.TunnelingScore,
		EntropyScore:        m.EntropyScore,
	}
	if len(m.Answers) > 0 {
		result.Answers = make([]*data.DNSAnswer, len(m.Answers))
		for i, answer := range m.Answers {
			result.Answers[i] = &data.DNSAnswer{
				Name: answer.Name, Type: answer.Type, Class: answer.Class,
				Ttl: answer.TTL, Data: answer.Data,
			}
		}
	}
	return result
}
