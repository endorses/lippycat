package types

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/stretchr/testify/require"
)

func TestSMSRecordsPreserveContentAndBoundAssemblyUpdates(t *testing.T) {
	original := SMSRecord{TransactionID: "first", Message: &sms.Message{Status: sms.StatusDecoded, Text: "first", Assembly: sms.AssemblyInfo{ID: "group", Status: sms.AssemblyComplete, Text: "first second"}}}
	result := MergeSMSRecords([]SMSRecord{original}, []SMSRecord{{TransactionID: "first", Message: &sms.Message{Status: sms.StatusMalformed}}})
	require.Equal(t, "first", result[0].Message.Text)
	result = UpdateSMSAssembly(result, &sms.Message{Assembly: sms.AssemblyInfo{ID: "group", Status: sms.AssemblyExpired}})
	require.Equal(t, sms.AssemblyComplete, result[0].Message.Assembly.Status)
	result = MergeSMSRecords(result, []SMSRecord{{TransactionID: "first", Message: &sms.Message{Status: sms.StatusDecoded, Text: "changed"}}})
	require.Equal(t, "first", result[0].Message.Text)
	require.Equal(t, sms.AssemblyConflict, result[0].Message.Assembly.Status)
	records := make([]SMSRecord, SMSRecordLimit)
	for i := range records {
		records[i] = SMSRecord{TransactionID: string(rune('a' + i)), Message: &sms.Message{Status: sms.StatusDecoded, Text: "segment", Assembly: sms.AssemblyInfo{ID: "group", Status: sms.AssemblyPending}}}
	}
	result = UpdateSMSAssembly(records, &sms.Message{Assembly: sms.AssemblyInfo{ID: "group", Status: sms.AssemblyComplete, Text: strings.Repeat("x", 40000)}})
	require.LessOrEqual(t, SMSRecordsBytes(result), smsRecordByteLimit)
	require.Less(t, len(result), len(records))
	original.Message.Text = "caller mutation"
	require.Equal(t, "first", MergeSMSRecords(nil, []SMSRecord{{TransactionID: "second", Message: &sms.Message{Text: "first"}}})[0].Message.Text)
}

func TestSMSDisplayAssemblerLifecycleAndSourceIsolation(t *testing.T) {
	at := time.Unix(100, 0)
	part := func(n uint8) *sms.Message {
		return &sms.Message{Status: sms.StatusDecoded, Text: fmt.Sprint(n), Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: n}, Assembly: sms.AssemblyInfo{ID: "producer-id", Status: sms.AssemblyPending}}
	}
	var tracker SMSDisplayAssembler
	first := tracker.Add("source-a", part(1), at)
	other := tracker.Add("source-b", part(2), at)
	require.NotEqual(t, first.Assembly.ID, other.Assembly.ID)
	require.Equal(t, sms.AssemblyPending, other.Assembly.Status)
	complete := part(2)
	complete.Assembly = sms.AssemblyInfo{ID: "producer-id", Status: sms.AssemblyComplete, Text: "12", Received: []uint8{1, 2}}
	result := tracker.Add("source-a", complete, at.Add(time.Second))
	require.Equal(t, first.Assembly.ID, result.Assembly.ID)
	require.Equal(t, "12", result.Assembly.Text)
	records := []SMSRecord{{TransactionID: "first", Message: result}}
	expired := tracker.Expire(at.Add(5 * time.Minute))
	require.Len(t, expired, 2)
	for _, message := range expired {
		records = UpdateSMSAssembly(records, message)
	}
	require.Equal(t, sms.AssemblyComplete, records[0].Message.Assembly.Status)
	require.Empty(t, tracker.aliases)
	require.Zero(t, tracker.assembler.Stats().Assemblies)
	tracker.Close()
	require.Empty(t, tracker.aliases)
	tracker.Add("new", part(1), at.Add(6*time.Minute))
	require.Zero(t, tracker.assembler.Stats().Assemblies)
}

func TestSMSDisplayAssemblerForgetsContributingSegments(t *testing.T) {
	at := time.Unix(100, 0)
	message := &sms.Message{Status: sms.StatusDecoded, Text: "first", Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: 1}}
	var tracker SMSDisplayAssembler
	first := tracker.Add("source", message, at)
	tracker.Forget(first)
	require.Empty(t, tracker.aliases)
	require.Zero(t, tracker.assembler.Stats().Bytes)
	message.Text = "second"
	message.Concat.Part = 2
	second := tracker.Add("source", message, at.Add(time.Second))
	require.Equal(t, sms.AssemblyPending, second.Assembly.Status)
	require.NotEqual(t, first.Assembly.ID, second.Assembly.ID)
	require.Equal(t, []uint8{1}, second.Assembly.Missing)
	tracker.Close()
}

func TestSMSDisplayAssemblerPreservesProducerNegativeOutcomes(t *testing.T) {
	for _, status := range []sms.AssemblyStatus{sms.AssemblyConflict, sms.AssemblyExpired, sms.AssemblyResourceLimited} {
		t.Run(string(status), func(t *testing.T) {
			part := func(n uint8) *sms.Message {
				return &sms.Message{Status: sms.StatusDecoded, Text: fmt.Sprint(n), Direction: sms.DirectionMO, To: "+123", Concat: &sms.Concatenation{Reference: 42, ReferenceBits: 8, Total: 2, Part: n}, Assembly: sms.AssemblyInfo{ID: "G", Status: status}}
			}
			var late SMSDisplayAssembler
			first := late.Add("source", part(1), time.Unix(100, 0))
			second := late.Add("source", part(2), time.Unix(101, 0))
			require.Equal(t, status, first.Assembly.Status)
			require.Equal(t, status, second.Assembly.Status)
			require.Equal(t, first.Assembly.ID, second.Assembly.ID)
			require.Nil(t, late.assembler, "producer-rejected segments must not seed a fresh local group")
			var observed SMSDisplayAssembler
			pending := part(1)
			pending.Assembly.Status = sms.AssemblyPending
			original := observed.Add("source", pending, time.Unix(100, 0))
			terminal := observed.Add("source", part(2), time.Unix(101, 0))
			require.Equal(t, original.Assembly.ID, terminal.Assembly.ID, "resolve producer G through its local generation")
			records := UpdateSuppliedSMSAssembly([]SMSRecord{{TransactionID: "first", Message: original}}, terminal)
			require.Equal(t, status, records[0].Message.Assembly.Status)
			require.Empty(t, observed.Expire(time.Unix(500, 0)), "local expiry must not rewrite the producer outcome")
			require.Equal(t, "1", records[0].Message.Text)
		})
	}
}

func TestSuppliedSMSExpiryIsDistinctFromLocalDeduplicationExpiry(t *testing.T) {
	records := []SMSRecord{{TransactionID: "first", Message: &sms.Message{Status: sms.StatusDecoded, Text: "part", Assembly: sms.AssemblyInfo{ID: "G", Status: sms.AssemblyComplete, Text: "complete"}}}}
	expired := &sms.Message{Assembly: sms.AssemblyInfo{ID: "G", Status: sms.AssemblyExpired}}
	require.Equal(t, sms.AssemblyComplete, UpdateSMSAssembly(records, expired)[0].Message.Assembly.Status)
	require.Equal(t, sms.AssemblyExpired, UpdateSuppliedSMSAssembly(records, expired)[0].Message.Assembly.Status)
}
