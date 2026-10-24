//go:build tui || all

package store

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCallStoreRetainsOwnedBoundedSMSTransactions(t *testing.T) {
	store := NewCallStore(1)
	message := &sms.Message{Status: sms.StatusDecoded, Text: "original", Concat: &sms.Concatenation{Part: 1, Total: 2}, Assembly: sms.AssemblyInfo{Missing: []uint8{2}}}
	store.AddOrUpdateCall(components.Call{CallID: "sms", SMS: []types.SMSRecord{{TransactionID: "tx", Message: message}}})
	message.Text = "changed"
	message.Assembly.Missing[0] = 3
	store.AddOrUpdateCall(components.Call{CallID: "sms", State: components.CallStateMessage})
	got, ok := store.GetCall("sms")
	require.True(t, ok)
	require.Len(t, got.SMS, 1)
	require.Equal(t, "original", got.SMS[0].Message.Text)
	require.Equal(t, []uint8{2}, got.SMS[0].Message.Assembly.Missing)
	got.SMS[0].Message.Text = "caller mutation"
	require.Equal(t, "original", store.GetCallsInOrder()[0].SMS[0].Message.Text)
	for i := 0; i < types.SMSRecordLimit+4; i++ {
		store.AddOrUpdateCall(components.Call{CallID: "sms", SMS: []types.SMSRecord{{TransactionID: fmt.Sprint(i), Message: &sms.Message{Status: sms.StatusDecoded, Text: fmt.Sprint(i)}}}})
	}
	require.Len(t, store.GetCallsInOrder()[0].SMS, types.SMSRecordLimit)
	store.AddOrUpdateCall(components.Call{CallID: "other"})
	_, ok = store.GetCall("sms")
	require.False(t, ok)
}

func TestCallStoreClearReleasesSMSContent(t *testing.T) {
	store := NewCallStore(2)
	store.AddOrUpdateCall(components.Call{CallID: "sms", SMS: []types.SMSRecord{{TransactionID: "tx", Message: &sms.Message{Status: sms.StatusDecoded, Text: "text"}}}})
	require.NotEmpty(t, store.GetCallsInOrder())
	store.Clear()
	require.Empty(t, store.GetCallsInOrder())
	require.Empty(t, store.GetFilteredCalls())
	require.Empty(t, store.cachedCalls)
	require.Empty(t, store.calls)
}
