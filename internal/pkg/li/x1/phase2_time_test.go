//go:build li

package x1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func mediationTime(value string) *schema.QualifiedMicrosecondDateTime {
	v := schema.QualifiedMicrosecondDateTime(value)
	return &v
}

func TestExtractMediationWindow(t *testing.T) {
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	end := start.Add(time.Hour)
	list := &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{
		{StartTime: mediationTime(start.Format(time.RFC3339Nano)), EndTime: mediationTime(end.Format(time.RFC3339Nano))},
		{StartTime: mediationTime(start.Format(time.RFC3339Nano)), EndTime: mediationTime(end.Format(time.RFC3339Nano))},
	}}
	gotStart, gotEnd, err := extractMediationWindow(list)
	require.NoError(t, err)
	assert.Equal(t, start, gotStart)
	assert.Equal(t, end, gotEnd)

	list.MediationDetails[1].EndTime = mediationTime(end.Add(time.Second).Format(time.RFC3339Nano))
	_, _, err = extractMediationWindow(list)
	assert.ErrorContains(t, err, "inconsistent")
}

func TestExtractMediationWindowRejectsMalformedAndReversed(t *testing.T) {
	_, _, err := extractMediationWindow(&schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{StartTime: mediationTime("invalid")}}})
	assert.Error(t, err)
	start := time.Now().UTC()
	_, _, err = extractMediationWindow(&schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{
		StartTime: mediationTime(start.Format(time.RFC3339Nano)), EndTime: mediationTime(start.Format(time.RFC3339Nano)),
	}}})
	assert.ErrorContains(t, err, "must be after")
}
