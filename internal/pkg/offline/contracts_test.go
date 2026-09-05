package offline

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

func TestResourceLimitsRejectUnusableRecordBudgets(t *testing.T) {
	valid := ResourceLimits{Directory: t.TempDir(), DiskBytes: 4096, CacheBytes: 1024, MaxRecordBytes: 512, MaxSources: 4}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []ResourceLimits{{}, {Directory: valid.Directory, DiskBytes: 4096, CacheBytes: 1024, MaxRecordBytes: 2048, MaxSources: 4}, {Directory: valid.Directory, DiskBytes: 256, CacheBytes: 1024, MaxRecordBytes: 512, MaxSources: 4}, {Directory: valid.Directory, DiskBytes: 4096, CacheBytes: 1024, MaxRecordBytes: 512}}
	for i, limits := range cases {
		if limits.Validate() == nil {
			t.Errorf("case %d accepted invalid limits", i)
		}
	}
}

func TestTimestampRegressionIncludesDisambiguatedSource(t *testing.T) {
	err := &TimestampRegressionError{Source: SourcePosition{Path: "/first/same.pcapng", ArgumentIndex: 2, InterfaceID: 3, Sequence: 42}, Previous: time.Unix(2, 0).UTC(), Current: time.Unix(1, 0).UTC()}
	for _, part := range []string{"/first/same.pcapng", "argument 2", "interface 3", "sequence 42", "1970-01-01T00:00:01Z", "1970-01-01T00:00:02Z"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error missing %q: %s", part, err)
		}
	}
}

func TestSummaryDisplayFieldsNeedNoDetails(t *testing.T) {
	p := types.PacketDisplay{Timestamp: time.Unix(12, 34), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "123", DstPort: "456", Protocol: "SIP", Transport: 17, Length: 99, Info: "INVITE", NodeID: "Local", Interface: "eth0", LinkType: layers.LinkTypeEthernet, RawData: []byte{1}, VoIPData: &types.VoIPMetadata{User: "Alice"}}
	s := NewSummary(1, p)
	got := s.DisplayFields()
	p.RawData, p.VoIPData = nil, nil
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("display fields differ: %#v", got)
	}
	got.Info = "changed"
	if s.GetStringField("info") != "INVITE" {
		t.Fatal("display aliases summary")
	}
}
