//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func iriTestEntry(name, value string) iripolicy.DictionaryEntry {
	return iripolicy.DictionaryEntry{Owner: "DE", Name: name, Value: value}
}

func iriTestProfileFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func iriTestLoadProfile(t *testing.T, profile iriPolicyProfile) (iriPolicyProfile, iripolicy.Profile, string) {
	t.Helper()
	data, err := json.Marshal(profile)
	require.NoError(t, err)
	loaded, capabilities, revision, err := loadIRIPolicyProfile(iriTestProfileFile(t, data))
	require.NoError(t, err)
	return loaded, capabilities, revision
}

func TestIRIPolicyProfileCanonicalRevisionAndFacts(t *testing.T) {
	format := iripolicy.DictionaryEntry{Owner: "ETSI", Name: "HandoverFormat", Value: "TS102232-5"}
	invite := iriEventMapping{Entry: iriTestEntry("IRIEvents", "Invite"), SIP: &iriSIPSelector{Method: "INVITE"}}
	response := iriEventMapping{Entry: iriTestEntry("IRIEvents", "Response"), SIP: &iriSIPSelector{Response: true}}
	nfA, nfB := iriTestEntry("NFType", "Probe"), iriTestEntry("NFType", "Edge")
	profile := iriPolicyProfile{Version: 1, NFTypes: []iripolicy.DictionaryEntry{nfA, nfB}, HandoverFormat: &format, Events: []iriEventMapping{invite, response}}
	loaded, capabilities, revision := iriTestLoadProfile(t, profile)
	require.Len(t, revision, 64)
	require.ElementsMatch(t, []iripolicy.DictionaryEntry{nfA, nfB}, capabilities.NFTypes)
	require.ElementsMatch(t, []iripolicy.DictionaryEntry{invite.Entry, response.Entry}, capabilities.Events)
	require.Equal(t, []iripolicy.DictionaryEntry{format}, capabilities.HandoverFormats)
	facts := loaded.baseFacts()
	require.True(t, facts.NFTypesKnown)
	require.ElementsMatch(t, capabilities.NFTypes, facts.NFTypes)
	require.Equal(t, &format, facts.HandoverFormat)
	require.False(t, facts.EventsKnown)

	// Mapping order, insignificant JSON, duplicate identical mappings, and the
	// spelled-out response default cannot change the administrative identity.
	profile.NFTypes = []iripolicy.DictionaryEntry{nfB, nfA}
	response.SIP = &iriSIPSelector{Response: true, StatusMin: 100, StatusMax: 699}
	profile.Events = []iriEventMapping{response, invite, invite}
	_, _, reordered := iriTestLoadProfile(t, profile)
	require.Equal(t, revision, reordered)
	profile.Events[0].SIP.StatusMin = 200
	_, _, changed := iriTestLoadProfile(t, profile)
	require.NotEqual(t, revision, changed, "classification changes must invalidate the profile revision")

	_, _, implicit, err := loadIRIPolicyProfile("")
	require.NoError(t, err)
	_, _, explicit := iriTestLoadProfile(t, iriPolicyProfile{Version: 1})
	require.Equal(t, implicit, explicit)
	pretty := []byte("{\n  \"events\": [],\n  \"version\": 1,\n  \"nf_types\": []\n}\n")
	_, _, empty, err := loadIRIPolicyProfile(iriTestProfileFile(t, pretty))
	require.NoError(t, err)
	require.Equal(t, implicit, empty)
}

func TestIRIPolicyProfileRejectsInvalidInput(t *testing.T) {
	entry := `{"Owner":"DE","Name":"IRIEvents","Value":"Start"}`
	for _, tc := range []struct{ name, input string }{
		{"empty", ""}, {"null", "null"}, {"array", "[]"},
		{"missing version", `{}`}, {"unsupported version", `{"version":2}`},
		{"string version", `{"version":"1"}`},
		{"unknown field", `{"version":1,"sensitive-unknown-field":true}`},
		{"duplicate key", `{"version":1,"version":1}`},
		{"case alias", `{"version":1,"VERSION":1}`},
		{"trailing object", `{"version":1}{"version":1}`},
		{"unknown nested field", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"unknown":1}}]}`},
		{"duplicate nested key", `{"version":1,"events":[{"entry":{"Owner":"DE","owner":"FR","Name":"IRIEvents","Value":"Start"},"sip":{}}]}`},
		{"excessive nesting", `{"version":1,"unknown":` + strings.Repeat("[", 10) + "0" + strings.Repeat("]", 10) + `}`},
		{"no selector", `{"version":1,"events":[{"entry":` + entry + `}]}`},
		{"both selectors", `{"version":1,"events":[{"entry":` + entry + `,"sip":{},"radius":{"code":1}}]}`},
		{"invented ETSI event", `{"version":1,"events":[{"entry":{"Owner":"ETSI","Name":"IRIEvents","Value":"All"},"sip":{}}]}`},
		{"lowercase method", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"method":"invite"}}]}`},
		{"invalid method token", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"method":"BAD METHOD"}}]}`},
		{"request with status", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"status_min":200,"status_max":299}}]}`},
		{"reversed status", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"response":true,"status_min":299,"status_max":200}}]}`},
		{"low status", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"response":true,"status_min":99,"status_max":200}}]}`},
		{"high status", `{"version":1,"events":[{"entry":` + entry + `,"sip":{"response":true,"status_min":200,"status_max":700}}]}`},
		{"unsupported RADIUS", `{"version":1,"events":[{"entry":` + entry + `,"radius":{"code":255}}]}`},
		{"invalid dictionary", `{"version":1,"nf_types":[{"Owner":"ETSI","Name":"NFType","Value":"Invented"}]}`},
		{"oversized", strings.Repeat(" ", maxIRIProfileBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, revision, err := loadIRIPolicyProfile(iriTestProfileFile(t, []byte(tc.input)))
			require.Error(t, err)
			require.Empty(t, revision)
			require.NotContains(t, err.Error(), "sensitive-unknown-field")
		})
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing.json")} {
		_, _, _, err := loadIRIPolicyProfile(path)
		require.Error(t, err)
		require.NotContains(t, err.Error(), path, "profile errors must not disclose configured paths")
	}
	profile := iriPolicyProfile{Version: 1}
	for i := 0; i < 257; i++ {
		profile.Events = append(profile.Events, iriEventMapping{Entry: iriTestEntry("IRIEvents", fmt.Sprintf("Event%d", i)), SIP: &iriSIPSelector{}})
	}
	data, err := json.Marshal(profile)
	require.NoError(t, err)
	_, _, _, err = loadIRIPolicyProfile(iriTestProfileFile(t, data))
	require.Error(t, err)
}

func iriTestSIP(start, cseq string) *types.PacketDisplay {
	raw := start + "\r\nFrom: <sip:a@example.invalid>;tag=a\r\nTo: <sip:b@example.invalid>\r\nCall-ID: policy@example.invalid\r\n" + cseq + "Content-Length: 0\r\n\r\n"
	return &types.PacketDisplay{RawData: []byte(raw), VoIPData: &types.VoIPMetadata{RawSIP: []byte(raw), Method: "BYE", CSeqMethod: "BYE", Status: 599}}
}

func TestIRIPolicySIPFactsUseParsedWireContent(t *testing.T) {
	invite, success := iriTestEntry("IRIEvents", "Invite"), iriTestEntry("IRIEvents", "InviteSuccess")
	profile, _, _ := iriTestLoadProfile(t, iriPolicyProfile{Version: 1, Events: []iriEventMapping{
		{Entry: invite, SIP: &iriSIPSelector{Method: "INVITE"}},
		{Entry: success, SIP: &iriSIPSelector{Method: "INVITE", Response: true, StatusMin: 200, StatusMax: 299}},
	}})
	for _, tc := range []struct {
		name, start, cseq string
		known             bool
		want              []iripolicy.DictionaryEntry
	}{
		{"request", "INVITE sip:b@example.invalid SIP/2.0", "CSeq: 1 INVITE\r\n", true, []iripolicy.DictionaryEntry{invite}},
		{"unmatched request", "BYE sip:b@example.invalid SIP/2.0", "CSeq: 1 BYE\r\n", true, nil},
		{"lower boundary", "SIP/2.0 200 OK", "CSeq: 1 INVITE\r\n", true, []iripolicy.DictionaryEntry{success}},
		{"upper boundary", "SIP/2.0 299 Result", "CSeq: 1 INVITE\r\n", true, []iripolicy.DictionaryEntry{success}},
		{"below range", "SIP/2.0 199 Result", "CSeq: 1 INVITE\r\n", true, nil},
		{"above range", "SIP/2.0 300 Result", "CSeq: 1 INVITE\r\n", true, nil},
		{"other method", "SIP/2.0 200 OK", "CSeq: 1 BYE\r\n", true, nil},
		{"missing response method", "SIP/2.0 200 OK", "", false, nil},
		{"duplicate response method", "SIP/2.0 200 OK", "CSeq: 1 INVITE\r\nCSeq: 1 BYE\r\n", false, nil},
		{"malformed", "unparseable", "", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := iriTestSIP(tc.start, tc.cseq)
			facts := profile.sipFacts(packet)
			require.Equal(t, tc.known, facts.EventsKnown)
			require.ElementsMatch(t, tc.want, facts.Events)
			packet.VoIPData.RawSIP = nil
			require.Equal(t, facts, profile.sipFacts(packet), "packet-byte fallback must agree with authoritative SIP bytes")
		})
	}
	packet := iriTestSIP("INVITE sip:b@example.invalid SIP/2.0", "CSeq: 1 INVITE\r\n")
	packet.VoIPData.RawSIP = append([]byte("untrusted-prefix\r\n"), packet.VoIPData.RawSIP...)
	require.False(t, profile.sipFacts(packet).EventsKnown, "malformed authoritative SIP must not fall back to other bytes")
	packet.VoIPData.IsRTP = true
	require.False(t, profile.sipFacts(packet).EventsKnown)
	require.False(t, profile.sipFacts(nil).EventsKnown)
}

func TestIRIPolicyRADIUSFactsAndKnownEmptyDefaults(t *testing.T) {
	profile := iriPolicyProfile{Version: 1}
	for _, code := range []uint8{1, 2, 3, 4, 5, 11} {
		profile.Events = append(profile.Events, iriEventMapping{Entry: iriTestEntry("IRIEvents", fmt.Sprintf("Code%d", code)), RADIUS: &iriRADIUSSelector{Code: code}})
	}
	loaded, capabilities, _ := iriTestLoadProfile(t, profile)
	for _, mapping := range profile.Events {
		facts := loaded.radiusFacts(&radius.Observation{Message: &radius.Message{Code: mapping.RADIUS.Code}})
		require.True(t, facts.EventsKnown)
		require.Equal(t, []iripolicy.DictionaryEntry{mapping.Entry}, facts.Events)
	}
	require.False(t, loaded.radiusFacts(nil).EventsKnown)
	require.False(t, loaded.radiusFacts(&radius.Observation{}).EventsKnown)

	// Reliable absence is distinct from a parser failure: a nonmatching event
	// reaches the standard default-deliver result instead of a policy fault.
	ruleID, policyID := uuid.New(), uuid.New()
	compiled, err := iripolicy.Compile([]uuid.UUID{policyID}, []iripolicy.Object{
		{ID: ruleID, Generation: 1, Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{profile.Events[0].Entry}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}},
		{ID: policyID, Generation: 1, Policy: &iripolicy.Policy{Rules: []iripolicy.RuleReference{{Order: 1, ObjectID: ruleID}}}},
	}, capabilities, iripolicy.Limits{})
	require.NoError(t, err)
	facts := loaded.sipFacts(iriTestSIP("BYE sip:b@example.invalid SIP/2.0", "CSeq: 1 BYE\r\n"))
	require.True(t, facts.EventsKnown)
	require.Empty(t, facts.Events)
	deliver, err := compiled.Evaluate(facts)
	require.NoError(t, err)
	require.True(t, deliver)
	deliver, err = compiled.Evaluate(loaded.radiusFacts(nil))
	require.Error(t, err)
	require.False(t, deliver)
}

func iriTestPolicy(t *testing.T, p *Processor, action string) uuid.UUID {
	t.Helper()
	ruleID, policyID := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateGenericObject(iripolicy.Object{ID: ruleID, Rule: &iripolicy.Rule{
		Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "IRIEvents", Value: "All"}}}},
		Action:   iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: action},
	}}))
	require.NoError(t, p.liManager.CreateGenericObject(iripolicy.Object{ID: policyID, Policy: &iripolicy.Policy{Rules: []iripolicy.RuleReference{{Order: 1, ObjectID: ruleID}}}}))
	return policyID
}

func TestProcessorIRIPolicyTaskIsolationAndSequenceAdmission(t *testing.T) {
	p, did, products := wireFormatProcessor(t, "etsi-8", "target-identifier")
	suppress, deliver := iriTestPolicy(t, p, "NotDelivered"), iriTestPolicy(t, p, "Delivered")
	var filters []string
	var allowed uuid.UUID
	for _, policyID := range []uuid.UUID{suppress, deliver} {
		xid := uuid.New()
		require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3, IRIPolicyReferences: []uuid.UUID{policyID}}))
		filters = append(filters, "li-"+xid.String()+"-0")
		allowed = xid
	}
	before := p.getLIEncodingStats()
	packet := correlationIntegrationSIP(dirCallID, dirTargetURI, time.Now())
	p.processLIPacketWithProvenance(packet, filters[:1], nil)
	require.Zero(t, liSequencer.Len(), "suppression must precede X2 sequence allocation")
	p.processLIPacketWithProvenance(packet, filters, nil)
	product := receiveProduct(t, products)
	require.Equal(t, allowed, product.Header.XID)
	require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
	require.Zero(t, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
	after := p.getLIEncodingStats()
	require.Equal(t, before.IRIPolicySuppressed+2, after.IRIPolicySuppressed)
	require.Equal(t, before.IRIPolicyErrors, after.IRIPolicyErrors)
	require.Equal(t, before.X2Encoded+1, after.X2Encoded)
}

func TestProcessorIRIPolicyNationalMappingEnforcedFromRawSIP(t *testing.T) {
	entry := iriTestEntry("IRIEvents", "Invite")
	data, err := json.Marshal(iriPolicyProfile{Version: 1, Events: []iriEventMapping{{Entry: entry, SIP: &iriSIPSelector{Method: "INVITE"}}}})
	require.NoError(t, err)
	cfg := storageKeyStartupConfig(t)
	cfg.ProcessorID = "national-policy-test"
	cfg.LIIRIPolicyProfileFile = iriTestProfileFile(t, data)
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	port, products := correlationMDF(t)
	did, ruleID, policyID, xid := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, ProtocolType: "X2Only"}))
	require.NoError(t, p.liManager.CreateGenericObject(iripolicy.Object{ID: ruleID, Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{entry}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}}))
	require.NoError(t, p.liManager.CreateGenericObject(iripolicy.Object{ID: policyID, Policy: &iripolicy.Policy{Rules: []iripolicy.RuleReference{{Order: 1, ObjectID: ruleID}}}}))
	target := li.TargetIdentity{Type: li.TargetTypeSIPURI, Value: "sip:a@example.invalid"}
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only, IRIPolicyReferences: []uuid.UUID{policyID}}))
	filters := []string{"li-" + xid.String() + "-0"}
	before := p.getLIEncodingStats()
	invite := iriTestSIP("INVITE sip:b@example.invalid SIP/2.0", "CSeq: 1 INVITE\r\n")
	invite.Timestamp, invite.VoIPData.CallID = time.Now(), "policy@example.invalid"
	p.processLIPacketWithProvenance(invite, filters, nil)
	require.Zero(t, liSequencer.Len(), "forged BYE metadata must not bypass the wire INVITE rule")
	bye := iriTestSIP("BYE sip:b@example.invalid SIP/2.0", "CSeq: 2 BYE\r\n")
	bye.Timestamp, bye.VoIPData.CallID, bye.VoIPData.Method = time.Now(), "policy@example.invalid", "INVITE"
	p.processLIPacketWithProvenance(bye, filters, nil)
	product := receiveProduct(t, products)
	require.Equal(t, bye.VoIPData.RawSIP, product.Payload)
	require.Zero(t, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
	after := p.getLIEncodingStats()
	require.Equal(t, before.IRIPolicySuppressed+1, after.IRIPolicySuppressed)
	require.Equal(t, before.IRIPolicyErrors, after.IRIPolicyErrors, "known empty events use default delivery")
	require.Equal(t, before.X2Encoded+1, after.X2Encoded)
}

func TestProcessorIRIPolicySuppressionPreservesMediaLearningAndDelivery(t *testing.T) {
	p, did, products := wireFormatProcessor(t, "etsi-8", "target-identifier")
	policyID := iriTestPolicy(t, p, "NotDelivered")
	xid := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3, IRIPolicyReferences: []uuid.UUID{policyID}}))
	filter := "li-" + xid.String() + "-0"
	before := p.getLIEncodingStats()
	for _, signal := range []*types.PacketDisplay{
		dirSIPPacket("INVITE "+dirTargetURI+" SIP/2.0", 0, dirRemoteURI, dirTargetURI, "", dirSDP(dirCoreAddr, dirCorePort)),
		dirSIPPacket("SIP/2.0 200 OK", 200, dirRemoteURI, dirTargetURI, "xyz", dirSDP(dirGWAddr, dirGWPort)),
	} {
		signal.Timestamp = time.Now()
		p.processLIPacketWithProvenance(signal, []string{filter}, nil)
	}
	require.Zero(t, liSequencer.Len())
	rtp := dirRTPPacket(42, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
	rtp.Timestamp = time.Now()
	p.processLIPacketWithProvenance(rtp, nil, []string{filter})
	product := receiveProduct(t, products)
	require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
	require.Equal(t, xid, product.Header.XID)
	require.Equal(t, x2x3.PayloadDirectionToTarget, product.Header.PayloadDirection)
	after := p.getLIEncodingStats()
	require.Equal(t, before.IRIPolicySuppressed+2, after.IRIPolicySuppressed)
	require.Equal(t, before.X2Encoded, after.X2Encoded)
	require.Equal(t, before.X3Encoded+1, after.X3Encoded)
}

func TestProcessorIRIPolicyRADIUSSuppressionPrecedesAllocator(t *testing.T) {
	p, did, _ := wireFormatProcessor(t, "etsi-8", "target-identifier")
	policyID := iriTestPolicy(t, p, "NotDelivered")
	xid := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "alice@example.test"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}, IRIPolicyReferences: []uuid.UUID{policyID}}))
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	batch, observations := radiusPOIBatch(t, p, task)
	before := p.getLIEncodingStats()
	p.processBatch(batch)
	require.Nil(t, p.radiusLIAllocator, "suppression must precede creation of durable RADIUS correlation state")
	require.Zero(t, liSequencer.Len())
	after := p.getLIEncodingStats()
	require.Equal(t, before.IRIPolicySuppressed+uint64(len(observations)), after.IRIPolicySuppressed)
	require.Equal(t, before.X2Encoded, after.X2Encoded)
	require.Zero(t, liDeliveryClient.QueueDepth())
}

func TestProcessorIRIPolicyInvalidProfilePrecedesOutputEffects(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	cfg.LIIRIPolicyProfileFile = iriTestProfileFile(t, []byte(`{"version":999}`))
	output := filepath.Join(t.TempDir(), "output.pcap")
	cfg.WriteFile = output
	previous := liDeliveryClient
	p, err := New(cfg)
	require.Error(t, err)
	require.Nil(t, p)
	require.Same(t, previous, liDeliveryClient)
	require.NoFileExists(t, output)
}

func TestProcessorIRIPolicyProfileWiredIntoAdministrativeCapabilities(t *testing.T) {
	entry := iriTestEntry("IRIEvents", "Invite")
	data, err := json.Marshal(iriPolicyProfile{Version: 1, Events: []iriEventMapping{{Entry: entry, SIP: &iriSIPSelector{Method: "INVITE"}}}})
	require.NoError(t, err)
	cfg := storageKeyStartupConfig(t)
	cfg.LIIRIPolicyProfileFile = iriTestProfileFile(t, data)
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	rule := iripolicy.Object{ID: uuid.New(), Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{entry}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}}
	require.NoError(t, p.liManager.CreateGenericObject(rule))
	rule.ID = uuid.New()
	rule.Rule.Criteria[0].Events[0].Value = "Unconfigured"
	require.Error(t, p.liManager.CreateGenericObject(rule), "undeclared classifications must fail provisioning")
}

func TestProcessorIRIPolicyTelemetryMapsGraphAndOutcomes(t *testing.T) {
	p, did, _ := wireFormatProcessor(t, "etsi-8", "target-identifier")
	policyID := iriTestPolicy(t, p, "NotDelivered")
	xid := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3, IRIPolicyReferences: []uuid.UUID{policyID}}))
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	before := p.getLIEncodingStats()
	require.False(t, p.allowIRI(task, iripolicy.Facts{}))
	task.ActivationGeneration++
	require.False(t, p.allowIRI(task, iripolicy.Facts{}), "unavailable current policy must be accounted separately from an explicit suppression")
	dst := &management.ProcessorStats{}
	p.populateLIEncodingStats(dst)
	require.NotNil(t, dst.LiIriPolicy)
	require.Equal(t, uint64(2), dst.LiIriPolicy.Objects)
	require.Equal(t, uint64(1), dst.LiIriPolicy.Policies)
	require.Equal(t, uint64(1), dst.LiIriPolicy.Rules)
	require.Equal(t, uint64(2), dst.LiIriPolicy.ConfirmedObjects)
	require.Equal(t, before.IRIPolicySuppressed+1, dst.LiIriPolicy.Suppressed)
	require.Equal(t, before.IRIPolicyErrors+1, dst.LiIriPolicy.EvaluationErrors)
	second := &management.ProcessorStats{}
	p.populateLIEncodingStats(second)
	require.Equal(t, dst.LiIriPolicy, second.LiIriPolicy, "reading telemetry must not increment outcome counters")
}

func TestProcessorIRIPolicyUpdateWithdrawsBothQueuedProducts(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	cfg.ProcessorID = "policy-queue-withdrawal"
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	// A reserved TCP port without a TLS responder keeps transport claims live
	// while both products queue. The policy update must join those claims.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() {
		if listener != nil {
			require.NoError(t, listener.Close())
		}
	})
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3"}))
	policyID := iriTestPolicy(t, p, "Delivered")
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3, IRIPolicyReferences: []uuid.UUID{policyID}}))
	held, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	filter := "li-" + xid.String() + "-0"
	packet := correlationIntegrationSIP(dirCallID, dirTargetURI, time.Now())
	p.processLIPacketWithProvenance(packet, []string{filter}, nil)
	p.processLIPacketWithProvenance(orderedRTP(1, 42, "synthetic"), nil, []string{filter})
	require.NoError(t, p.liStorage.client.FlushPersistence(context.Background()))
	require.Eventually(t, func() bool { return p.liStorage.client.QueueDepth() == 2 }, time.Second, time.Millisecond)
	before := p.liStorage.client.Stats()
	policy, err := p.liManager.GetGenericObject(policyID)
	require.NoError(t, err)
	rule, err := p.liManager.GetGenericObject(policy.Policy.Rules[0].ObjectID)
	require.NoError(t, err)
	rule.Rule.Action.Value = "NotDelivered"
	require.NoError(t, p.liManager.ModifyGenericObject(rule))
	current, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Greater(t, current.ActivationGeneration, held.ActivationGeneration)
	require.Zero(t, p.liStorage.client.QueueDepth())
	after := p.liStorage.client.Stats()
	require.Equal(t, before.X2Dropped+1, after.X2Dropped, "policy generation changes withdraw already queued IRI")
	require.Equal(t, before.X3Dropped+1, after.X3Dropped, "policy generation changes also withdraw old-generation CC")
	require.NoError(t, p.liStorage.client.FlushPersistence(context.Background()))
	require.Zero(t, p.liStorage.client.JournalStats().Retained)

	require.NoError(t, listener.Close())
	listener = nil
	products := (&persistentProcessorFixture{address: address}).listenMDF(t)
	packet.Timestamp = time.Now()
	p.processLIPacketWithProvenance(packet, []string{filter}, nil)
	rtp := orderedRTP(2, 43, "synthetic")
	p.processLIPacketWithProvenance(rtp, nil, []string{filter})
	product := receiveProduct(t, products)
	require.Equal(t, x2x3.PDUTypeX3, product.Header.Type, "the new policy suppresses IRI while allowing current-generation CC")
	require.Equal(t, rtp.RawData, product.Payload, "neither old queued product may cross the transport boundary")
	require.Equal(t, xid, product.Header.XID)
}
