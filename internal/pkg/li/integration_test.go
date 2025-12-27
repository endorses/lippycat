//go:build li

package li_test

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ============================================================================
// Mock ADMF Server for X1 Testing
// ============================================================================

// MockADMFServer simulates an ADMF (Administration Function) for X1 testing.
// It receives notifications from the NE (Network Element) via the X1 client.
type MockADMFServer struct {
	mu sync.Mutex

	// Server is the underlying HTTP test server.
	Server *httptest.Server

	// Requests records all received requests.
	Requests []MockADMFRequest

	// KeepaliveCount tracks the number of keepalive requests received.
	KeepaliveCount int

	// TaskReports tracks task issue reports by XID.
	TaskReports map[uuid.UUID][]MockTaskReport

	// DestinationReports tracks destination issue reports by DID.
	DestinationReports map[uuid.UUID][]MockDestinationReport

	// NEReports tracks NE issue reports.
	NEReports []MockNEReport

	// ResponseHandler allows tests to customize responses.
	ResponseHandler func(reqType string, body []byte) (int, []byte)
}

// MockADMFRequest represents a request received by the mock ADMF.
type MockADMFRequest struct {
	Type      string
	Body      []byte
	Timestamp time.Time
}

// MockTaskReport represents a task issue report.
type MockTaskReport struct {
	XID        uuid.UUID
	ReportType string
	ErrorCode  *int
	Details    string
	Timestamp  time.Time
}

// MockDestinationReport represents a destination issue report.
type MockDestinationReport struct {
	DID        uuid.UUID
	ReportType string
	ErrorCode  *int
	Details    string
	Timestamp  time.Time
}

// MockNEReport represents an NE issue report.
type MockNEReport struct {
	IssueType   string
	Description string
	IssueCode   *int
	Timestamp   time.Time
}

// NewMockADMFServer creates a new mock ADMF server.
func NewMockADMFServer() *MockADMFServer {
	m := &MockADMFServer{
		TaskReports:        make(map[uuid.UUID][]MockTaskReport),
		DestinationReports: make(map[uuid.UUID][]MockDestinationReport),
	}

	m.Server = httptest.NewServer(http.HandlerFunc(m.handleRequest))
	return m
}

// NewMockADMFServerTLS creates a new mock ADMF server with TLS.
func NewMockADMFServerTLS(certFile, keyFile string) (*MockADMFServer, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	m := &MockADMFServer{
		TaskReports:        make(map[uuid.UUID][]MockTaskReport),
		DestinationReports: make(map[uuid.UUID][]MockDestinationReport),
	}

	m.Server = httptest.NewUnstartedServer(http.HandlerFunc(m.handleRequest))
	m.Server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	m.Server.StartTLS()

	return m, nil
}

// Close shuts down the mock ADMF server.
func (m *MockADMFServer) Close() {
	m.Server.Close()
}

// URL returns the server URL.
func (m *MockADMFServer) URL() string {
	return m.Server.URL
}

// handleRequest processes incoming X1 requests.
func (m *MockADMFServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Detect request type from XML root element
	var rootDetector struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(body, &rootDetector); err != nil {
		http.Error(w, "invalid XML", http.StatusBadRequest)
		return
	}

	reqType := rootDetector.XMLName.Local

	m.mu.Lock()
	m.Requests = append(m.Requests, MockADMFRequest{
		Type:      reqType,
		Body:      body,
		Timestamp: time.Now(),
	})

	// Parse specific request types
	switch reqType {
	case "KeepaliveRequest", "keepaliveRequest":
		m.KeepaliveCount++

	case "ReportTaskIssueRequest", "reportTaskIssueRequest":
		m.parseTaskReport(body)

	case "ReportDestinationIssueRequest", "reportDestinationIssueRequest":
		m.parseDestinationReport(body)

	case "ReportNEIssueRequest", "reportNEIssueRequest":
		m.parseNEReport(body)
	}
	m.mu.Unlock()

	// Allow tests to customize response
	if m.ResponseHandler != nil {
		status, respBody := m.ResponseHandler(reqType, body)
		w.WriteHeader(status)
		w.Write(respBody)
		return
	}

	// Default: return success response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<responseContainer>
  <x1ResponseMessage>
    <neIdentifier>mock-admf</neIdentifier>
  </x1ResponseMessage>
</responseContainer>`))
}

// parseTaskReport parses a task issue report.
func (m *MockADMFServer) parseTaskReport(body []byte) {
	var req schema.ReportTaskIssueRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return
	}

	if req.XId == nil {
		return
	}

	xid, err := uuid.Parse(string(*req.XId))
	if err != nil {
		return
	}

	report := MockTaskReport{
		XID:        xid,
		ReportType: req.TaskReportType,
		ErrorCode:  req.TaskIssueErrorCode,
		Timestamp:  time.Now(),
	}
	if req.TaskIssueDetails != nil {
		report.Details = *req.TaskIssueDetails
	}

	m.TaskReports[xid] = append(m.TaskReports[xid], report)
}

// parseDestinationReport parses a destination issue report.
func (m *MockADMFServer) parseDestinationReport(body []byte) {
	var req schema.ReportDestinationIssueRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return
	}

	if req.DId == nil {
		return
	}

	did, err := uuid.Parse(string(*req.DId))
	if err != nil {
		return
	}

	report := MockDestinationReport{
		DID:        did,
		ReportType: req.DestinationReportType,
		ErrorCode:  req.DestinationIssueErrorCode,
		Timestamp:  time.Now(),
	}
	if req.DestinationIssueDetails != nil {
		report.Details = *req.DestinationIssueDetails
	}

	m.DestinationReports[did] = append(m.DestinationReports[did], report)
}

// parseNEReport parses an NE issue report.
func (m *MockADMFServer) parseNEReport(body []byte) {
	var req schema.ReportNEIssueRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return
	}

	report := MockNEReport{
		IssueType:   req.TypeOfNeIssueMessage,
		Description: req.Description,
		IssueCode:   req.IssueCode,
		Timestamp:   time.Now(),
	}

	m.NEReports = append(m.NEReports, report)
}

// GetKeepaliveCount returns the number of keepalive requests received.
func (m *MockADMFServer) GetKeepaliveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KeepaliveCount
}

// GetTaskReports returns task reports for a given XID.
func (m *MockADMFServer) GetTaskReports(xid uuid.UUID) []MockTaskReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.TaskReports[xid]
}

// GetNEReports returns all NE reports.
func (m *MockADMFServer) GetNEReports() []MockNEReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.NEReports
}

// GetRequestCount returns the total number of requests received.
func (m *MockADMFServer) GetRequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Requests)
}

// WaitForRequest waits for a specific number of requests with timeout.
func (m *MockADMFServer) WaitForRequest(count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.GetRequestCount() >= count {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// ============================================================================
// Mock MDF Server for X2/X3 Testing
// ============================================================================

// MockMDFServer simulates an MDF (Mediation/Delivery Function) for X2/X3 testing.
// It receives X2 IRI and X3 CC PDUs from the delivery client.
type MockMDFServer struct {
	mu       sync.Mutex
	listener net.Listener
	conns    []net.Conn
	stopChan chan struct{}
	wg       sync.WaitGroup

	// ReceivedPDUs stores all received PDU data.
	ReceivedPDUs []MockPDU

	// X2Count tracks X2 (IRI) PDUs received.
	X2Count int

	// X3Count tracks X3 (CC) PDUs received.
	X3Count int

	// TotalBytes tracks total bytes received.
	TotalBytes uint64
}

// mockPDUType represents the PDU type (local to avoid x2x3 dependency).
type mockPDUType uint8

const (
	mockPDUTypeX2 mockPDUType = 1 // X2 IRI PDU
	mockPDUTypeX3 mockPDUType = 2 // X3 CC PDU
)

// MockPDU represents a received PDU.
type MockPDU struct {
	Type      mockPDUType
	Data      []byte
	Timestamp time.Time
}

// NewMockMDFServer creates a new mock MDF server.
func NewMockMDFServer() (*MockMDFServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	m := &MockMDFServer{
		listener: listener,
		stopChan: make(chan struct{}),
	}

	m.wg.Add(1)
	go m.acceptLoop()

	return m, nil
}

// NewMockMDFServerTLS creates a new mock MDF server with TLS.
func NewMockMDFServerTLS(certFile, keyFile string) (*MockMDFServer, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS listener: %w", err)
	}

	m := &MockMDFServer{
		listener: listener,
		stopChan: make(chan struct{}),
	}

	m.wg.Add(1)
	go m.acceptLoop()

	return m, nil
}

// Addr returns the server address.
func (m *MockMDFServer) Addr() net.Addr {
	return m.listener.Addr()
}

// Close shuts down the mock MDF server.
func (m *MockMDFServer) Close() {
	close(m.stopChan)
	m.listener.Close()

	m.mu.Lock()
	for _, conn := range m.conns {
		conn.Close()
	}
	m.mu.Unlock()

	m.wg.Wait()
}

// acceptLoop accepts incoming connections.
func (m *MockMDFServer) acceptLoop() {
	defer m.wg.Done()

	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				return
			default:
				continue
			}
		}

		m.mu.Lock()
		m.conns = append(m.conns, conn)
		m.mu.Unlock()

		m.wg.Add(1)
		go m.handleConnection(conn)
	}
}

// handleConnection reads PDUs from a connection.
func (m *MockMDFServer) handleConnection(conn net.Conn) {
	defer m.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			m.mu.Lock()
			m.TotalBytes += uint64(n)

			// Try to detect PDU type from header
			pduType := mockPDUTypeX2 // Default
			if n >= 4 && data[3] == byte(mockPDUTypeX3) {
				pduType = mockPDUTypeX3
				m.X3Count++
			} else {
				m.X2Count++
			}

			m.ReceivedPDUs = append(m.ReceivedPDUs, MockPDU{
				Type:      pduType,
				Data:      data,
				Timestamp: time.Now(),
			})
			m.mu.Unlock()
		}
	}
}

// GetX2Count returns the number of X2 PDUs received.
func (m *MockMDFServer) GetX2Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.X2Count
}

// GetX3Count returns the number of X3 PDUs received.
func (m *MockMDFServer) GetX3Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.X3Count
}

// GetTotalPDUs returns the total number of PDUs received.
func (m *MockMDFServer) GetTotalPDUs() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ReceivedPDUs)
}

// GetTotalBytes returns total bytes received.
func (m *MockMDFServer) GetTotalBytes() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.TotalBytes
}

// WaitForPDUs waits for a specific number of PDUs with timeout.
func (m *MockMDFServer) WaitForPDUs(count int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.GetTotalPDUs() >= count {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// ============================================================================
// Mock Filter Pusher for Testing
// ============================================================================

// mockFilterPusher implements FilterPusher for testing.
type mockFilterPusher struct {
	mu            sync.Mutex
	updatedCount  int
	deletedCount  int
	updateErr     error
	deleteErr     error
	filterUpdates []*management.Filter
	filterDeletes []string
}

func newMockFilterPusher() *mockFilterPusher {
	return &mockFilterPusher{}
}

func (m *mockFilterPusher) UpdateFilter(filter *management.Filter) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updatedCount++
	m.filterUpdates = append(m.filterUpdates, filter)
	return m.updateErr
}

func (m *mockFilterPusher) DeleteFilter(filterID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedCount++
	m.filterDeletes = append(m.filterDeletes, filterID)
	return m.deleteErr
}

// Ensure mockFilterPusher implements li.FilterPusher.
var _ li.FilterPusher = (*mockFilterPusher)(nil)

// ============================================================================
// Integration Tests
// ============================================================================

// TestIntegration_MockADMFServer tests the mock ADMF server functionality.
func TestIntegration_MockADMFServer(t *testing.T) {
	admf := NewMockADMFServer()
	defer admf.Close()

	// Create X1 client pointing to mock ADMF (without TLS for simplicity)
	// Note: In a real test, you'd configure proper TLS
	config := x1.ClientConfig{
		ADMFEndpoint:      admf.URL(),
		NEIdentifier:      "test-ne",
		KeepaliveInterval: 0, // Disable keepalive loop
		RequestTimeout:    5 * time.Second,
		MaxRetries:        0, // No retries for tests
	}

	// Build a client that skips TLS verification for testing
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Send a test XML request (simulating a keepalive)
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<KeepaliveRequest>
  <neIdentifier>test-ne</neIdentifier>
</KeepaliveRequest>`
	resp, err := client.Post(admf.URL(), "application/xml", strings.NewReader(xmlBody))
	require.NoError(t, err)
	resp.Body.Close()

	// Verify request was received
	assert.True(t, admf.WaitForRequest(1, time.Second))
	assert.Equal(t, 1, admf.GetRequestCount())
	assert.Equal(t, 1, admf.GetKeepaliveCount())

	// Suppress unused variable warning
	_ = config
}

// TestIntegration_MockMDFServer tests the mock MDF server functionality.
func TestIntegration_MockMDFServer(t *testing.T) {
	mdf, err := NewMockMDFServer()
	require.NoError(t, err)
	defer mdf.Close()

	// Connect to MDF
	conn, err := net.Dial("tcp", mdf.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Send some test data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Wait for data to be received
	assert.True(t, mdf.WaitForPDUs(1, time.Second))
	assert.Equal(t, 1, mdf.GetTotalPDUs())
	assert.Equal(t, uint64(5), mdf.GetTotalBytes())
}

// TestIntegration_FullFlow_TaskActivation tests the complete task activation flow.
func TestIntegration_FullFlow_TaskActivation(t *testing.T) {
	// Create mock filter pusher
	filterPusher := newMockFilterPusher()

	// Create LI Manager without ADMF/X1 server for this test
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	// Track deactivation callbacks
	var deactivatedTasks []uuid.UUID
	var deactivatedReasons []li.DeactivationReason
	var deactivationMu sync.Mutex

	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		deactivationMu.Lock()
		defer deactivationMu.Unlock()
		deactivatedTasks = append(deactivatedTasks, task.XID)
		deactivatedReasons = append(deactivatedReasons, reason)
	}

	manager := li.NewManager(config, deactivationCallback)
	require.NotNil(t, manager)

	// Create a destination first (required for task)
	did := uuid.New()
	dest := &li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	}
	err := manager.CreateDestination(dest)
	require.NoError(t, err)

	// Create and activate a task
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
			{Type: li.TargetTypeTELURI, Value: "tel:+15551234567"},
		},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   li.DeliveryX2andX3,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Verify task is active
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Equal(t, li.TaskStatusActive, retrievedTask.Status)
	assert.Len(t, retrievedTask.Targets, 2)

	// Verify filters were created
	assert.Equal(t, 2, manager.FilterCount())

	// Track matched packets
	var matchedPackets []*types.PacketDisplay
	var matchedTasks []*li.InterceptTask
	var matchMu sync.Mutex

	manager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		matchMu.Lock()
		defer matchMu.Unlock()
		matchedPackets = append(matchedPackets, pkt)
		matchedTasks = append(matchedTasks, task)
	})

	// Deactivate task
	err = manager.DeactivateTask(xid)
	require.NoError(t, err)

	// Verify task is deactivated
	retrievedTask, err = manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Equal(t, li.TaskStatusDeactivated, retrievedTask.Status)

	// Verify filters were removed
	assert.Equal(t, 0, manager.FilterCount())
}

// TestIntegration_ModifyTask_AtomicUpdate tests atomic task modification.
func TestIntegration_ModifyTask_AtomicUpdate(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	manager := li.NewManager(config, nil)

	// Create destinations
	did1 := uuid.New()
	did2 := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did1,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	})
	require.NoError(t, err)

	err = manager.CreateDestination(&li.Destination{
		DID:       did2,
		Address:   "192.168.1.101",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	})
	require.NoError(t, err)

	// Create and activate a task
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{did1},
		DeliveryType:   li.DeliveryX2Only,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Modify task with new targets and destinations
	newTargets := []li.TargetIdentity{
		{Type: li.TargetTypeSIPURI, Value: "sip:bob@example.com"},
		{Type: li.TargetTypeIPv4Address, Value: "10.0.0.1"},
	}
	newDests := []uuid.UUID{did1, did2}
	newDeliveryType := li.DeliveryX2andX3

	mod := &li.TaskModification{
		Targets:        &newTargets,
		DestinationIDs: &newDests,
		DeliveryType:   &newDeliveryType,
	}

	err = manager.ModifyTask(xid, mod)
	require.NoError(t, err)

	// Verify modifications were applied
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)

	assert.Len(t, retrievedTask.Targets, 2)
	assert.Equal(t, "sip:bob@example.com", retrievedTask.Targets[0].Value)
	assert.Equal(t, "10.0.0.1", retrievedTask.Targets[1].Value)

	assert.Len(t, retrievedTask.DestinationIDs, 2)
	assert.Equal(t, li.DeliveryX2andX3, retrievedTask.DeliveryType)
}

// TestIntegration_ModifyTask_RejectionOnInvalidDestination tests that ModifyTask
// rejects the entire modification if any destination is invalid.
func TestIntegration_ModifyTask_RejectionOnInvalidDestination(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	manager := li.NewManager(config, nil)

	// Create one destination
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	// Create and activate a task
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   li.DeliveryX2Only,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Try to modify with invalid destination
	invalidDID := uuid.New() // This destination doesn't exist
	newDests := []uuid.UUID{did, invalidDID}

	mod := &li.TaskModification{
		DestinationIDs: &newDests,
	}

	err = manager.ModifyTask(xid, mod)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Verify original task is unchanged
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Len(t, retrievedTask.DestinationIDs, 1)
	assert.Equal(t, did, retrievedTask.DestinationIDs[0])
}

// TestIntegration_DeactivateTask_StopsInterception tests that deactivation
// properly stops interception and cleans up filters.
func TestIntegration_DeactivateTask_StopsInterception(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	manager := li.NewManager(config, nil)

	// Create destination
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	})
	require.NoError(t, err)

	// Create and activate a task
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   li.DeliveryX2andX3,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Verify task is active and filters exist
	assert.Equal(t, 1, manager.ActiveTaskCount())
	assert.Equal(t, 1, manager.FilterCount())

	// Deactivate task
	err = manager.DeactivateTask(xid)
	require.NoError(t, err)

	// Verify task is deactivated
	assert.Equal(t, 0, manager.ActiveTaskCount())

	// Verify filters were removed
	assert.Equal(t, 0, manager.FilterCount())

	// Verify task status
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Equal(t, li.TaskStatusDeactivated, retrievedTask.Status)
	assert.False(t, retrievedTask.DeactivatedAt.IsZero())
}

// TestIntegration_ImplicitDeactivation_EnforcesEndTime tests that tasks with
// ImplicitDeactivationAllowed=true are deactivated when EndTime is reached.
func TestIntegration_ImplicitDeactivation_EnforcesEndTime(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	var deactivatedXIDs []uuid.UUID
	var deactivatedReasons []li.DeactivationReason
	var mu sync.Mutex

	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		mu.Lock()
		defer mu.Unlock()
		deactivatedXIDs = append(deactivatedXIDs, task.XID)
		deactivatedReasons = append(deactivatedReasons, reason)
	}

	manager := li.NewManager(config, deactivationCallback)
	require.NoError(t, manager.Start())
	defer manager.Stop()

	// Create destination
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	// Create task with EndTime in the past and ImplicitDeactivationAllowed=true
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs:              []uuid.UUID{did},
		DeliveryType:                li.DeliveryX2andX3,
		EndTime:                     time.Now().Add(-1 * time.Second), // Already expired
		ImplicitDeactivationAllowed: true,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Wait for expiration checker to run (runs every second)
	time.Sleep(2 * time.Second)

	// Verify task was implicitly deactivated
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Equal(t, li.TaskStatusDeactivated, retrievedTask.Status)

	// Verify callback was called with correct reason
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, deactivatedXIDs, 1)
	assert.Equal(t, xid, deactivatedXIDs[0])
	assert.Equal(t, li.DeactivationReasonExpired, deactivatedReasons[0])
}

// TestIntegration_NoImplicitDeactivation_IgnoresEndTime tests that tasks with
// ImplicitDeactivationAllowed=false are NOT deactivated when EndTime is reached.
func TestIntegration_NoImplicitDeactivation_IgnoresEndTime(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	deactivationCalled := false
	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		if reason == li.DeactivationReasonExpired {
			deactivationCalled = true
		}
	}

	manager := li.NewManager(config, deactivationCallback)
	require.NoError(t, manager.Start())
	defer manager.Stop()

	// Create destination
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	// Create task with EndTime in the past but ImplicitDeactivationAllowed=false
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs:              []uuid.UUID{did},
		DeliveryType:                li.DeliveryX2andX3,
		EndTime:                     time.Now().Add(-1 * time.Second), // Already expired
		ImplicitDeactivationAllowed: false,                            // NOT allowed
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Wait for expiration checker to run
	time.Sleep(2 * time.Second)

	// Verify task is still active (not deactivated)
	retrievedTask, err := manager.GetTaskDetails(xid)
	require.NoError(t, err)
	assert.Equal(t, li.TaskStatusActive, retrievedTask.Status)

	// Verify callback was NOT called for expiration
	assert.False(t, deactivationCalled, "task should not be implicitly deactivated")
}

// TestIntegration_FullFlow_PacketMatch_Delivery tests the complete flow:
// task activation → packet match → delivery callback.
//
// Note: This test uses the mock filter pusher to capture filter updates,
// since we can't access the internal filter IDs from the external test package.
// We verify that filters are created/deleted and that the packet processor is invoked.
func TestIntegration_FullFlow_PacketMatch_Delivery(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	manager := li.NewManager(config, nil)

	// Track delivered packets
	var deliveredTasks []*li.InterceptTask
	var deliveredPackets []*types.PacketDisplay
	var mu sync.Mutex

	manager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		mu.Lock()
		defer mu.Unlock()
		deliveredTasks = append(deliveredTasks, task)
		deliveredPackets = append(deliveredPackets, pkt)
	})

	// Create destination
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	})
	require.NoError(t, err)

	// Create and activate a task targeting alice@example.com
	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   li.DeliveryX2andX3,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Verify that a filter was created and pushed
	filterPusher.mu.Lock()
	require.Equal(t, 1, filterPusher.updatedCount)
	require.Len(t, filterPusher.filterUpdates, 1)
	filterID := filterPusher.filterUpdates[0].Id
	filterPusher.mu.Unlock()

	// Simulate a packet that matches the filter
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		VoIPData: &types.VoIPMetadata{
			Method:  "INVITE",
			CallID:  "test-call@example.com",
			From:    "sip:alice@example.com",
			To:      "sip:bob@example.com",
			FromTag: "tag-1",
		},
	}

	// Process packet with matched filter
	manager.ProcessPacket(pkt, []string{filterID})

	// Verify the packet processor was called
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, deliveredTasks, 1)
	require.Len(t, deliveredPackets, 1)

	assert.Equal(t, xid, deliveredTasks[0].XID)
	assert.Equal(t, "sip:alice@example.com", deliveredPackets[0].VoIPData.From)
}

// TestIntegration_PacketMatch_NoMatch tests that packets not matching
// any LI filter are not processed.
func TestIntegration_PacketMatch_NoMatch(t *testing.T) {
	filterPusher := newMockFilterPusher()
	config := li.ManagerConfig{
		Enabled:      true,
		FilterPusher: filterPusher,
	}

	manager := li.NewManager(config, nil)

	processorCalled := false
	manager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		processorCalled = true
	})

	// Create destination and task
	did := uuid.New()
	err := manager.CreateDestination(&li.Destination{
		DID:       did,
		Address:   "192.168.1.100",
		Port:      5443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	xid := uuid.New()
	task := &li.InterceptTask{
		XID: xid,
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   li.DeliveryX2Only,
	}

	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Process packet with no matching filter ID
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
	}

	// Use a filter ID that doesn't exist
	manager.ProcessPacket(pkt, []string{"non-existent-filter"})

	// Verify the packet processor was NOT called
	assert.False(t, processorCalled)
}

// TestIntegration_PacketMatch_DisabledManager tests that packets are not
// processed when LI is disabled.
func TestIntegration_PacketMatch_DisabledManager(t *testing.T) {
	config := li.ManagerConfig{
		Enabled: false, // Disabled
	}

	manager := li.NewManager(config, nil)

	processorCalled := false
	manager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		processorCalled = true
	})

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
	}

	manager.ProcessPacket(pkt, []string{"some-filter"})

	assert.False(t, processorCalled)
}
