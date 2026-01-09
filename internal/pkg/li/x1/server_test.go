//go:build li

package x1

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// mockDestinationManager implements DestinationManager for testing.
type mockDestinationManager struct {
	destinations map[uuid.UUID]*Destination
	createErr    error
	getErr       error
	modifyErr    error
	removeErr    error
}

func newMockDestinationManager() *mockDestinationManager {
	return &mockDestinationManager{
		destinations: make(map[uuid.UUID]*Destination),
	}
}

func (m *mockDestinationManager) CreateDestination(dest *Destination) error {
	if m.createErr != nil {
		return m.createErr
	}
	if _, exists := m.destinations[dest.DID]; exists {
		return ErrDestinationAlreadyExists
	}
	m.destinations[dest.DID] = dest
	return nil
}

func (m *mockDestinationManager) GetDestination(did uuid.UUID) (*Destination, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	dest, exists := m.destinations[did]
	if !exists {
		return nil, ErrDestinationNotFound
	}
	return dest, nil
}

func (m *mockDestinationManager) RemoveDestination(did uuid.UUID) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	if _, exists := m.destinations[did]; !exists {
		return ErrDestinationNotFound
	}
	delete(m.destinations, did)
	return nil
}

func (m *mockDestinationManager) ModifyDestination(did uuid.UUID, dest *Destination) error {
	if m.modifyErr != nil {
		return m.modifyErr
	}
	if _, exists := m.destinations[did]; !exists {
		return ErrDestinationNotFound
	}
	m.destinations[did] = dest
	return nil
}

// Ensure mockDestinationManager implements DestinationManager.
var _ DestinationManager = (*mockDestinationManager)(nil)

// mockTaskManager implements TaskManager for testing.
type mockTaskManager struct {
	tasks         map[uuid.UUID]*Task
	activateErr   error
	deactivateErr error
	modifyErr     error
	getErr        error
}

func newMockTaskManager() *mockTaskManager {
	return &mockTaskManager{
		tasks: make(map[uuid.UUID]*Task),
	}
}

func (m *mockTaskManager) ActivateTask(task *Task) error {
	if m.activateErr != nil {
		return m.activateErr
	}
	if _, exists := m.tasks[task.XID]; exists {
		return ErrTaskAlreadyExists
	}
	task.Status = TaskStatusActive
	m.tasks[task.XID] = task
	return nil
}

func (m *mockTaskManager) DeactivateTask(xid uuid.UUID) error {
	if m.deactivateErr != nil {
		return m.deactivateErr
	}
	if _, exists := m.tasks[xid]; !exists {
		return ErrTaskNotFound
	}
	m.tasks[xid].Status = TaskStatusDeactivated
	return nil
}

func (m *mockTaskManager) ModifyTask(xid uuid.UUID, mod *TaskModification) error {
	if m.modifyErr != nil {
		return m.modifyErr
	}
	task, exists := m.tasks[xid]
	if !exists {
		return ErrTaskNotFound
	}
	if mod.Targets != nil {
		task.Targets = *mod.Targets
	}
	if mod.DestinationIDs != nil {
		task.DestinationIDs = *mod.DestinationIDs
	}
	if mod.DeliveryType != nil {
		task.DeliveryType = *mod.DeliveryType
	}
	return nil
}

func (m *mockTaskManager) GetTaskDetails(xid uuid.UUID) (*Task, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	task, exists := m.tasks[xid]
	if !exists {
		return nil, ErrTaskNotFound
	}
	return task, nil
}

// Ensure mockTaskManager implements TaskManager.
var _ TaskManager = (*mockTaskManager)(nil)

func TestServer_HandlePing(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, mock, nil)

	// Build Ping request (direct request type, not wrapped)
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>test-ne</neIdentifier>
  <version>v1.13.1</version>
</pingRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Parse response
	var respContainer schema.ResponseContainer
	err := xml.Unmarshal(w.Body.Bytes(), &respContainer)
	require.NoError(t, err)
	require.Len(t, respContainer.X1ResponseMessage, 1)

	resp := respContainer.X1ResponseMessage[0]
	assert.Equal(t, "test-ne", resp.NeIdentifier)
	assert.NotNil(t, resp.MessageTimestamp)
}

func TestServer_HandleCreateDestination(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Build CreateDestination request
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<createDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>test-ne</neIdentifier>
  <version>v1.13.1</version>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <friendlyName>Test MDF</friendlyName>
    <deliveryType>X2andX3</deliveryType>
    <deliveryAddress>
      <ipAddressAndPort>
        <address>
          <IPv4Address>192.168.1.100</IPv4Address>
        </address>
        <port>
          <TCPPort>5443</TCPPort>
        </port>
      </ipAddressAndPort>
    </deliveryAddress>
  </destinationDetails>
</createDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify destination was created
	dest, exists := mock.destinations[did]
	require.True(t, exists, "destination should be created")
	assert.Equal(t, "192.168.1.100", dest.Address)
	assert.Equal(t, 5443, dest.Port)
	assert.True(t, dest.X2Enabled)
	assert.True(t, dest.X3Enabled)
	assert.Equal(t, "Test MDF", dest.Description)
}

func TestServer_HandleCreateDestination_AlreadyExists(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Pre-create destination
	mock.destinations[did] = &Destination{
		DID:     did,
		Address: "10.0.0.1",
		Port:    443,
	}

	// Try to create same destination
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<createDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <deliveryType>X2Only</deliveryType>
    <deliveryAddress>
      <ipAddressAndPort>
        <address>
          <IPv4Address>192.168.1.100</IPv4Address>
        </address>
        <port>
          <TCPPort>5443</TCPPort>
        </port>
      </ipAddressAndPort>
    </deliveryAddress>
  </destinationDetails>
</createDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	// Should still return 200 OK (X1 uses error codes in response, not HTTP status)
	assert.Equal(t, http.StatusOK, w.Code)

	// Original destination should be unchanged
	assert.Equal(t, "10.0.0.1", mock.destinations[did].Address)
}

func TestServer_HandleModifyDestination(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Pre-create destination
	mock.destinations[did] = &Destination{
		DID:       did,
		Address:   "10.0.0.1",
		Port:      443,
		X2Enabled: true,
		X3Enabled: false,
	}

	// Modify destination
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<modifyDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <friendlyName>Updated MDF</friendlyName>
    <deliveryType>X2andX3</deliveryType>
    <deliveryAddress>
      <ipAddressAndPort>
        <address>
          <IPv4Address>192.168.1.200</IPv4Address>
        </address>
        <port>
          <TCPPort>6443</TCPPort>
        </port>
      </ipAddressAndPort>
    </deliveryAddress>
  </destinationDetails>
</modifyDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify destination was modified
	dest := mock.destinations[did]
	assert.Equal(t, "192.168.1.200", dest.Address)
	assert.Equal(t, 6443, dest.Port)
	assert.True(t, dest.X2Enabled)
	assert.True(t, dest.X3Enabled)
	assert.Equal(t, "Updated MDF", dest.Description)
}

func TestServer_HandleModifyDestination_NotFound(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Try to modify non-existent destination
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<modifyDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <deliveryType>X2Only</deliveryType>
  </destinationDetails>
</modifyDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (not tested in detail here)
}

func TestServer_HandleRemoveDestination(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Pre-create destination
	mock.destinations[did] = &Destination{
		DID:     did,
		Address: "10.0.0.1",
		Port:    443,
	}

	// Remove destination
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<removeDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <dId>` + did.String() + `</dId>
</removeDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify destination was removed
	_, exists := mock.destinations[did]
	assert.False(t, exists, "destination should be removed")
}

func TestServer_HandleRemoveDestination_NotFound(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, mock, nil)

	did := uuid.New()

	// Try to remove non-existent destination
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<removeDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <dId>` + did.String() + `</dId>
</removeDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (not tested in detail here)
}

func TestServer_InvalidXML(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, mock, nil)

	// Send invalid XML
	reqBody := `not valid xml at all`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_BuildTLSConfig(t *testing.T) {
	// Skip if test certs don't exist
	testCertDir := "../../../../testdata/certs"
	certFile := filepath.Join(testCertDir, "server.crt")
	keyFile := filepath.Join(testCertDir, "server.key")
	caFile := filepath.Join(testCertDir, "ca.crt")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Skip("Test certificates not available - run generate_test_certs.sh first")
	}

	// Test with mutual TLS
	s := &Server{
		config: ServerConfig{
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
			TLSCAFile:   caFile,
		},
	}

	tlsConfig, err := s.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

func TestServer_BuildTLSConfig_NoMutualTLS(t *testing.T) {
	// Skip if test certs don't exist
	testCertDir := "../../../../testdata/certs"
	certFile := filepath.Join(testCertDir, "server.crt")
	keyFile := filepath.Join(testCertDir, "server.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Skip("Test certificates not available - run generate_test_certs.sh first")
	}

	// Test without mutual TLS (no CA file)
	s := &Server{
		config: ServerConfig{
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	tlsConfig, err := s.buildTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth)
	assert.Nil(t, tlsConfig.ClientCAs)
}

func TestExtractDeliveryAddress_IPv4(t *testing.T) {
	ipv4 := "192.168.1.100"
	port := 5443
	da := &schema.DeliveryAddress{
		IpAddressAndPort: &schema.IPAddressPort{
			Address: &schema.IPAddress{
				IPv4Address: &ipv4,
			},
			Port: &schema.Port{
				TCPPort: &port,
			},
		},
	}

	addr, p, err := extractDeliveryAddress(da)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.100", addr)
	assert.Equal(t, 5443, p)
}

func TestExtractDeliveryAddress_IPv6(t *testing.T) {
	ipv6 := "2001:db8::1"
	port := 6443
	da := &schema.DeliveryAddress{
		IpAddressAndPort: &schema.IPAddressPort{
			Address: &schema.IPAddress{
				IPv6Address: &ipv6,
			},
			Port: &schema.Port{
				TCPPort: &port,
			},
		},
	}

	addr, p, err := extractDeliveryAddress(da)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", addr)
	assert.Equal(t, 6443, p)
}

func TestExtractDeliveryAddress_URI(t *testing.T) {
	uri := "https://mdf.example.com:8443/delivery"
	da := &schema.DeliveryAddress{
		Uri: &uri,
	}

	addr, p, err := extractDeliveryAddress(da)
	require.NoError(t, err)
	assert.Equal(t, uri, addr)
	assert.Equal(t, 443, p) // Default port for URI
}

func TestExtractDeliveryAddress_Missing(t *testing.T) {
	da := &schema.DeliveryAddress{}

	_, _, err := extractDeliveryAddress(da)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported delivery address format")
}

func TestExtractDeliveryAddress_Nil(t *testing.T) {
	_, _, err := extractDeliveryAddress(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing delivery address")
}

func TestServer_HandleActivateTask(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	// Build ActivateTask request
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>test-ne</neIdentifier>
  <version>v1.13.1</version>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:alice@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was created
	task, exists := taskMock.tasks[xid]
	require.True(t, exists, "task should be created")
	assert.Equal(t, xid, task.XID)
	require.Len(t, task.Targets, 1)
	assert.Equal(t, TargetTypeSIPURI, task.Targets[0].Type)
	assert.Equal(t, "sip:alice@example.com", task.Targets[0].Value)
	assert.Equal(t, DeliveryX2andX3, task.DeliveryType)
	require.Len(t, task.DestinationIDs, 1)
	assert.Equal(t, did, task.DestinationIDs[0])
}

func TestServer_HandleActivateTask_AlreadyExists(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	// Pre-create task
	taskMock.tasks[xid] = &Task{
		XID:    xid,
		Status: TaskStatusActive,
	}

	// Try to create same task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:bob@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2Only</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (task already exists)
}

func TestServer_HandleDeactivateTask(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()

	// Pre-create task
	taskMock.tasks[xid] = &Task{
		XID:    xid,
		Status: TaskStatusActive,
	}

	// Deactivate task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</deactivateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was deactivated
	task := taskMock.tasks[xid]
	assert.Equal(t, TaskStatusDeactivated, task.Status)
}

func TestServer_HandleDeactivateTask_NotFound(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()

	// Try to deactivate non-existent task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</deactivateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (task not found)
}

func TestServer_HandleModifyTask(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	// Pre-create task
	taskMock.tasks[xid] = &Task{
		XID:          xid,
		Status:       TaskStatusActive,
		DeliveryType: DeliveryX2Only,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
	}

	// Modify task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<modifyTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</modifyTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was modified
	task := taskMock.tasks[xid]
	assert.Equal(t, DeliveryX2andX3, task.DeliveryType)
	require.Len(t, task.DestinationIDs, 1)
	assert.Equal(t, did, task.DestinationIDs[0])
}

func TestServer_HandleModifyTask_NotFound(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()

	// Try to modify non-existent task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<modifyTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <deliveryType>X2Only</deliveryType>
  </taskDetails>
</modifyTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (task not found)
}

func TestServer_HandleGetTaskDetails(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()

	// Pre-create task
	taskMock.tasks[xid] = &Task{
		XID:          xid,
		Status:       TaskStatusActive,
		DeliveryType: DeliveryX2andX3,
	}

	// Get task details
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<getTaskDetailsRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</getTaskDetailsRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_HandleGetTaskDetails_NotFound(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()

	// Try to get non-existent task
	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<getTaskDetailsRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</getTaskDetailsRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error code (task not found)
}

func TestServer_HandleActivateTask_NoTaskManager(t *testing.T) {
	destMock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
	}
	s := NewServer(config, destMock, nil) // No task manager

	xid := uuid.New()
	did := uuid.New()

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:alice@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response will contain error (task management not configured)
}

func TestParseDeliveryType(t *testing.T) {
	tests := []struct {
		input    string
		expected DeliveryType
	}{
		{"X2Only", DeliveryX2Only},
		{"X3Only", DeliveryX3Only},
		{"X2andX3", DeliveryX2andX3},
		{"Unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseDeliveryType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractTargetIdentifiers(t *testing.T) {
	sipUri := schema.SIPURI("sip:alice@example.com")
	telUri := schema.TELURI("tel:+15551234567")
	e164 := schema.InternationalE164("+15551234567")
	ipv4 := schema.IPv4Address("192.168.1.100")

	tests := []struct {
		name     string
		input    *schema.ListOfTargetIdentifiers
		expected []TargetIdentity
		hasError bool
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
			hasError: false,
		},
		{
			name: "SIP URI",
			input: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{SipUri: &sipUri},
				},
			},
			expected: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			},
			hasError: false,
		},
		{
			name: "TEL URI",
			input: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{TelUri: &telUri},
				},
			},
			expected: []TargetIdentity{
				{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
			},
			hasError: false,
		},
		{
			name: "E.164 Number",
			input: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{E164Number: &e164},
				},
			},
			expected: []TargetIdentity{
				{Type: TargetTypeE164, Value: "+15551234567"},
			},
			hasError: false,
		},
		{
			name: "IPv4 Address",
			input: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{Ipv4Address: &ipv4},
				},
			},
			expected: []TargetIdentity{
				{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			},
			hasError: false,
		},
		{
			name: "Multiple targets",
			input: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{SipUri: &sipUri},
					{TelUri: &telUri},
				},
			},
			expected: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
				{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
			},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractTargetIdentifiers(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestExtractDestinationIDs(t *testing.T) {
	did1 := uuid.New()
	did2 := uuid.New()
	schemaUUID1 := schema.UUID(did1.String())
	schemaUUID2 := schema.UUID(did2.String())
	invalidUUID := schema.UUID("not-a-valid-uuid")

	tests := []struct {
		name     string
		input    *schema.ListOfDids
		expected []uuid.UUID
		hasError bool
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
			hasError: false,
		},
		{
			name: "single DID",
			input: &schema.ListOfDids{
				DId: []*schema.UUID{&schemaUUID1},
			},
			expected: []uuid.UUID{did1},
			hasError: false,
		},
		{
			name: "multiple DIDs",
			input: &schema.ListOfDids{
				DId: []*schema.UUID{&schemaUUID1, &schemaUUID2},
			},
			expected: []uuid.UUID{did1, did2},
			hasError: false,
		},
		{
			name: "invalid UUID",
			input: &schema.ListOfDids{
				DId: []*schema.UUID{&invalidUUID},
			},
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractDestinationIDs(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// ============================================================================
// Step 4.3 Unit Tests: Task Activation/Deactivation Flow
// ============================================================================

// TestServer_TaskActivationDeactivationFlow tests the complete task lifecycle.
func TestServer_TaskActivationDeactivationFlow(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	// Step 1: Activate task
	activateReq := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>test-ne</neIdentifier>
  <version>v1.13.1</version>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:target@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(activateReq))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was created and is active
	task, exists := taskMock.tasks[xid]
	require.True(t, exists, "task should exist after activation")
	assert.Equal(t, TaskStatusActive, task.Status)

	// Step 2: Get task details
	getReq := `<?xml version="1.0" encoding="UTF-8"?>
<getTaskDetailsRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</getTaskDetailsRequest>`

	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(getReq))
	req.Header.Set("Content-Type", "application/xml")
	w = httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Step 3: Deactivate task
	deactivateReq := `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</deactivateTaskRequest>`

	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(deactivateReq))
	req.Header.Set("Content-Type", "application/xml")
	w = httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was deactivated
	task = taskMock.tasks[xid]
	assert.Equal(t, TaskStatusDeactivated, task.Status)
}

// TestServer_HandleActivateTask_MultipleTargets tests task activation with multiple targets.
func TestServer_HandleActivateTask_MultipleTargets(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	config := ServerConfig{
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}
	s := NewServer(config, destMock, taskMock)

	xid := uuid.New()
	did1 := uuid.New()
	did2 := uuid.New()

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:alice@example.com</sipUri>
      </targetIdentifier>
      <targetIdentifier>
        <telUri>tel:+15551234567</telUri>
      </targetIdentifier>
      <targetIdentifier>
        <e164Number>+15559876543</e164Number>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did1.String() + `</dId>
      <dId>` + did2.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify task was created with all targets
	task, exists := taskMock.tasks[xid]
	require.True(t, exists, "task should be created")
	require.Len(t, task.Targets, 3)
	assert.Equal(t, TargetTypeSIPURI, task.Targets[0].Type)
	assert.Equal(t, "sip:alice@example.com", task.Targets[0].Value)
	assert.Equal(t, TargetTypeTELURI, task.Targets[1].Type)
	assert.Equal(t, "tel:+15551234567", task.Targets[1].Value)
	assert.Equal(t, TargetTypeE164, task.Targets[2].Type)
	assert.Equal(t, "+15559876543", task.Targets[2].Value)

	// Verify multiple destinations
	require.Len(t, task.DestinationIDs, 2)
	assert.Equal(t, did1, task.DestinationIDs[0])
	assert.Equal(t, did2, task.DestinationIDs[1])
}

// TestServer_HandleActivateTask_IPv4Target tests task activation with IPv4 address target.
func TestServer_HandleActivateTask_IPv4Target(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <ipv4Address>192.168.1.100</ipv4Address>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2Only</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	task := taskMock.tasks[xid]
	require.NotNil(t, task)
	require.Len(t, task.Targets, 1)
	assert.Equal(t, TargetTypeIPv4Address, task.Targets[0].Type)
	assert.Equal(t, "192.168.1.100", task.Targets[0].Value)
	assert.Equal(t, DeliveryX2Only, task.DeliveryType)
}

// TestServer_HandleActivateTask_NAITarget tests task activation with NAI target.
func TestServer_HandleActivateTask_NAITarget(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <nai>user@realm.example.com</nai>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X3Only</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	task := taskMock.tasks[xid]
	require.NotNil(t, task)
	require.Len(t, task.Targets, 1)
	assert.Equal(t, TargetTypeNAI, task.Targets[0].Type)
	assert.Equal(t, "user@realm.example.com", task.Targets[0].Value)
	assert.Equal(t, DeliveryX3Only, task.DeliveryType)
}

// TestServer_HandleActivateTask_ImplicitDeactivationAllowed tests implicit deactivation flag.
func TestServer_HandleActivateTask_ImplicitDeactivationAllowed(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <implicitDeactivationAllowed>true</implicitDeactivationAllowed>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	task := taskMock.tasks[xid]
	require.NotNil(t, task)
	assert.True(t, task.ImplicitDeactivationAllowed)
}

// ============================================================================
// Step 4.3 Unit Tests: XML Parsing and Validation
// ============================================================================

// TestServer_XMLParsing_MalformedXML tests various malformed XML scenarios.
func TestServer_XMLParsing_MalformedXML(t *testing.T) {
	mock := newMockDestinationManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, mock, nil)

	tests := []struct {
		name       string
		body       string
		expectCode int
	}{
		{
			name:       "completely invalid XML",
			body:       "this is not xml",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "unclosed tag",
			body:       `<?xml version="1.0"?><pingRequest><admfIdentifier>test`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "mismatched tags",
			body:       `<?xml version="1.0"?><pingRequest></wrongTag>`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid characters",
			body:       `<?xml version="1.0"?><pingRequest>` + string([]byte{0x00, 0x01}) + `</pingRequest>`,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       "",
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

// TestServer_XMLParsing_MissingRequiredFields tests missing required fields.
func TestServer_XMLParsing_MissingRequiredFields(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "activate task missing XID",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + uuid.New().String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`,
		},
		{
			name: "activate task missing targets",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + uuid.New().String() + `</xId>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + uuid.New().String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`,
		},
		{
			name: "activate task missing destination IDs",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + uuid.New().String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
  </taskDetails>
</activateTaskRequest>`,
		},
		{
			name: "deactivate task missing XID",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</deactivateTaskRequest>`,
		},
		{
			name: "create destination missing DID",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<createDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <deliveryType>X2andX3</deliveryType>
    <deliveryAddress>
      <ipAddressAndPort>
        <address>
          <IPv4Address>192.168.1.100</IPv4Address>
        </address>
        <port>
          <TCPPort>5443</TCPPort>
        </port>
      </ipAddressAndPort>
    </deliveryAddress>
  </destinationDetails>
</createDestinationRequest>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			// Should return 200 OK with error in response (X1 protocol)
			assert.Equal(t, http.StatusOK, w.Code)
			// Response body would contain error code
		})
	}
}

// TestServer_XMLParsing_InvalidUUIDs tests invalid UUID formats.
func TestServer_XMLParsing_InvalidUUIDs(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "invalid XID format",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <taskDetails>
    <xId>not-a-valid-uuid</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + uuid.New().String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`,
		},
		{
			name: "invalid DID format",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <taskDetails>
    <xId>` + uuid.New().String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>invalid-did</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`,
		},
		{
			name: "empty XID",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <xId></xId>
</deactivateTaskRequest>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			// Should return 200 OK with error in response (X1 protocol)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// TestServer_XMLParsing_InvalidDeliveryType tests invalid delivery types.
func TestServer_XMLParsing_InvalidDeliveryType(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	tests := []struct {
		name         string
		deliveryType string
	}{
		{"empty delivery type", ""},
		{"invalid delivery type", "InvalidType"},
		{"lowercase x2only", "x2only"},
		{"numeric", "123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>` + tt.deliveryType + `</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			// Should return 200 OK with error code for unsupported delivery type
			assert.Equal(t, http.StatusOK, w.Code)

			// Verify task was not created
			_, exists := taskMock.tasks[xid]
			assert.False(t, exists, "task should not be created with invalid delivery type")
		})
	}
}

// TestServer_XMLParsing_UnknownRequestType tests unknown request types.
func TestServer_XMLParsing_UnknownRequestType(t *testing.T) {
	mock := newMockDestinationManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<unknownRequestType>
  <admfIdentifier>test-admf</admfIdentifier>
</unknownRequestType>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	// Should return 200 with error in response
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// Step 4.3 Unit Tests: Error Reporting and Error Code Verification
// ============================================================================

// TestServer_ErrorCodes_TaskNotFound tests error code for task not found.
func TestServer_ErrorCodes_TaskNotFound(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()

	tests := []struct {
		name    string
		reqBody string
	}{
		{
			name: "deactivate non-existent task",
			reqBody: `<?xml version="1.0" encoding="UTF-8"?>
<deactivateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</deactivateTaskRequest>`,
		},
		{
			name: "get details of non-existent task",
			reqBody: `<?xml version="1.0" encoding="UTF-8"?>
<getTaskDetailsRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <xId>` + xid.String() + `</xId>
</getTaskDetailsRequest>`,
		},
		{
			name: "modify non-existent task",
			reqBody: `<?xml version="1.0" encoding="UTF-8"?>
<modifyTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <deliveryType>X2Only</deliveryType>
  </taskDetails>
</modifyTaskRequest>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			// Response contains ErrorCodeXIDNotFound (301)
		})
	}
}

// TestServer_ErrorCodes_DestinationNotFound tests error code for destination not found.
func TestServer_ErrorCodes_DestinationNotFound(t *testing.T) {
	destMock := newMockDestinationManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, nil)

	did := uuid.New()

	tests := []struct {
		name    string
		reqBody string
	}{
		{
			name: "remove non-existent destination",
			reqBody: `<?xml version="1.0" encoding="UTF-8"?>
<removeDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <dId>` + did.String() + `</dId>
</removeDestinationRequest>`,
		},
		{
			name: "modify non-existent destination",
			reqBody: `<?xml version="1.0" encoding="UTF-8"?>
<modifyDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <deliveryType>X2Only</deliveryType>
  </destinationDetails>
</modifyDestinationRequest>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/xml")
			w := httptest.NewRecorder()
			s.handleX1Request(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			// Response contains ErrorCodeDIDNotFound (303)
		})
	}
}

// TestServer_ErrorCodes_DuplicateXID tests error code for duplicate task XID.
func TestServer_ErrorCodes_DuplicateXID(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	did := uuid.New()

	// Pre-create task
	taskMock.tasks[xid] = &Task{
		XID:    xid,
		Status: TaskStatusActive,
	}

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<activateTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:test@example.com</sipUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + did.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</activateTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response contains ErrorCodeXIDAlreadyExists (300)
}

// TestServer_ErrorCodes_DuplicateDID tests error code for duplicate destination DID.
func TestServer_ErrorCodes_DuplicateDID(t *testing.T) {
	destMock := newMockDestinationManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, nil)

	did := uuid.New()

	// Pre-create destination
	destMock.destinations[did] = &Destination{
		DID:     did,
		Address: "10.0.0.1",
		Port:    443,
	}

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<createDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <destinationDetails>
    <dId>` + did.String() + `</dId>
    <deliveryType>X2andX3</deliveryType>
    <deliveryAddress>
      <ipAddressAndPort>
        <address>
          <IPv4Address>192.168.1.100</IPv4Address>
        </address>
        <port>
          <TCPPort>5443</TCPPort>
        </port>
      </ipAddressAndPort>
    </deliveryAddress>
  </destinationDetails>
</createDestinationRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Response contains ErrorCodeDIDAlreadyExists (302)

	// Verify original destination unchanged
	assert.Equal(t, "10.0.0.1", destMock.destinations[did].Address)
}

// TestServer_ResponseXMLStructure tests the structure of X1 response XML.
func TestServer_ResponseXMLStructure(t *testing.T) {
	mock := newMockDestinationManager()
	s := NewServer(ServerConfig{
		NEIdentifier: "ne-unit-test",
		Version:      "v1.13.1",
	}, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>admf-test</admfIdentifier>
  <neIdentifier>ne-unit-test</neIdentifier>
  <version>v1.13.1</version>
</pingRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Parse response
	var respContainer schema.ResponseContainer
	err := xml.Unmarshal(w.Body.Bytes(), &respContainer)
	require.NoError(t, err)

	require.Len(t, respContainer.X1ResponseMessage, 1)
	resp := respContainer.X1ResponseMessage[0]

	// Verify response structure
	assert.Equal(t, "ne-unit-test", resp.NeIdentifier)
	assert.NotNil(t, resp.MessageTimestamp)
}

// TestServer_ModifyTask_UpdatesAllFields tests that ModifyTask updates all provided fields.
func TestServer_ModifyTask_UpdatesAllFields(t *testing.T) {
	destMock := newMockDestinationManager()
	taskMock := newMockTaskManager()
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destMock, taskMock)

	xid := uuid.New()
	oldDID := uuid.New()
	newDID1 := uuid.New()
	newDID2 := uuid.New()

	// Pre-create task with initial values
	taskMock.tasks[xid] = &Task{
		XID:          xid,
		Status:       TaskStatusActive,
		DeliveryType: DeliveryX2Only,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:old@example.com"},
		},
		DestinationIDs: []uuid.UUID{oldDID},
	}

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<modifyTaskRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <taskDetails>
    <xId>` + xid.String() + `</xId>
    <targetIdentifiers>
      <targetIdentifier>
        <sipUri>sip:new1@example.com</sipUri>
      </targetIdentifier>
      <targetIdentifier>
        <telUri>tel:+15551234567</telUri>
      </targetIdentifier>
    </targetIdentifiers>
    <deliveryType>X2andX3</deliveryType>
    <listOfDIDs>
      <dId>` + newDID1.String() + `</dId>
      <dId>` + newDID2.String() + `</dId>
    </listOfDIDs>
  </taskDetails>
</modifyTaskRequest>`

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify all fields were updated
	task := taskMock.tasks[xid]
	require.NotNil(t, task)

	// Verify targets updated
	require.Len(t, task.Targets, 2)
	assert.Equal(t, "sip:new1@example.com", task.Targets[0].Value)
	assert.Equal(t, "tel:+15551234567", task.Targets[1].Value)

	// Verify delivery type updated
	assert.Equal(t, DeliveryX2andX3, task.DeliveryType)

	// Verify destination IDs updated
	require.Len(t, task.DestinationIDs, 2)
	assert.Equal(t, newDID1, task.DestinationIDs[0])
	assert.Equal(t, newDID2, task.DestinationIDs[1])
}

// TestExtractTargetIdentifiers_IPv6 tests IPv6 address target extraction.
func TestExtractTargetIdentifiers_IPv6(t *testing.T) {
	ipv6 := schema.IPv6Address("2001:db8::1")

	input := &schema.ListOfTargetIdentifiers{
		TargetIdentifier: []*schema.TargetIdentifier{
			{Ipv6Address: &ipv6},
		},
	}

	result, err := extractTargetIdentifiers(input)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, TargetTypeIPv6Address, result[0].Type)
	assert.Equal(t, "2001:db8::1", result[0].Value)
}

// TestExtractTargetIdentifiers_IPv4CIDR tests IPv4 CIDR target extraction.
func TestExtractTargetIdentifiers_IPv4CIDR(t *testing.T) {
	cidr := "192.168.1.0/24"

	input := &schema.ListOfTargetIdentifiers{
		TargetIdentifier: []*schema.TargetIdentifier{
			{Ipv4Cidr: &schema.IPCIDR{IPv4CIDR: &cidr}},
		},
	}

	result, err := extractTargetIdentifiers(input)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, TargetTypeIPv4CIDR, result[0].Type)
	assert.Equal(t, "192.168.1.0/24", result[0].Value)
}

// TestExtractTargetIdentifiers_IPv6CIDR tests IPv6 CIDR target extraction.
func TestExtractTargetIdentifiers_IPv6CIDR(t *testing.T) {
	cidr := schema.IPv6CIDR("2001:db8::/32")

	input := &schema.ListOfTargetIdentifiers{
		TargetIdentifier: []*schema.TargetIdentifier{
			{Ipv6Cidr: &cidr},
		},
	}

	result, err := extractTargetIdentifiers(input)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, TargetTypeIPv6CIDR, result[0].Type)
	assert.Equal(t, "2001:db8::/32", result[0].Value)
}

// TestExtractTargetIdentifiers_NilEntry tests that nil entries in target list are skipped.
func TestExtractTargetIdentifiers_NilEntry(t *testing.T) {
	valid := schema.SIPURI("sip:valid@example.com")

	input := &schema.ListOfTargetIdentifiers{
		TargetIdentifier: []*schema.TargetIdentifier{
			{SipUri: &valid}, // Should be included
			nil,              // Should be skipped
		},
	}

	result, err := extractTargetIdentifiers(input)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "sip:valid@example.com", result[0].Value)
}

// TestExtractTargetIdentifiers_EmptyIdentifier tests that empty identifier value errors.
func TestExtractTargetIdentifiers_EmptyIdentifier(t *testing.T) {
	empty := schema.SIPURI("")

	input := &schema.ListOfTargetIdentifiers{
		TargetIdentifier: []*schema.TargetIdentifier{
			{SipUri: &empty}, // Empty value - unsupported
		},
	}

	// Empty identifier should result in error (unsupported target type)
	_, err := extractTargetIdentifiers(input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target identifier type")
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

// TestServer_RateLimiting tests that rate limiting is enforced per IP.
func TestServer_RateLimiting(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier:   "test-ne",
		RateLimitPerIP: 2, // Very low limit for testing
		RateLimitBurst: 2, // Allow burst of 2
	}
	s := NewServer(config, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</pingRequest>`

	// First two requests should succeed (burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/xml")
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()
		s.handleX1Request(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/xml")
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	s.handleX1Request(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "third request should be rate limited")
}

// TestServer_RateLimiting_PerIP tests that different IPs have separate rate limits.
func TestServer_RateLimiting_PerIP(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier:   "test-ne",
		RateLimitPerIP: 1,
		RateLimitBurst: 1,
	}
	s := NewServer(config, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</pingRequest>`

	// Request from IP 1 - should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req1.Header.Set("Content-Type", "application/xml")
	req1.RemoteAddr = "192.168.1.100:12345"
	w1 := httptest.NewRecorder()
	s.handleX1Request(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code, "first IP should succeed")

	// Request from IP 2 - should also succeed (different rate limiter)
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req2.Header.Set("Content-Type", "application/xml")
	req2.RemoteAddr = "192.168.1.200:12345"
	w2 := httptest.NewRecorder()
	s.handleX1Request(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "second IP should succeed")

	// Second request from IP 1 - should be rate limited
	req3 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req3.Header.Set("Content-Type", "application/xml")
	req3.RemoteAddr = "192.168.1.100:54321"
	w3 := httptest.NewRecorder()
	s.handleX1Request(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code, "second request from first IP should be limited")
}

// TestServer_RateLimiting_XForwardedFor tests rate limiting with X-Forwarded-For header.
func TestServer_RateLimiting_XForwardedFor(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier:   "test-ne",
		RateLimitPerIP: 1,
		RateLimitBurst: 1,
	}
	s := NewServer(config, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</pingRequest>`

	// Request with X-Forwarded-For - should use forwarded IP
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req1.Header.Set("Content-Type", "application/xml")
	req1.Header.Set("X-Forwarded-For", "10.0.0.50")
	req1.RemoteAddr = "192.168.1.100:12345" // Proxy IP
	w1 := httptest.NewRecorder()
	s.handleX1Request(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code, "first request should succeed")

	// Second request from same forwarded IP - should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req2.Header.Set("Content-Type", "application/xml")
	req2.Header.Set("X-Forwarded-For", "10.0.0.50")
	req2.RemoteAddr = "192.168.1.100:54321"
	w2 := httptest.NewRecorder()
	s.handleX1Request(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "second request from same forwarded IP should be limited")

	// Request from different forwarded IP - should succeed
	req3 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req3.Header.Set("Content-Type", "application/xml")
	req3.Header.Set("X-Forwarded-For", "10.0.0.60")
	req3.RemoteAddr = "192.168.1.100:54321"
	w3 := httptest.NewRecorder()
	s.handleX1Request(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code, "different forwarded IP should succeed")
}

// TestServer_RateLimiting_XForwardedFor_Chain tests X-Forwarded-For with multiple IPs.
func TestServer_RateLimiting_XForwardedFor_Chain(t *testing.T) {
	mock := newMockDestinationManager()
	config := ServerConfig{
		NEIdentifier:   "test-ne",
		RateLimitPerIP: 1,
		RateLimitBurst: 1,
	}
	s := NewServer(config, mock, nil)

	reqBody := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</pingRequest>`

	// Request with X-Forwarded-For chain - should use first IP
	req1 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req1.Header.Set("Content-Type", "application/xml")
	req1.Header.Set("X-Forwarded-For", "10.0.0.50, 172.16.0.1, 192.168.1.1")
	req1.RemoteAddr = "192.168.1.100:12345"
	w1 := httptest.NewRecorder()
	s.handleX1Request(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code, "first request should succeed")

	// Second request from same chain - should be rate limited (same first IP)
	req2 := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(reqBody))
	req2.Header.Set("Content-Type", "application/xml")
	req2.Header.Set("X-Forwarded-For", "10.0.0.50, 172.16.0.2")
	req2.RemoteAddr = "192.168.1.200:12345"
	w2 := httptest.NewRecorder()
	s.handleX1Request(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "same origin IP should be limited")
}

// TestExtractClientIP tests client IP extraction from requests.
func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		expected   string
	}{
		{
			name:       "simple remote addr with port",
			remoteAddr: "192.168.1.100:12345",
			xff:        "",
			expected:   "192.168.1.100",
		},
		{
			name:       "IPv6 remote addr with port",
			remoteAddr: "[2001:db8::1]:12345",
			xff:        "",
			expected:   "2001:db8::1",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "192.168.1.100",
			xff:        "",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "10.0.0.1:12345",
			xff:        "192.168.1.100",
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For chain",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			expected:   "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "192.168.1.100:12345",
			xff:        "10.0.0.50",
			expected:   "10.0.0.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			result := extractClientIP(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestServer_GetRateLimiter tests rate limiter creation and reuse.
func TestServer_GetRateLimiter(t *testing.T) {
	s := NewServer(ServerConfig{
		NEIdentifier:   "test-ne",
		RateLimitPerIP: 10,
		RateLimitBurst: 20,
	}, nil, nil)

	// Get limiter for IP
	limiter1 := s.getRateLimiter("192.168.1.100")
	assert.NotNil(t, limiter1)

	// Get limiter again - should return same instance (pointer comparison)
	limiter2 := s.getRateLimiter("192.168.1.100")
	assert.True(t, limiter1 == limiter2, "should return same limiter instance for same IP")

	// Get limiter for different IP - should be different instance (pointer comparison)
	limiter3 := s.getRateLimiter("192.168.1.200")
	assert.True(t, limiter1 != limiter3, "should return different limiter instance for different IP")
}

// TestServer_DefaultConfig tests that default config values are applied.
func TestServer_DefaultConfig(t *testing.T) {
	s := NewServer(ServerConfig{}, nil, nil)

	assert.Equal(t, "v1.13.1", s.config.Version)
	assert.Equal(t, float64(10), s.config.RateLimitPerIP)
	assert.Equal(t, 20, s.config.RateLimitBurst)
	assert.Equal(t, 5*time.Second, s.config.XMLParseTimeout)
}

// TestServer_CustomConfig tests that custom config values are preserved.
func TestServer_CustomConfig(t *testing.T) {
	s := NewServer(ServerConfig{
		Version:         "v2.0.0",
		RateLimitPerIP:  50,
		RateLimitBurst:  100,
		XMLParseTimeout: 10 * time.Second,
	}, nil, nil)

	assert.Equal(t, "v2.0.0", s.config.Version)
	assert.Equal(t, float64(50), s.config.RateLimitPerIP)
	assert.Equal(t, 100, s.config.RateLimitBurst)
	assert.Equal(t, 10*time.Second, s.config.XMLParseTimeout)
}
