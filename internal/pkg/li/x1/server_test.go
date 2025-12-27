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
