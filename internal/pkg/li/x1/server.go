//go:build li

// Package x1 implements the ETSI X1 administration interface for lawful interception.
//
// The X1 interface provides HTTPS/XML-based communication between the ADMF
// (Administration Function) and NE (Network Element) for managing intercept
// tasks and delivery destinations per ETSI TS 103 221-1.
package x1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// X1 error codes per ETSI TS 103 221-1 section 6.3.3.
const (
	ErrorCodeGenericError           = 100
	ErrorCodeRequestSyntaxError     = 101
	ErrorCodeGenericWarning         = 200
	ErrorCodeXIDAlreadyExists       = 300
	ErrorCodeXIDNotFound            = 301
	ErrorCodeDIDAlreadyExists       = 302
	ErrorCodeDIDNotFound            = 303
	ErrorCodeDIDInUse               = 304
	ErrorCodeDeliveryNotPossible    = 400
	ErrorCodeTargetNotSupported     = 401
	ErrorCodeDeliveryTypeNotSupport = 402
)

// X1 content type for XML.
const contentTypeXML = "application/xml; charset=utf-8"

// X1 request message types.
const (
	MessageTypeCreateDestination = "CreateDestinationRequest"
	MessageTypeModifyDestination = "ModifyDestinationRequest"
	MessageTypeRemoveDestination = "RemoveDestinationRequest"
	MessageTypeActivateTask      = "ActivateTaskRequest"
	MessageTypeDeactivateTask    = "DeactivateTaskRequest"
	MessageTypeModifyTask        = "ModifyTaskRequest"
	MessageTypeGetTaskDetails    = "GetTaskDetailsRequest"
	MessageTypePing              = "PingRequest"
)

// Sentinel errors for destination operations.
var (
	// ErrDestinationNotFound indicates the requested destination DID does not exist.
	ErrDestinationNotFound = errors.New("destination not found")
	// ErrDestinationAlreadyExists indicates a destination with the given DID already exists.
	ErrDestinationAlreadyExists = errors.New("destination already exists")
)

// Sentinel errors for task operations.
var (
	// ErrTaskNotFound indicates the requested task XID does not exist.
	ErrTaskNotFound = errors.New("task not found")
	// ErrTaskAlreadyExists indicates a task with the given XID already exists.
	ErrTaskAlreadyExists = errors.New("task already exists")
	// ErrInvalidTask indicates the task parameters are invalid.
	ErrInvalidTask = errors.New("invalid task parameters")
	// ErrModifyNotAllowed indicates the requested modification is not permitted.
	ErrModifyNotAllowed = errors.New("modification not allowed")
)

// Destination represents an X2/X3 delivery endpoint.
// This is a simplified view of the destination for X1 operations.
type Destination struct {
	// DID is the unique identifier for this destination (UUID v4).
	DID uuid.UUID
	// Address is the hostname or IP address of the MDF endpoint.
	Address string
	// Port is the TCP port for the TLS connection.
	Port int
	// X2Enabled indicates this destination accepts X2 (IRI) traffic.
	X2Enabled bool
	// X3Enabled indicates this destination accepts X3 (CC) traffic.
	X3Enabled bool
	// Description is an optional human-readable description.
	Description string
}

// TargetType specifies the type of target identifier per ETSI TS 103 280.
type TargetType int

const (
	// TargetTypeSIPURI identifies a target by SIP URI.
	TargetTypeSIPURI TargetType = iota + 1
	// TargetTypeTELURI identifies a target by telephone URI.
	TargetTypeTELURI
	// TargetTypeIPv4Address identifies a target by IPv4 address.
	TargetTypeIPv4Address
	// TargetTypeIPv4CIDR identifies a target by IPv4 CIDR range.
	TargetTypeIPv4CIDR
	// TargetTypeIPv6Address identifies a target by IPv6 address.
	TargetTypeIPv6Address
	// TargetTypeIPv6CIDR identifies a target by IPv6 CIDR range.
	TargetTypeIPv6CIDR
	// TargetTypeNAI identifies a target by Network Access Identifier.
	TargetTypeNAI
	// TargetTypeE164 identifies a target by E.164 number.
	TargetTypeE164
)

// TargetIdentity specifies a single target to intercept.
type TargetIdentity struct {
	// Type specifies the format of the Value field.
	Type TargetType
	// Value contains the target identifier.
	Value string
}

// DeliveryType specifies what content should be delivered.
type DeliveryType int

const (
	// DeliveryX2Only delivers only IRI (Intercept Related Information).
	DeliveryX2Only DeliveryType = iota + 1
	// DeliveryX3Only delivers only CC (Content of Communication).
	DeliveryX3Only
	// DeliveryX2andX3 delivers both IRI and CC.
	DeliveryX2andX3
)

// TaskStatus represents the lifecycle state of an intercept task.
type TaskStatus int

const (
	// TaskStatusPending indicates the task has been received but not yet activated.
	TaskStatusPending TaskStatus = iota
	// TaskStatusActive indicates the task is actively intercepting traffic.
	TaskStatusActive
	// TaskStatusSuspended indicates the task is temporarily suspended.
	TaskStatusSuspended
	// TaskStatusDeactivated indicates the task has been explicitly deactivated.
	TaskStatusDeactivated
	// TaskStatusFailed indicates the task failed to activate.
	TaskStatusFailed
)

// Task represents an intercept task for X1 operations.
type Task struct {
	// XID is the unique identifier for this task (UUID v4).
	XID uuid.UUID
	// Targets specifies the identities to intercept.
	Targets []TargetIdentity
	// DestinationIDs references the Destination objects for X2/X3 delivery.
	DestinationIDs []uuid.UUID
	// DeliveryType specifies whether to deliver X2 (IRI), X3 (CC), or both.
	DeliveryType DeliveryType
	// StartTime is when the intercept should begin. Zero means immediately.
	StartTime time.Time
	// EndTime is when the intercept should end. Zero means indefinite.
	EndTime time.Time
	// ImplicitDeactivationAllowed indicates whether the NE may autonomously deactivate.
	ImplicitDeactivationAllowed bool
	// Status is the current lifecycle state of the task.
	Status TaskStatus
	// ActivatedAt records when the task was activated.
	ActivatedAt time.Time
	// LastError contains the most recent error message (if any).
	LastError string
}

// TaskModification specifies which fields to modify in a task.
type TaskModification struct {
	// Targets replaces the target list if non-nil.
	Targets *[]TargetIdentity
	// DestinationIDs replaces the destination list if non-nil.
	DestinationIDs *[]uuid.UUID
	// DeliveryType changes the delivery type if non-nil.
	DeliveryType *DeliveryType
	// EndTime changes the end time if non-nil.
	EndTime *time.Time
	// ImplicitDeactivationAllowed changes the implicit deactivation flag if non-nil.
	ImplicitDeactivationAllowed *bool
}

// ServerConfig holds configuration for the X1 server.
type ServerConfig struct {
	// ListenAddr is the address to listen on (e.g., ":8443").
	ListenAddr string

	// TLSCertFile is the path to the server TLS certificate.
	TLSCertFile string

	// TLSKeyFile is the path to the server TLS private key.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate for client verification (mutual TLS).
	TLSCAFile string

	// NEIdentifier is the network element identifier for X1 responses.
	NEIdentifier string

	// Version is the X1 protocol version (default: "v1.13.1").
	Version string
}

// DestinationManager provides destination CRUD operations.
// This interface is implemented by the LI Manager.
type DestinationManager interface {
	CreateDestination(dest *Destination) error
	GetDestination(did uuid.UUID) (*Destination, error)
	RemoveDestination(did uuid.UUID) error
	// ModifyDestination updates an existing destination.
	// The implementation should validate that the DID exists.
	ModifyDestination(did uuid.UUID, dest *Destination) error
}

// TaskManager provides task CRUD operations.
// This interface is implemented by the LI Manager.
type TaskManager interface {
	// ActivateTask creates and activates a new intercept task.
	ActivateTask(task *Task) error
	// DeactivateTask stops an active intercept task.
	DeactivateTask(xid uuid.UUID) error
	// ModifyTask updates an existing task's parameters atomically.
	ModifyTask(xid uuid.UUID, mod *TaskModification) error
	// GetTaskDetails retrieves a task by its XID.
	GetTaskDetails(xid uuid.UUID) (*Task, error)
}

// Server implements the X1 administration interface.
type Server struct {
	mu           sync.RWMutex
	config       ServerConfig
	destManager  DestinationManager
	taskManager  TaskManager
	httpServer   *http.Server
	listener     net.Listener
	shutdownOnce sync.Once
}

// NewServer creates a new X1 server.
func NewServer(config ServerConfig, destManager DestinationManager, taskManager TaskManager) *Server {
	if config.Version == "" {
		config.Version = "v1.13.1"
	}
	if config.NEIdentifier == "" {
		hostname, _ := os.Hostname()
		config.NEIdentifier = hostname
	}

	return &Server{
		config:      config,
		destManager: destManager,
		taskManager: taskManager,
	}
}

// Start begins serving the X1 interface.
func (s *Server) Start(ctx context.Context) error {
	// Setup phase - hold lock briefly.
	s.mu.Lock()

	// Build TLS config with mutual TLS
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to build TLS config: %w", err)
	}

	// Create HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleX1Request)

	s.httpServer = &http.Server{
		Addr:              s.config.ListenAddr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Create listener
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}
	s.listener = ln

	// Release lock before blocking operations.
	s.mu.Unlock()

	logger.Info("X1 server starting",
		"addr", ln.Addr().String(),
		"tls", true,
		"mutual_tls", s.config.TLSCAFile != "",
	)

	// Start serving in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.ServeTLS(ln, s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
		close(errChan)
	}()

	// Wait for context or error
	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-errChan:
		return err
	}
}

// Addr returns the server's bound address, or empty string if not started.
// This is useful for tests when using ":0" to get an available port.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Shutdown gracefully stops the X1 server.
func (s *Server) Shutdown() error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			logger.Info("X1 server shutting down")
			if err := s.httpServer.Shutdown(ctx); err != nil {
				logger.Error("X1 server shutdown error", "error", err)
				shutdownErr = err
			}
		}
	})
	return shutdownErr
}

// buildTLSConfig creates the TLS configuration for the server.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Configure mutual TLS if CA file is provided
	if s.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(s.config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		logger.Info("X1 mutual TLS enabled", "ca_file", s.config.TLSCAFile)
	}

	return tlsConfig, nil
}

// handleX1Request handles incoming X1 requests.
func (s *Server) handleX1Request(w http.ResponseWriter, r *http.Request) {
	// Log request
	logger.Debug("X1 request received",
		"method", r.Method,
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
	)

	// Read request body
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		s.sendErrorResponse(w, "", ErrorCodeGenericError, "failed to read request body")
		return
	}
	defer r.Body.Close()

	// Detect the root element to determine if this is a container or direct request
	var rootDetector xmlRootDetector
	if err := xml.Unmarshal(body, &rootDetector); err != nil {
		s.sendErrorResponse(w, "", ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		return
	}

	var responses []*schema.X1ResponseMessage

	// Check if it's a request container (batch) or a direct request
	if rootDetector.XMLName.Local == "requestContainer" {
		// Parse the request container
		var reqContainer schema.RequestContainer
		if err := xml.Unmarshal(body, &reqContainer); err != nil {
			s.sendErrorResponse(w, "", ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
			return
		}

		// Process each request message in the container
		// Note: In the container case, we'd need individual message bodies
		// For now, we only support single requests per container
		if len(reqContainer.X1RequestMessage) > 0 {
			resp := s.processRequestMessage(body, reqContainer.X1RequestMessage[0])
			responses = append(responses, resp)
		}
	} else {
		// Direct request (not wrapped in container)
		resp := s.processRequestMessage(body, nil)
		responses = append(responses, resp)
	}

	// Build response container
	respContainer := &schema.ResponseContainer{
		X1ResponseMessage: responses,
	}

	// Marshal and send response
	respBody, err := xml.MarshalIndent(respContainer, "", "  ")
	if err != nil {
		logger.Error("X1 failed to marshal response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentTypeXML)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBody); err != nil {
		logger.Error("X1 failed to write response", "error", err)
	}
}

// xmlRootDetector is used to detect the root element name of an XML document.
type xmlRootDetector struct {
	XMLName xml.Name
}

// processRequestMessage processes a single X1 request message.
func (s *Server) processRequestMessage(body []byte, reqMsg *schema.X1RequestMessage) *schema.X1ResponseMessage {
	// First, detect the root element to determine the request type
	var rootDetector xmlRootDetector
	if err := xml.Unmarshal(body, &rootDetector); err != nil {
		return s.buildErrorResponse(reqMsg, "Unknown", ErrorCodeRequestSyntaxError, "failed to parse XML root: "+err.Error())
	}

	// Route to appropriate handler based on root element name
	switch rootDetector.XMLName.Local {
	case "createDestinationRequest", "CreateDestinationRequest":
		var createReq schema.CreateDestinationRequest
		if err := xml.Unmarshal(body, &createReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeCreateDestination, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleCreateDestination(&createReq)

	case "modifyDestinationRequest", "ModifyDestinationRequest":
		var modifyReq schema.ModifyDestinationRequest
		if err := xml.Unmarshal(body, &modifyReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeModifyDestination, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleModifyDestination(&modifyReq)

	case "removeDestinationRequest", "RemoveDestinationRequest":
		var removeReq schema.RemoveDestinationRequest
		if err := xml.Unmarshal(body, &removeReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeRemoveDestination, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleRemoveDestination(&removeReq)

	case "pingRequest", "PingRequest":
		var pingReq schema.PingRequest
		if err := xml.Unmarshal(body, &pingReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypePing, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handlePing(&pingReq)

	case "activateTaskRequest", "ActivateTaskRequest":
		var activateReq schema.ActivateTaskRequest
		if err := xml.Unmarshal(body, &activateReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeActivateTask, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleActivateTask(&activateReq)

	case "deactivateTaskRequest", "DeactivateTaskRequest":
		var deactivateReq schema.DeactivateTaskRequest
		if err := xml.Unmarshal(body, &deactivateReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeDeactivateTask, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleDeactivateTask(&deactivateReq)

	case "modifyTaskRequest", "ModifyTaskRequest":
		var modifyReq schema.ModifyTaskRequest
		if err := xml.Unmarshal(body, &modifyReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeModifyTask, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleModifyTask(&modifyReq)

	case "getTaskDetailsRequest", "GetTaskDetailsRequest":
		var getReq schema.GetTaskDetailsRequest
		if err := xml.Unmarshal(body, &getReq); err != nil {
			return s.buildErrorResponse(reqMsg, MessageTypeGetTaskDetails, ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
		}
		return s.handleGetTaskDetails(&getReq)

	case "requestContainer":
		// This is a container with multiple messages - already handled in handleX1Request
		// This shouldn't happen, but handle gracefully
		return s.buildErrorResponse(reqMsg, "requestContainer", ErrorCodeRequestSyntaxError, "nested request containers not supported")

	default:
		return s.buildErrorResponse(reqMsg, "Unknown", ErrorCodeRequestSyntaxError, "unknown request type: "+rootDetector.XMLName.Local)
	}
}

// handleCreateDestination handles CreateDestinationRequest.
func (s *Server) handleCreateDestination(req *schema.CreateDestinationRequest) *schema.X1ResponseMessage {
	details := req.DestinationDetails
	if details == nil || details.DId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			ErrorCodeRequestSyntaxError, "missing destination details or DID")
	}

	// Parse DID
	did, err := uuid.Parse(string(*details.DId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			ErrorCodeRequestSyntaxError, "invalid DID format: "+err.Error())
	}

	// Extract delivery address
	address, port, err := extractDeliveryAddress(details.DeliveryAddress)
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			ErrorCodeRequestSyntaxError, err.Error())
	}

	// Build destination
	dest := &Destination{
		DID:       did,
		Address:   address,
		Port:      port,
		X2Enabled: details.DeliveryType == "X2Only" || details.DeliveryType == "X2andX3",
		X3Enabled: details.DeliveryType == "X3Only" || details.DeliveryType == "X2andX3",
	}

	if details.FriendlyName != nil {
		dest.Description = *details.FriendlyName
	}

	// Create destination
	if err := s.destManager.CreateDestination(dest); err != nil {
		if errors.Is(err, ErrDestinationAlreadyExists) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
				ErrorCodeDIDAlreadyExists, "destination already exists: "+did.String())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			ErrorCodeGenericError, "failed to create destination: "+err.Error())
	}

	logger.Info("X1 destination created",
		"did", did,
		"address", address,
		"port", port,
	)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeCreateDestination)
}

// handleModifyDestination handles ModifyDestinationRequest.
func (s *Server) handleModifyDestination(req *schema.ModifyDestinationRequest) *schema.X1ResponseMessage {
	details := req.DestinationDetails
	if details == nil || details.DId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			ErrorCodeRequestSyntaxError, "missing destination details or DID")
	}

	// Parse DID
	did, err := uuid.Parse(string(*details.DId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			ErrorCodeRequestSyntaxError, "invalid DID format: "+err.Error())
	}

	// Get existing destination
	existing, err := s.destManager.GetDestination(did)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
				ErrorCodeDIDNotFound, "destination not found: "+did.String())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			ErrorCodeGenericError, "failed to get destination: "+err.Error())
	}

	// Update fields
	if details.DeliveryAddress != nil {
		address, port, err := extractDeliveryAddress(details.DeliveryAddress)
		if err != nil {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
				ErrorCodeRequestSyntaxError, err.Error())
		}
		existing.Address = address
		existing.Port = port
	}

	if details.DeliveryType != "" {
		existing.X2Enabled = details.DeliveryType == "X2Only" || details.DeliveryType == "X2andX3"
		existing.X3Enabled = details.DeliveryType == "X3Only" || details.DeliveryType == "X2andX3"
	}

	if details.FriendlyName != nil {
		existing.Description = *details.FriendlyName
	}

	// Update destination
	if err := s.destManager.ModifyDestination(did, existing); err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			ErrorCodeGenericError, "failed to modify destination: "+err.Error())
	}

	logger.Info("X1 destination modified",
		"did", did,
	)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeModifyDestination)
}

// handleRemoveDestination handles RemoveDestinationRequest.
func (s *Server) handleRemoveDestination(req *schema.RemoveDestinationRequest) *schema.X1ResponseMessage {
	if req.DId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeRemoveDestination,
			ErrorCodeRequestSyntaxError, "missing DID")
	}

	// Parse DID
	did, err := uuid.Parse(string(*req.DId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeRemoveDestination,
			ErrorCodeRequestSyntaxError, "invalid DID format: "+err.Error())
	}

	// Remove destination
	if err := s.destManager.RemoveDestination(did); err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeRemoveDestination,
				ErrorCodeDIDNotFound, "destination not found: "+did.String())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeRemoveDestination,
			ErrorCodeGenericError, "failed to remove destination: "+err.Error())
	}

	logger.Info("X1 destination removed",
		"did", did,
	)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeRemoveDestination)
}

// handlePing handles PingRequest.
func (s *Server) handlePing(req *schema.PingRequest) *schema.X1ResponseMessage {
	logger.Debug("X1 ping received")
	return s.buildOKResponse(req.X1RequestMessage, MessageTypePing)
}

// handleActivateTask handles ActivateTaskRequest.
func (s *Server) handleActivateTask(req *schema.ActivateTaskRequest) *schema.X1ResponseMessage {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeGenericError, "task management not configured")
	}

	details := req.TaskDetails
	if details == nil || details.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "missing task details or XID")
	}

	// Parse XID
	xid, err := uuid.Parse(string(*details.XId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "invalid XID format: "+err.Error())
	}

	// Extract target identifiers
	targets, err := extractTargetIdentifiers(details.TargetIdentifiers)
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, err.Error())
	}

	if len(targets) == 0 {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "no target identifiers specified")
	}

	// Extract destination IDs
	destIDs, err := extractDestinationIDs(details.ListOfDIDs)
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, err.Error())
	}

	if len(destIDs) == 0 {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "no destination IDs specified")
	}

	// Parse delivery type
	deliveryType := parseDeliveryType(details.DeliveryType)
	if deliveryType == 0 {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeDeliveryTypeNotSupport, "unsupported delivery type: "+details.DeliveryType)
	}

	// Build task
	task := &Task{
		XID:            xid,
		Targets:        targets,
		DestinationIDs: destIDs,
		DeliveryType:   deliveryType,
	}

	// Parse implicit deactivation allowed
	if details.ImplicitDeactivationAllowed != nil {
		task.ImplicitDeactivationAllowed = *details.ImplicitDeactivationAllowed
	}

	// Note: StartTime and EndTime parsing from MediationDetails would go here
	// For now, we use immediate activation and indefinite duration

	// Activate task
	if err := s.taskManager.ActivateTask(task); err != nil {
		if errors.Is(err, ErrTaskAlreadyExists) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeXIDAlreadyExists, "task already exists: "+xid.String())
		}
		if errors.Is(err, ErrInvalidTask) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeRequestSyntaxError, "invalid task: "+err.Error())
		}
		// Check for destination not found error
		if errors.Is(err, ErrDestinationNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeDIDNotFound, "destination not found: "+err.Error())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeGenericError, "failed to activate task: "+err.Error())
	}

	logger.Info("X1 task activated",
		"xid", xid,
		"targets", len(targets),
		"destinations", len(destIDs),
		"delivery_type", details.DeliveryType,
	)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeActivateTask)
}

// handleDeactivateTask handles DeactivateTaskRequest.
func (s *Server) handleDeactivateTask(req *schema.DeactivateTaskRequest) *schema.X1ResponseMessage {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeDeactivateTask,
			ErrorCodeGenericError, "task management not configured")
	}

	if req.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeDeactivateTask,
			ErrorCodeRequestSyntaxError, "missing XID")
	}

	// Parse XID
	xid, err := uuid.Parse(string(*req.XId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeDeactivateTask,
			ErrorCodeRequestSyntaxError, "invalid XID format: "+err.Error())
	}

	// Deactivate task
	if err := s.taskManager.DeactivateTask(xid); err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeDeactivateTask,
				ErrorCodeXIDNotFound, "task not found: "+xid.String())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeDeactivateTask,
			ErrorCodeGenericError, "failed to deactivate task: "+err.Error())
	}

	logger.Info("X1 task deactivated", "xid", xid)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeDeactivateTask)
}

// handleModifyTask handles ModifyTaskRequest.
func (s *Server) handleModifyTask(req *schema.ModifyTaskRequest) *schema.X1ResponseMessage {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeGenericError, "task management not configured")
	}

	details := req.TaskDetails
	if details == nil || details.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeRequestSyntaxError, "missing task details or XID")
	}

	// Parse XID
	xid, err := uuid.Parse(string(*details.XId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeRequestSyntaxError, "invalid XID format: "+err.Error())
	}

	// Build modification
	mod := &TaskModification{}

	// Update targets if provided
	if details.TargetIdentifiers != nil {
		targets, err := extractTargetIdentifiers(details.TargetIdentifiers)
		if err != nil {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeRequestSyntaxError, err.Error())
		}
		mod.Targets = &targets
	}

	// Update destination IDs if provided
	if details.ListOfDIDs != nil {
		destIDs, err := extractDestinationIDs(details.ListOfDIDs)
		if err != nil {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeRequestSyntaxError, err.Error())
		}
		mod.DestinationIDs = &destIDs
	}

	// Update delivery type if provided
	if details.DeliveryType != "" {
		deliveryType := parseDeliveryType(details.DeliveryType)
		if deliveryType == 0 {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeDeliveryTypeNotSupport, "unsupported delivery type: "+details.DeliveryType)
		}
		mod.DeliveryType = &deliveryType
	}

	// Update implicit deactivation allowed if provided
	if details.ImplicitDeactivationAllowed != nil {
		mod.ImplicitDeactivationAllowed = details.ImplicitDeactivationAllowed
	}

	// Modify task
	if err := s.taskManager.ModifyTask(xid, mod); err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeXIDNotFound, "task not found: "+xid.String())
		}
		if errors.Is(err, ErrModifyNotAllowed) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeGenericError, "modification not allowed: "+err.Error())
		}
		if errors.Is(err, ErrDestinationNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeDIDNotFound, "destination not found: "+err.Error())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeGenericError, "failed to modify task: "+err.Error())
	}

	logger.Info("X1 task modified", "xid", xid)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeModifyTask)
}

// handleGetTaskDetails handles GetTaskDetailsRequest.
func (s *Server) handleGetTaskDetails(req *schema.GetTaskDetailsRequest) *schema.X1ResponseMessage {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeGetTaskDetails,
			ErrorCodeGenericError, "task management not configured")
	}

	if req.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeGetTaskDetails,
			ErrorCodeRequestSyntaxError, "missing XID")
	}

	// Parse XID
	xid, err := uuid.Parse(string(*req.XId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeGetTaskDetails,
			ErrorCodeRequestSyntaxError, "invalid XID format: "+err.Error())
	}

	// Get task details
	task, err := s.taskManager.GetTaskDetails(xid)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeGetTaskDetails,
				ErrorCodeXIDNotFound, "task not found: "+xid.String())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeGetTaskDetails,
			ErrorCodeGenericError, "failed to get task details: "+err.Error())
	}

	logger.Debug("X1 task details retrieved", "xid", xid, "status", task.Status)

	// Build GetTaskDetailsResponse
	// Note: For now, we return a basic OK response. A full implementation would
	// return the TaskResponseDetails with full task information.
	return s.buildOKResponse(req.X1RequestMessage, MessageTypeGetTaskDetails)
}

// extractTargetIdentifiers extracts target identities from schema.
func extractTargetIdentifiers(list *schema.ListOfTargetIdentifiers) ([]TargetIdentity, error) {
	if list == nil {
		return nil, nil
	}

	var targets []TargetIdentity
	for _, ti := range list.TargetIdentifier {
		if ti == nil {
			continue
		}

		target, err := parseTargetIdentifier(ti)
		if err != nil {
			return nil, err
		}
		if target != nil {
			targets = append(targets, *target)
		}
	}

	return targets, nil
}

// parseTargetIdentifier parses a single target identifier.
func parseTargetIdentifier(ti *schema.TargetIdentifier) (*TargetIdentity, error) {
	if ti == nil {
		return nil, nil
	}

	// SIP URI
	if ti.SipUri != nil && *ti.SipUri != "" {
		return &TargetIdentity{
			Type:  TargetTypeSIPURI,
			Value: string(*ti.SipUri),
		}, nil
	}

	// TEL URI
	if ti.TelUri != nil && *ti.TelUri != "" {
		return &TargetIdentity{
			Type:  TargetTypeTELURI,
			Value: string(*ti.TelUri),
		}, nil
	}

	// E.164 Number
	if ti.E164Number != nil && *ti.E164Number != "" {
		return &TargetIdentity{
			Type:  TargetTypeE164,
			Value: string(*ti.E164Number),
		}, nil
	}

	// IPv4 Address
	if ti.Ipv4Address != nil && *ti.Ipv4Address != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv4Address,
			Value: string(*ti.Ipv4Address),
		}, nil
	}

	// IPv4 CIDR
	if ti.Ipv4Cidr != nil {
		if ti.Ipv4Cidr.IPv4CIDR != nil && *ti.Ipv4Cidr.IPv4CIDR != "" {
			return &TargetIdentity{
				Type:  TargetTypeIPv4CIDR,
				Value: *ti.Ipv4Cidr.IPv4CIDR,
			}, nil
		}
	}

	// IPv6 Address
	if ti.Ipv6Address != nil && *ti.Ipv6Address != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv6Address,
			Value: string(*ti.Ipv6Address),
		}, nil
	}

	// IPv6 CIDR
	if ti.Ipv6Cidr != nil && *ti.Ipv6Cidr != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv6CIDR,
			Value: string(*ti.Ipv6Cidr),
		}, nil
	}

	// NAI (Network Access Identifier)
	if ti.Nai != nil && *ti.Nai != "" {
		return &TargetIdentity{
			Type:  TargetTypeNAI,
			Value: string(*ti.Nai),
		}, nil
	}

	return nil, fmt.Errorf("unsupported target identifier type")
}

// extractDestinationIDs extracts destination UUIDs from schema.
func extractDestinationIDs(list *schema.ListOfDids) ([]uuid.UUID, error) {
	if list == nil {
		return nil, nil
	}

	var destIDs []uuid.UUID
	for _, did := range list.DId {
		if did == nil {
			continue
		}
		id, err := uuid.Parse(string(*did))
		if err != nil {
			return nil, fmt.Errorf("invalid destination ID format: %w", err)
		}
		destIDs = append(destIDs, id)
	}

	return destIDs, nil
}

// parseDeliveryType parses delivery type string to enum.
func parseDeliveryType(dt string) DeliveryType {
	switch dt {
	case "X2Only":
		return DeliveryX2Only
	case "X3Only":
		return DeliveryX3Only
	case "X2andX3":
		return DeliveryX2andX3
	default:
		return 0
	}
}

// buildOKResponse creates a successful X1 response.
func (s *Server) buildOKResponse(reqMsg *schema.X1RequestMessage, messageType string) *schema.X1ResponseMessage {
	now := schema.QualifiedMicrosecondDateTime(time.Now().Format(time.RFC3339Nano))

	admfID := ""
	var transID *schema.UUID
	if reqMsg != nil {
		admfID = reqMsg.AdmfIdentifier
		transID = reqMsg.X1TransactionId
	}

	return &schema.X1ResponseMessage{
		AdmfIdentifier:   admfID,
		NeIdentifier:     s.config.NEIdentifier,
		MessageTimestamp: &now,
		Version:          s.config.Version,
		X1TransactionId:  transID,
	}
}

// buildErrorResponse creates an error X1 response.
func (s *Server) buildErrorResponse(reqMsg *schema.X1RequestMessage, messageType string, errorCode int, errorDesc string) *schema.X1ResponseMessage {
	logger.Warn("X1 error response",
		"message_type", messageType,
		"error_code", errorCode,
		"error_desc", errorDesc,
	)

	now := schema.QualifiedMicrosecondDateTime(time.Now().Format(time.RFC3339Nano))

	admfID := ""
	var transID *schema.UUID
	if reqMsg != nil {
		admfID = reqMsg.AdmfIdentifier
		transID = reqMsg.X1TransactionId
	}

	// Note: The ErrorResponse type embeds X1ResponseMessage but we return
	// the base response for simplicity. A full implementation would return
	// the ErrorResponse type with proper XML marshaling.
	return &schema.X1ResponseMessage{
		AdmfIdentifier:   admfID,
		NeIdentifier:     s.config.NEIdentifier,
		MessageTimestamp: &now,
		Version:          s.config.Version,
		X1TransactionId:  transID,
	}
}

// sendErrorResponse sends a top-level error response.
func (s *Server) sendErrorResponse(w http.ResponseWriter, admfID string, errorCode int, errorDesc string) {
	logger.Warn("X1 top-level error",
		"error_code", errorCode,
		"error_desc", errorDesc,
	)

	now := schema.QualifiedMicrosecondDateTime(time.Now().Format(time.RFC3339Nano))
	resp := &schema.TopLevelErrorResponse{
		AdmfIdentifier:   admfID,
		NeIdentifier:     s.config.NEIdentifier,
		MessageTimestamp: &now,
		Version:          s.config.Version,
	}

	respBody, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentTypeXML)
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write(respBody); err != nil {
		logger.Error("X1 failed to write error response", "error", err)
	}
}

// extractDeliveryAddress extracts address and port from DeliveryAddress.
func extractDeliveryAddress(da *schema.DeliveryAddress) (string, int, error) {
	if da == nil {
		return "", 0, fmt.Errorf("missing delivery address")
	}

	// Try IP address and port
	if da.IpAddressAndPort != nil {
		ipap := da.IpAddressAndPort

		// Extract address
		var address string
		if ipap.Address != nil {
			if ipap.Address.IPv4Address != nil {
				address = *ipap.Address.IPv4Address
			} else if ipap.Address.IPv6Address != nil {
				address = *ipap.Address.IPv6Address
			}
		}

		if address == "" {
			return "", 0, fmt.Errorf("missing IP address in delivery address")
		}

		// Extract port
		var port int
		if ipap.Port != nil {
			if ipap.Port.TCPPort != nil {
				port = *ipap.Port.TCPPort
			} else if ipap.Port.UDPPort != nil {
				port = *ipap.Port.UDPPort
			}
		}

		if port == 0 {
			return "", 0, fmt.Errorf("missing port in delivery address")
		}

		return address, port, nil
	}

	// Try URI
	if da.Uri != nil && *da.Uri != "" {
		// For now, just return the URI as address with default port
		// A full implementation would parse the URI
		return *da.Uri, 443, nil
	}

	return "", 0, fmt.Errorf("unsupported delivery address format")
}
