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
	MessageTypePing              = "PingRequest"
)

// Sentinel errors for destination operations.
var (
	// ErrDestinationNotFound indicates the requested destination DID does not exist.
	ErrDestinationNotFound = errors.New("destination not found")
	// ErrDestinationAlreadyExists indicates a destination with the given DID already exists.
	ErrDestinationAlreadyExists = errors.New("destination already exists")
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

// Server implements the X1 administration interface.
type Server struct {
	mu           sync.RWMutex
	config       ServerConfig
	destManager  DestinationManager
	httpServer   *http.Server
	shutdownOnce sync.Once
}

// NewServer creates a new X1 server.
func NewServer(config ServerConfig, destManager DestinationManager) *Server {
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
	}
}

// Start begins serving the X1 interface.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Build TLS config with mutual TLS
	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
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
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}

	logger.Info("X1 server starting",
		"addr", s.config.ListenAddr,
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
