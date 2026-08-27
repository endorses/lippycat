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
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

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

// etsiX1Namespace is the ETSI TS 103 221-1 XML namespace for X1 messages.
const etsiX1Namespace = "http://uri.etsi.org/03221/X1/2017/10"

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

// X1 error response request types. These are operation names from the
// RequestMessageType schema enumeration, not request element/type names.
const (
	RequestTypeCreateDestination = "CreateDestination"
	RequestTypeModifyDestination = "ModifyDestination"
	RequestTypeRemoveDestination = "RemoveDestination"
	RequestTypeActivateTask      = "ActivateTask"
	RequestTypeDeactivateTask    = "DeactivateTask"
	RequestTypeModifyTask        = "ModifyTask"
	RequestTypeGetTaskDetails    = "GetTaskDetails"
	RequestTypePing              = "Ping"
	RequestTypeExtended          = "ExtendedRequestMessageType"
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
	// ErrTaskDefinitionConflict indicates that an existing XID was reasserted
	// with different enforcement semantics and must be changed with ModifyTask.
	ErrTaskDefinitionConflict = errors.New("task definition conflicts with existing task")
	// ErrReactivationIdentityConflict indicates that a retained task was
	// reasserted with different protected interception identity fields.
	ErrReactivationIdentityConflict = errors.New("retained task interception identity differs")
	// ErrInvalidTask indicates the task parameters are invalid.
	ErrInvalidTask = errors.New("invalid task parameters")
	// ErrModifyNotAllowed indicates the requested modification is not permitted.
	ErrModifyNotAllowed = errors.New("modification not allowed")
	// ErrUnsupportedDeliveryCombination indicates that the requested targets
	// and delivery type cannot be produced by this network element.
	ErrUnsupportedDeliveryCombination = errors.New("unsupported delivery combination")
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
	// ProtocolType preserves the X1 destination delivery type.
	ProtocolType string
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

	// Version is the declared outbound X1 protocol version. It defaults to
	// DefaultProtocolVersion; inbound compatibility is independently validated.
	Version string

	// RateLimitPerIP is the maximum requests per second per IP address (default: 10).
	RateLimitPerIP float64

	// RateLimitBurst is the maximum burst size for rate limiting (default: 20).
	RateLimitBurst int

	// TrustedProxyCIDRs are the only peers whose Forwarded or
	// X-Forwarded-For headers are accepted. Empty means no trusted proxies.
	TrustedProxyCIDRs []string
	// RateLimiterMaxEntries bounds per-client limiter memory. Defaults to 4096.
	RateLimiterMaxEntries int
	// RateLimiterTTL expires idle client entries. Defaults to 15 minutes.
	RateLimiterTTL time.Duration

	// XMLParseTimeout is the maximum time allowed for XML parsing (default: 5s).
	XMLParseTimeout time.Duration

	// OnADMFIdentified is called when the ADMF identifier is learned from an inbound request.
	// This allows the client to include the ADMF identifier in outbound messages.
	OnADMFIdentified func(admfID string)
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

	rateLimitersMu       sync.Mutex
	rateLimiters         map[string]*limiterEntry
	trustedProxies       []netip.Prefix
	rateLimiterEvictions atomic.Uint64

	revisionMetrics revisionMetrics
	revisionLogsMu  sync.Mutex
	revisionLogs    map[string]struct{}
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const DefaultProtocolVersion = "v1.22.1"

// The inbound window is based on verified wire compatibility with the bundled
// V1.22.1 schema. It is deliberately not a general semantic-version policy.
const minimumProtocolVersion = "v1.13.1"

type protocolRevision struct{ major, minor, patch int }
type revisionDisposition uint8

const (
	revisionAcceptedExact revisionDisposition = iota
	revisionAcceptedCompatible
	revisionAbsent
	revisionMalformed
	revisionUnsupported
)

type revisionMetrics struct {
	acceptedExact, acceptedCompatible atomic.Uint64
	absent, malformed, unsupported    atomic.Uint64
}

// RevisionStats is a snapshot of inbound X1 protocol revision counters.
type RevisionStats struct {
	AcceptedExact, AcceptedCompatible uint64
	Absent, Malformed, Unsupported    uint64
}

func parseProtocolRevision(version string) (protocolRevision, error) {
	value := version
	if strings.HasPrefix(value, "v") {
		value = value[1:]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return protocolRevision{}, fmt.Errorf("expected MAJOR.MINOR.PATCH")
	}
	values := [3]int{}
	for i, part := range parts {
		if part == "" {
			return protocolRevision{}, fmt.Errorf("empty revision component")
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return protocolRevision{}, fmt.Errorf("non-numeric revision component")
			}
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return protocolRevision{}, fmt.Errorf("revision component out of range: %w", err)
		}
		values[i] = parsed
	}
	return protocolRevision{values[0], values[1], values[2]}, nil
}

func compareProtocolRevisions(left, right protocolRevision) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	return left.patch - right.patch
}

func classifyProtocolVersion(version string) revisionDisposition {
	if version == "" {
		return revisionAbsent
	}
	revision, err := parseProtocolRevision(version)
	if err != nil {
		return revisionMalformed
	}
	minimum, _ := parseProtocolRevision(minimumProtocolVersion)
	maximum, _ := parseProtocolRevision(DefaultProtocolVersion)
	if compareProtocolRevisions(revision, minimum) < 0 || compareProtocolRevisions(revision, maximum) > 0 {
		return revisionUnsupported
	}
	if compareProtocolRevisions(revision, maximum) == 0 {
		return revisionAcceptedExact
	}
	return revisionAcceptedCompatible
}

// RevisionStats returns inbound revision classifications since server creation.
func (s *Server) RevisionStats() RevisionStats {
	return RevisionStats{
		AcceptedExact: s.revisionMetrics.acceptedExact.Load(), AcceptedCompatible: s.revisionMetrics.acceptedCompatible.Load(),
		Absent: s.revisionMetrics.absent.Load(), Malformed: s.revisionMetrics.malformed.Load(), Unsupported: s.revisionMetrics.unsupported.Load(),
	}
}

// NewServer creates a new X1 server.
func NewServer(config ServerConfig, destManager DestinationManager, taskManager TaskManager) *Server {
	if config.Version == "" {
		config.Version = DefaultProtocolVersion
	}
	if config.NEIdentifier == "" {
		hostname, _ := os.Hostname()
		config.NEIdentifier = hostname
	}
	if config.RateLimitPerIP <= 0 {
		config.RateLimitPerIP = 10 // 10 requests/second per IP
	}
	if config.RateLimitBurst <= 0 {
		config.RateLimitBurst = 20
	}
	if config.XMLParseTimeout <= 0 {
		config.XMLParseTimeout = 5 * time.Second
	}
	if config.RateLimiterMaxEntries <= 0 {
		config.RateLimiterMaxEntries = 4096
	}
	if config.RateLimiterTTL <= 0 {
		config.RateLimiterTTL = 15 * time.Minute
	}
	trusted := make([]netip.Prefix, 0, len(config.TrustedProxyCIDRs))
	for _, raw := range config.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			logger.Error("ignoring invalid trusted proxy CIDR", "cidr", raw, "error", err)
			continue
		}
		trusted = append(trusted, prefix.Masked())
	}

	return &Server{
		config:         config,
		destManager:    destManager,
		taskManager:    taskManager,
		rateLimiters:   make(map[string]*limiterEntry),
		revisionLogs:   make(map[string]struct{}),
		trustedProxies: trusted,
	}
}

// Start begins serving the X1 interface.
func (s *Server) Start(ctx context.Context) error {
	if err := s.ValidateConfiguration(); err != nil {
		return err
	}
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
		"mutual_tls", true,
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

// ValidateConfiguration verifies that the X1 listener can start with mandatory
// mutual TLS. It is safe to call before Start so callers can fail before
// launching any background lifecycle work.
func (s *Server) ValidateConfiguration() error {
	if s.config.ListenAddr == "" {
		return errors.New("X1 listen address is required")
	}
	if s.config.TLSCertFile == "" {
		return errors.New("X1 server TLS certificate is required")
	}
	if s.config.TLSKeyFile == "" {
		return errors.New("X1 server TLS key is required")
	}
	if s.config.TLSCAFile == "" {
		return errors.New("X1 client CA is required for mutual TLS authentication")
	}
	if _, err := s.buildTLSConfig(); err != nil {
		return fmt.Errorf("invalid X1 TLS configuration: %w", err)
	}
	return nil
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
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	if s.config.TLSCAFile == "" {
		return nil, errors.New("X1 client CA is required for mutual TLS authentication")
	}
	caCert, err := os.ReadFile(s.config.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig.ClientCAs = certPool

	logger.Info("X1 mutual TLS enabled", "ca_file", s.config.TLSCAFile)

	return tlsConfig, nil
}

// getRateLimiter returns the rate limiter for the given IP, creating one if necessary.
func (s *Server) getRateLimiter(ip string) *rate.Limiter {
	now := time.Now()
	s.rateLimitersMu.Lock()
	defer s.rateLimitersMu.Unlock()
	if entry := s.rateLimiters[ip]; entry != nil {
		entry.lastSeen = now
		return entry.limiter
	}
	for key, entry := range s.rateLimiters {
		if now.Sub(entry.lastSeen) > s.config.RateLimiterTTL {
			delete(s.rateLimiters, key)
			s.rateLimiterEvictions.Add(1)
		}
	}
	if len(s.rateLimiters) >= s.config.RateLimiterMaxEntries {
		var oldestKey string
		var oldest time.Time
		for key, entry := range s.rateLimiters {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey, oldest = key, entry.lastSeen
			}
		}
		delete(s.rateLimiters, oldestKey)
		s.rateLimiterEvictions.Add(1)
	}
	limiter := rate.NewLimiter(rate.Limit(s.config.RateLimitPerIP), s.config.RateLimitBurst)
	s.rateLimiters[ip] = &limiterEntry{limiter: limiter, lastSeen: now}
	return limiter
}

// RateLimiterStats reports bounded-cache observability counters.
func (s *Server) RateLimiterStats() (entries int, evictions uint64) {
	s.rateLimitersMu.Lock()
	entries = len(s.rateLimiters)
	s.rateLimitersMu.Unlock()
	return entries, s.rateLimiterEvictions.Load()
}

// extractClientIP extracts the client IP from the request, handling proxies.
func extractClientIP(r *http.Request) string {
	// For X1, we typically don't go through proxies, but handle X-Forwarded-For if present
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Extract IP from RemoteAddr (host:port format)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return host
	}
	trusted := false
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return peer.String()
	}
	// RFC 7239 Forwarded takes precedence. Use the first valid client address.
	if forwarded := r.Header.Values("Forwarded"); len(forwarded) > 0 {
		for _, field := range strings.Split(strings.Join(forwarded, ","), ",") {
			for _, param := range strings.Split(field, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
				if !ok || !strings.EqualFold(key, "for") {
					continue
				}
				if addr, ok := parseForwardedAddr(value); ok {
					return addr.String()
				}
			}
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return peer.String()
			}
			if addr.IsValid() {
				return addr.String()
			}
		}
	}
	return peer.String()
}

func parseForwardedAddr(raw string) (netip.Addr, bool) {
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	if strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			raw = host
		}
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr, true
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		addr, err := netip.ParseAddr(host)
		return addr, err == nil
	}
	return netip.Addr{}, false
}

// handleX1Request handles incoming X1 requests.
func (s *Server) handleX1Request(w http.ResponseWriter, r *http.Request) {
	// Extract client IP for rate limiting
	clientIP := s.clientIP(r)

	// Check rate limit
	limiter := s.getRateLimiter(clientIP)
	if !limiter.Allow() {
		logger.Warn("X1 rate limit exceeded",
			"remote", r.RemoteAddr,
			"client_ip", clientIP,
		)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

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

	// Create context with timeout for XML parsing
	ctx, cancel := context.WithTimeout(r.Context(), s.config.XMLParseTimeout)
	defer cancel()

	// Parse XML with timeout protection via goroutine
	type parseResult struct {
		rootDetector xmlRootDetector
		err          error
	}
	resultCh := make(chan parseResult, 1)

	go func() {
		var root xmlRootDetector
		err := xml.Unmarshal(body, &root)
		resultCh <- parseResult{root, err}
	}()

	// Wait for result or timeout
	var rootDetector xmlRootDetector
	select {
	case result := <-resultCh:
		if result.err != nil {
			s.sendErrorResponse(w, "", ErrorCodeRequestSyntaxError, "invalid XML: "+result.err.Error())
			return
		}
		rootDetector = result.rootDetector
	case <-ctx.Done():
		logger.Warn("X1 XML parsing timeout",
			"remote", r.RemoteAddr,
			"timeout", s.config.XMLParseTimeout,
		)
		http.Error(w, "request timeout", http.StatusServiceUnavailable)
		return
	}

	var responses []any

	// Check if it's a request container (batch), X1Request envelope, or a direct request.
	switch rootDetector.XMLName.Local {
	case "requestContainer":
		// Legacy container format. Decode the concrete message envelopes rather
		// than schema.RequestContainer: the generated base-message slice drops
		// xsi:type and operation-specific fields.
		var reqContainer x1RequestEnvelope
		if err := xml.Unmarshal(body, &reqContainer); err != nil {
			s.sendErrorResponse(w, "", ErrorCodeRequestSyntaxError, "invalid XML: "+err.Error())
			return
		}
		for _, message := range reqContainer.RequestMessages {
			responses = append(responses, s.processEnvelopeMessage(message, clientIP))
		}
		if len(reqContainer.RequestMessages) == 0 {
			responses = append(responses, s.buildErrorResponse(nil, "requestContainer", ErrorCodeRequestSyntaxError, "request container is empty"))
		}

	case "X1Request":
		// ETSI-compliant X1Request envelope with xsi:type on x1RequestMessage.
		responses = append(responses, s.processX1RequestEnvelope(body, clientIP)...)

	default:
		// Direct request (not wrapped in container) for backward compatibility.
		resp := s.processRequestMessage(body, nil, clientIP)
		responses = append(responses, resp)
	}

	// Build flexible response container that handles both success and error responses
	respContainer := &flexibleResponseContainer{
		Responses: responses,
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

// flexibleResponseContainer wraps responses for XML marshaling.
// It handles both X1ResponseMessage and ErrorResponse types properly.
type flexibleResponseContainer struct {
	Responses []any
}

// MarshalXML implements custom marshaling for the flexible response container.
// Each response is marshaled with the appropriate xml element name based on its type.
// Per ETSI TS 103 221-1, responses are wrapped in <X1Response xmlns="...">.
func (c *flexibleResponseContainer) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	// Start the X1Response element with ETSI namespace.
	containerStart := xml.StartElement{
		Name: xml.Name{Local: "X1Response", Space: etsiX1Namespace},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns:xsi"}, Value: "http://www.w3.org/2001/XMLSchema-instance"}},
	}
	if err := e.EncodeToken(containerStart); err != nil {
		return err
	}

	// Every response is carried in the element declared by ResponseContainer.
	// Derived response values identify their concrete schema type using xsi:type.
	for _, resp := range c.Responses {
		respStart := xml.StartElement{Name: xml.Name{Local: "x1ResponseMessage"}}
		responseType := reflect.TypeOf(resp)
		if responseType == nil {
			return errors.New("cannot marshal nil X1 response")
		}
		if responseType.Kind() == reflect.Pointer {
			responseType = responseType.Elem()
		}
		if responseType.Name() != "X1ResponseMessage" {
			respStart.Attr = append(respStart.Attr, xml.Attr{
				Name:  xml.Name{Local: "xsi:type"},
				Value: responseType.Name(),
			})
		}
		if err := e.EncodeElement(resp, respStart); err != nil {
			return err
		}
	}

	// End the responseContainer element
	if err := e.EncodeToken(containerStart.End()); err != nil {
		return err
	}

	return e.Flush()
}

// x1RequestEnvelope represents the ETSI-compliant X1Request envelope.
// The x1RequestMessage element uses xsi:type to indicate the concrete request type.
type x1RequestEnvelope struct {
	XMLName         xml.Name
	RequestMessages []x1RequestMessageAttr `xml:"x1RequestMessage"`
}

// x1RequestMessageAttr captures the xsi:type attribute, admfIdentifier, and inner XML from x1RequestMessage.
type x1RequestMessageAttr struct {
	Type           string `xml:"type,attr"`
	AdmfIdentifier string `xml:"admfIdentifier"`
	InnerXML       []byte `xml:",innerxml"`
}

// processX1RequestEnvelope processes an ETSI-compliant X1Request envelope.
// It extracts the xsi:type from x1RequestMessage and synthesizes a bare request
// for processing by processRequestMessage.
func (s *Server) processX1RequestEnvelope(body []byte, peer string) []any {
	var envelope x1RequestEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return []any{s.buildErrorResponse(nil, "Unknown", ErrorCodeRequestSyntaxError, "invalid X1Request envelope: "+err.Error())}
	}
	if len(envelope.RequestMessages) == 0 {
		return []any{s.buildErrorResponse(nil, "Unknown", ErrorCodeRequestSyntaxError, "X1Request envelope is empty")}
	}
	responses := make([]any, 0, len(envelope.RequestMessages))
	for _, message := range envelope.RequestMessages {
		responses = append(responses, s.processEnvelopeMessage(message, peer))
	}
	return responses
}

func (s *Server) processEnvelopeMessage(message x1RequestMessageAttr, peer string) any {
	requestMessage := envelopeBaseMessage(message)
	messageType := message.Type
	if messageType == "" {
		return s.buildErrorResponse(requestMessage, "Unknown", ErrorCodeRequestSyntaxError, "missing xsi:type on x1RequestMessage")
	}
	if strings.EqualFold(messageType, "requestContainer") || containsElement(message.InnerXML, "requestContainer") || containsElement(message.InnerXML, "X1Request") {
		return s.buildErrorResponse(requestMessage, "requestContainer", ErrorCodeRequestSyntaxError, "nested request containers not supported")
	}

	// Learn the ADMF identifier from the inbound request.
	if message.AdmfIdentifier != "" && s.config.OnADMFIdentified != nil {
		s.config.OnADMFIdentified(message.AdmfIdentifier)
	}

	// Synthesize a bare request XML from the xsi:type and inner content
	// so it can be processed by the existing processRequestMessage logic.
	syntheticXML := []byte("<" + messageType + ">" + string(message.InnerXML) + "</" + messageType + ">")

	return s.processRequestMessage(syntheticXML, requestMessage, peer)
}

func containsElement(data []byte, localName string) bool {
	decoder := xml.NewDecoder(strings.NewReader("<root>" + string(data) + "</root>"))
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if start, ok := token.(xml.StartElement); ok && strings.EqualFold(start.Name.Local, localName) {
			return true
		}
	}
}

func envelopeBaseMessage(message x1RequestMessageAttr) *schema.X1RequestMessage {
	var requestMessage schema.X1RequestMessage
	syntheticXML := []byte("<x1RequestMessage>" + string(message.InnerXML) + "</x1RequestMessage>")
	if err := xml.Unmarshal(syntheticXML, &requestMessage); err != nil {
		return nil
	}
	return &requestMessage
}

func (s *Server) validateProtocolVersion(reqMsg *schema.X1RequestMessage, peer string) *schema.ErrorResponse {
	version := ""
	if reqMsg != nil {
		version = reqMsg.Version
	}
	switch classifyProtocolVersion(version) {
	case revisionAcceptedExact:
		s.revisionMetrics.acceptedExact.Add(1)
	case revisionAcceptedCompatible:
		s.revisionMetrics.acceptedCompatible.Add(1)
		revision, _ := parseProtocolRevision(version)
		s.logRevisionOnce(peer, revision.String())
	case revisionAbsent:
		s.revisionMetrics.absent.Add(1)
		s.logRevisionOnce(peer, "unspecified")
	case revisionMalformed:
		s.revisionMetrics.malformed.Add(1)
		return s.protocolVersionError(reqMsg, version)
	case revisionUnsupported:
		s.revisionMetrics.unsupported.Add(1)
		return s.protocolVersionError(reqMsg, version)
	}
	return nil
}

func (r protocolRevision) String() string {
	return fmt.Sprintf("v%d.%d.%d", r.major, r.minor, r.patch)
}

func (s *Server) protocolVersionError(reqMsg *schema.X1RequestMessage, version string) *schema.ErrorResponse {
	return s.buildErrorResponse(reqMsg, "Unknown", ErrorCodeRequestSyntaxError,
		fmt.Sprintf("unsupported X1 protocol version %q; supported range is %s through %s", version, minimumProtocolVersion, DefaultProtocolVersion))
}

func (s *Server) logRevisionOnce(peer, version string) {
	if peer == "" {
		peer = "unknown"
	}
	key := peer + "\x00" + version
	s.revisionLogsMu.Lock()
	defer s.revisionLogsMu.Unlock()
	if _, loaded := s.revisionLogs[key]; loaded {
		return
	}
	// Bound peer-derived observability state using the same configured ceiling
	// as the per-client rate-limiter cache.
	if len(s.revisionLogs) >= s.config.RateLimiterMaxEntries {
		for oldKey := range s.revisionLogs {
			delete(s.revisionLogs, oldKey)
			break
		}
	}
	s.revisionLogs[key] = struct{}{}
	logger.Info("X1 peer uses a compatible protocol revision",
		"peer", peer, "peer_revision", version, "declared_revision", DefaultProtocolVersion)
}

// processRequestMessage processes a single X1 request message.
// Returns either *schema.X1ResponseMessage for success or *schema.ErrorResponse for errors.
func (s *Server) processRequestMessage(body []byte, reqMsg *schema.X1RequestMessage, peer string) any {
	if reqMsg == nil {
		var parsed schema.X1RequestMessage
		if err := xml.Unmarshal(body, &parsed); err == nil {
			reqMsg = &parsed
		}
	}
	if response := s.validateProtocolVersion(reqMsg, peer); response != nil {
		return response
	}
	// Learn the ADMF identifier from the inbound request.
	if reqMsg != nil && reqMsg.AdmfIdentifier != "" && s.config.OnADMFIdentified != nil {
		s.config.OnADMFIdentified(reqMsg.AdmfIdentifier)
	}

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
func (s *Server) handleCreateDestination(req *schema.CreateDestinationRequest) any {
	details := req.DestinationDetails
	if details == nil || details.DId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			ErrorCodeRequestSyntaxError, "missing destination details or DID")
	}
	if capabilityErr := validateDestinationCapabilities(details, false); capabilityErr != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeCreateDestination,
			capabilityErr.code, capabilityErr.Error())
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
		DID:          did,
		Address:      address,
		Port:         port,
		X2Enabled:    details.DeliveryType == "X2Only" || details.DeliveryType == "X2andX3",
		X3Enabled:    details.DeliveryType == "X3Only" || details.DeliveryType == "X2andX3",
		ProtocolType: details.DeliveryType,
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
func (s *Server) handleModifyDestination(req *schema.ModifyDestinationRequest) any {
	details := req.DestinationDetails
	if details == nil || details.DId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			ErrorCodeRequestSyntaxError, "missing destination details or DID")
	}
	if capabilityErr := validateDestinationCapabilities(details, true); capabilityErr != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyDestination,
			capabilityErr.code, capabilityErr.Error())
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
		existing.ProtocolType = details.DeliveryType
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
func (s *Server) handleRemoveDestination(req *schema.RemoveDestinationRequest) any {
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
func (s *Server) handlePing(req *schema.PingRequest) any {
	logger.Debug("X1 ping received")
	return s.buildOKResponse(req.X1RequestMessage, MessageTypePing)
}

// handleActivateTask handles ActivateTaskRequest.
func (s *Server) handleActivateTask(req *schema.ActivateTaskRequest) any {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeGenericError, "task management not configured")
	}

	details := req.TaskDetails
	if details == nil || details.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "missing task details or XID")
	}
	if capabilityErr := validateTaskCapabilities(details, false); capabilityErr != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			capabilityErr.code, capabilityErr.Error())
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
	startTime, endTime, err := extractMediationWindow(details.ListOfMediationDetails)
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeRequestSyntaxError, "invalid mediation window: "+err.Error())
	}
	task.StartTime = startTime
	task.EndTime = endTime

	// Parse implicit deactivation allowed
	if details.ImplicitDeactivationAllowed != nil {
		task.ImplicitDeactivationAllowed = *details.ImplicitDeactivationAllowed
	}

	// Activate task
	if err := s.taskManager.ActivateTask(task); err != nil {
		if errors.Is(err, ErrReactivationIdentityConflict) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeGenericError, "retained task's interception identity differs: "+xid.String())
		}
		if errors.Is(err, ErrTaskDefinitionConflict) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeXIDAlreadyExists, "task definition conflicts with existing XID; use ModifyTask: "+xid.String())
		}
		if errors.Is(err, ErrTaskAlreadyExists) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeXIDAlreadyExists, "task already exists: "+xid.String())
		}
		if errors.Is(err, ErrInvalidTask) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeRequestSyntaxError, "invalid task: "+err.Error())
		}
		if errors.Is(err, ErrUnsupportedDeliveryCombination) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeDeliveryNotPossible, "unsupported task capability: "+err.Error())
		}
		// Check for destination not found error
		if errors.Is(err, ErrDestinationNotFound) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
				ErrorCodeDIDNotFound, "destination not found: "+err.Error())
		}
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeActivateTask,
			ErrorCodeGenericError, "failed to activate task: "+err.Error())
	}

	if hasMediationIdentity(details.ListOfMediationDetails) {
		logger.Info("X1 mediation identity recorded but not used for enforcement",
			"xid", xid,
			"reason", "lippycat delivers by DID; the MDF owns XID-to-LIID mapping",
		)
	}

	logger.Info("X1 task activated",
		"xid", xid,
		"targets", len(targets),
		"destinations", len(destIDs),
		"delivery_type", details.DeliveryType,
	)

	return s.buildOKResponse(req.X1RequestMessage, MessageTypeActivateTask)
}

func hasMediationIdentity(list *schema.ListOfMediationDetails) bool {
	if list == nil {
		return false
	}
	for _, mediation := range list.MediationDetails {
		if mediation != nil && (mediation.LIID != nil || mediation.DeliveryType != "") {
			return true
		}
	}
	return false
}

// handleDeactivateTask handles DeactivateTaskRequest.
func (s *Server) handleDeactivateTask(req *schema.DeactivateTaskRequest) any {
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
func (s *Server) handleModifyTask(req *schema.ModifyTaskRequest) any {
	if s.taskManager == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeGenericError, "task management not configured")
	}

	details := req.TaskDetails
	if details == nil || details.XId == nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeRequestSyntaxError, "missing task details or XID")
	}
	if capabilityErr := validateTaskCapabilities(details, true); capabilityErr != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			capabilityErr.code, capabilityErr.Error())
	}

	// Parse XID
	xid, err := uuid.Parse(string(*details.XId))
	if err != nil {
		return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
			ErrorCodeRequestSyntaxError, "invalid XID format: "+err.Error())
	}

	// Build modification
	mod := &TaskModification{}
	if details.ListOfMediationDetails != nil {
		_, endTime, err := extractMediationWindow(details.ListOfMediationDetails)
		if err != nil {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeRequestSyntaxError, "invalid mediation window: "+err.Error())
		}
		mod.EndTime = &endTime
	}

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
		if errors.Is(err, ErrInvalidTask) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeRequestSyntaxError, "invalid task modification: "+err.Error())
		}
		if errors.Is(err, ErrUnsupportedDeliveryCombination) {
			return s.buildErrorResponse(req.X1RequestMessage, MessageTypeModifyTask,
				ErrorCodeDeliveryNotPossible, "unsupported task capability: "+err.Error())
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

// extractMediationWindow returns the single effective window representable by
// the current task model. An absent EndTime explicitly means an indefinite task.
func extractMediationWindow(list *schema.ListOfMediationDetails) (time.Time, time.Time, error) {
	if list == nil || len(list.MediationDetails) == 0 {
		return time.Time{}, time.Time{}, nil
	}
	var effectiveStart, effectiveEnd time.Time
	initialized := false
	for i, details := range list.MediationDetails {
		if details == nil {
			return time.Time{}, time.Time{}, fmt.Errorf("entry %d is nil", i)
		}
		start, err := parseMediationTime(details.StartTime)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("entry %d StartTime: %w", i, err)
		}
		end, err := parseMediationTime(details.EndTime)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("entry %d EndTime: %w", i, err)
		}
		if !end.IsZero() && !end.After(start) {
			return time.Time{}, time.Time{}, fmt.Errorf("entry %d EndTime must be after StartTime", i)
		}
		if !initialized {
			effectiveStart, effectiveEnd, initialized = start, end, true
			continue
		}
		if !start.Equal(effectiveStart) || !end.Equal(effectiveEnd) {
			return time.Time{}, time.Time{}, fmt.Errorf("mediation entries have inconsistent time windows")
		}
	}
	return effectiveStart, effectiveEnd, nil
}

func parseMediationTime(value *schema.QualifiedMicrosecondDateTime) (time.Time, error) {
	if value == nil || string(*value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(*value))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %q: %w", string(*value), err)
	}
	return parsed, nil
}

// handleGetTaskDetails handles GetTaskDetailsRequest.
func (s *Server) handleGetTaskDetails(req *schema.GetTaskDetailsRequest) any {
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

	return &schema.GetTaskDetailsResponse{
		X1ResponseMessage: s.responseMessage(req.X1RequestMessage),
		TaskResponseDetails: &schema.TaskResponseDetails{
			TaskDetails: taskDetailsResponse(task),
			TaskStatus: &schema.TaskStatus{
				ProvisioningStatus: taskProvisioningStatus(task.Status),
				ListOfFaults:       taskFaults(task.LastError),
			},
		},
	}
}

func taskDetailsResponse(task *Task) *schema.TaskDetails {
	xid := schema.UUID(task.XID.String())
	details := &schema.TaskDetails{
		XId:                         &xid,
		DeliveryType:                deliveryTypeResponse(task.DeliveryType),
		ImplicitDeactivationAllowed: &task.ImplicitDeactivationAllowed,
		TargetIdentifiers:           &schema.ListOfTargetIdentifiers{},
		ListOfDIDs:                  &schema.ListOfDids{},
	}
	for _, target := range task.Targets {
		details.TargetIdentifiers.TargetIdentifier = append(details.TargetIdentifiers.TargetIdentifier, targetIdentifierResponse(target))
	}
	for _, id := range task.DestinationIDs {
		did := schema.UUID(id.String())
		details.ListOfDIDs.DId = append(details.ListOfDIDs.DId, &did)
	}
	liid := schema.LIID(strings.ReplaceAll(task.XID.String(), "-", ""))
	mediation := &schema.MediationDetails{LIID: &liid, DeliveryType: mediationDeliveryTypeResponse(task.DeliveryType), ListOfDIDs: details.ListOfDIDs}
	if !task.StartTime.IsZero() {
		start := formatQualifiedMicrosecondDateTime(task.StartTime)
		mediation.StartTime = &start
	}
	if !task.EndTime.IsZero() {
		end := formatQualifiedMicrosecondDateTime(task.EndTime)
		mediation.EndTime = &end
	}
	details.ListOfMediationDetails = &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{mediation}}
	return details
}

func deliveryTypeResponse(deliveryType DeliveryType) string {
	switch deliveryType {
	case DeliveryX2Only:
		return "X2Only"
	case DeliveryX3Only:
		return "X3Only"
	case DeliveryX2andX3:
		return "X2andX3"
	default:
		return ""
	}
}

func mediationDeliveryTypeResponse(deliveryType DeliveryType) string {
	switch deliveryType {
	case DeliveryX2Only:
		return "HI2Only"
	case DeliveryX3Only:
		return "HI3Only"
	case DeliveryX2andX3:
		return "HI2andHI3"
	default:
		return ""
	}
}

func targetIdentifierResponse(target TargetIdentity) *schema.TargetIdentifier {
	result := &schema.TargetIdentifier{}
	switch target.Type {
	case TargetTypeSIPURI:
		v := schema.SIPURI(target.Value)
		result.SipUri = &v
	case TargetTypeTELURI:
		v := schema.TELURI(target.Value)
		result.TelUri = &v
	case TargetTypeIPv4Address:
		v := schema.IPv4Address(target.Value)
		result.Ipv4Address = &v
	case TargetTypeIPv4CIDR:
		v := target.Value
		result.Ipv4Cidr = &schema.IPCIDR{IPv4CIDR: &v}
	case TargetTypeIPv6Address:
		v := schema.IPv6Address(target.Value)
		result.Ipv6Address = &v
	case TargetTypeIPv6CIDR:
		v := schema.IPv6CIDR(target.Value)
		result.Ipv6Cidr = &v
	case TargetTypeNAI:
		v := schema.NAI(target.Value)
		result.Nai = &v
	case TargetTypeE164:
		v := schema.InternationalE164(target.Value)
		result.E164Number = &v
	}
	return result
}

func taskProvisioningStatus(status TaskStatus) string {
	switch status {
	case TaskStatusPending:
		return "awaitingProvisioning"
	case TaskStatusActive, TaskStatusSuspended, TaskStatusDeactivated:
		return "complete"
	case TaskStatusFailed:
		return "failed"
	default:
		return "failed"
	}
}

func taskFaults(lastError string) *schema.ListOfFaults {
	if lastError == "" {
		return &schema.ListOfFaults{}
	}
	return &schema.ListOfFaults{UnresolvedFault: []*schema.ErrorInformation{{ErrorCode: ErrorCodeGenericError, ErrorDescription: lastError}}}
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
func (s *Server) buildOKResponse(reqMsg *schema.X1RequestMessage, messageType string) any {
	return s.responseMessage(reqMsg)
}

func (s *Server) responseMessage(reqMsg *schema.X1RequestMessage) *schema.X1ResponseMessage {
	now := formatQualifiedMicrosecondDateTime(time.Now())

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

// buildErrorResponse creates an error X1 response per ETSI TS 103 221-1.
// Returns a complete ErrorResponse with error code and description.
func (s *Server) buildErrorResponse(reqMsg *schema.X1RequestMessage, messageType string, errorCode int, errorDesc string) *schema.ErrorResponse {
	logger.Warn("X1 error response",
		"message_type", messageType,
		"error_code", errorCode,
		"error_desc", errorDesc,
	)

	now := formatQualifiedMicrosecondDateTime(time.Now())

	admfID := ""
	var transID *schema.UUID
	if reqMsg != nil {
		admfID = reqMsg.AdmfIdentifier
		transID = reqMsg.X1TransactionId
	}

	requestType, extension := errorRequestType(messageType)
	return &schema.ErrorResponse{
		RequestMessageType:   requestType,
		ExtensionInformation: extension,
		ErrorInformation: &schema.ErrorInformation{
			ErrorCode:        errorCode,
			ErrorDescription: errorDesc,
		},
		X1ResponseMessage: &schema.X1ResponseMessage{
			AdmfIdentifier:   admfID,
			NeIdentifier:     s.config.NEIdentifier,
			MessageTimestamp: &now,
			Version:          s.config.Version,
			X1TransactionId:  transID,
		},
	}
}

func errorRequestType(messageType string) (string, *schema.ExtensionInformation) {
	requestTypes := map[string]string{
		MessageTypeCreateDestination: RequestTypeCreateDestination,
		MessageTypeModifyDestination: RequestTypeModifyDestination,
		MessageTypeRemoveDestination: RequestTypeRemoveDestination,
		MessageTypeActivateTask:      RequestTypeActivateTask,
		MessageTypeDeactivateTask:    RequestTypeDeactivateTask,
		MessageTypeModifyTask:        RequestTypeModifyTask,
		MessageTypeGetTaskDetails:    RequestTypeGetTaskDetails,
		MessageTypePing:              RequestTypePing,
		RequestTypeCreateDestination: RequestTypeCreateDestination,
		RequestTypeModifyDestination: RequestTypeModifyDestination,
		RequestTypeRemoveDestination: RequestTypeRemoveDestination,
		RequestTypeActivateTask:      RequestTypeActivateTask,
		RequestTypeDeactivateTask:    RequestTypeDeactivateTask,
		RequestTypeModifyTask:        RequestTypeModifyTask,
		RequestTypeGetTaskDetails:    RequestTypeGetTaskDetails,
		RequestTypePing:              RequestTypePing,
	}
	if requestType, ok := requestTypes[messageType]; ok {
		return requestType, nil
	}
	return RequestTypeExtended, &schema.ExtensionInformation{
		ExtensionSpecification:     "TS133128",
		ExtendedRequestMessageType: messageType,
	}
}

// sendErrorResponse sends a top-level error response.
func (s *Server) sendErrorResponse(w http.ResponseWriter, admfID string, errorCode int, errorDesc string) {
	logger.Warn("X1 top-level error",
		"error_code", errorCode,
		"error_desc", errorDesc,
	)

	now := formatQualifiedMicrosecondDateTime(time.Now())
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
