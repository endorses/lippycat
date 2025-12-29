//go:build li

package x1

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Default client configuration values.
const (
	// DefaultKeepaliveInterval is the default interval for sending keepalive messages.
	DefaultKeepaliveInterval = 30 * time.Second

	// DefaultRequestTimeout is the default timeout for HTTP requests to ADMF.
	DefaultRequestTimeout = 10 * time.Second

	// DefaultInitialBackoff is the initial backoff duration for retries.
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the maximum backoff duration for retries.
	DefaultMaxBackoff = 5 * time.Minute

	// DefaultBackoffMultiplier is the multiplier for exponential backoff.
	DefaultBackoffMultiplier = 2.0

	// DefaultMaxRetries is the default maximum number of retries for notifications.
	DefaultMaxRetries = 3
)

// TaskReportType constants per ETSI TS 103 221-1.
const (
	// TaskReportTypeError indicates an error report.
	TaskReportTypeError = "Error"

	// TaskReportTypeTaskProgress indicates task progress.
	TaskReportTypeTaskProgress = "TaskProgress"

	// TaskReportTypeActivationAcknowledgement indicates activation acknowledgement.
	TaskReportTypeActivationAcknowledgement = "ActivationAcknowledgement"

	// TaskReportTypeDeactivationAcknowledgement indicates deactivation acknowledgement.
	TaskReportTypeDeactivationAcknowledgement = "DeactivationAcknowledgement"

	// TaskReportTypeImplicitDeactivation indicates implicit deactivation.
	TaskReportTypeImplicitDeactivation = "ImplicitDeactivation"
)

// DestinationReportType constants per ETSI TS 103 221-1.
const (
	// DestinationReportTypeDeliveryError indicates a delivery error.
	DestinationReportTypeDeliveryError = "DeliveryError"

	// DestinationReportTypeDeliveryRecovered indicates delivery has recovered.
	DestinationReportTypeDeliveryRecovered = "DeliveryRecovered"

	// DestinationReportTypeConnectionLost indicates connection was lost.
	DestinationReportTypeConnectionLost = "ConnectionLost"

	// DestinationReportTypeConnectionEstablished indicates connection was established.
	DestinationReportTypeConnectionEstablished = "ConnectionEstablished"
)

// NEIssueType constants per ETSI TS 103 221-1.
const (
	// NEIssueTypeStartup indicates NE startup.
	NEIssueTypeStartup = "Startup"

	// NEIssueTypeShutdown indicates NE shutdown.
	NEIssueTypeShutdown = "Shutdown"

	// NEIssueTypeWarning indicates a warning condition.
	NEIssueTypeWarning = "Warning"

	// NEIssueTypeError indicates an error condition.
	NEIssueTypeError = "Error"
)

// Errors returned by the client.
var (
	// ErrClientStopped indicates the client has been stopped.
	ErrClientStopped = errors.New("X1 client stopped")

	// ErrNoADMFEndpoint indicates no ADMF endpoint is configured.
	ErrNoADMFEndpoint = errors.New("no ADMF endpoint configured")

	// ErrRequestFailed indicates an HTTP request to ADMF failed.
	ErrRequestFailed = errors.New("ADMF request failed")
)

// ClientConfig holds configuration for the X1 client.
type ClientConfig struct {
	// ADMFEndpoint is the HTTPS URL of the ADMF (e.g., "https://admf.example.com:8443").
	ADMFEndpoint string

	// NEIdentifier is the network element identifier for X1 messages.
	NEIdentifier string

	// Version is the X1 protocol version (default: "v1.13.1").
	Version string

	// TLSCertFile is the path to the client TLS certificate for mutual TLS.
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate for ADMF server verification.
	TLSCAFile string

	// KeepaliveInterval is the interval for sending keepalive messages.
	// Set to 0 to disable keepalive.
	KeepaliveInterval time.Duration

	// RequestTimeout is the timeout for HTTP requests to ADMF.
	RequestTimeout time.Duration

	// InitialBackoff is the initial backoff duration for retries.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration for retries.
	MaxBackoff time.Duration

	// BackoffMultiplier is the multiplier for exponential backoff.
	BackoffMultiplier float64

	// MaxRetries is the maximum number of retries for notifications.
	MaxRetries int
}

// DefaultClientConfig returns a ClientConfig with default values.
func DefaultClientConfig() ClientConfig {
	hostname, _ := os.Hostname()
	return ClientConfig{
		NEIdentifier:      hostname,
		Version:           "v1.13.1",
		KeepaliveInterval: DefaultKeepaliveInterval,
		RequestTimeout:    DefaultRequestTimeout,
		InitialBackoff:    DefaultInitialBackoff,
		MaxBackoff:        DefaultMaxBackoff,
		BackoffMultiplier: DefaultBackoffMultiplier,
		MaxRetries:        DefaultMaxRetries,
	}
}

// ClientStats contains X1 client statistics.
type ClientStats struct {
	// KeepalivesSent is the number of keepalive messages sent.
	KeepalivesSent uint64

	// KeepalivesFailed is the number of failed keepalive attempts.
	KeepalivesFailed uint64

	// TaskReportsSent is the number of task reports sent.
	TaskReportsSent uint64

	// TaskReportsFailed is the number of failed task report attempts.
	TaskReportsFailed uint64

	// DestinationReportsSent is the number of destination reports sent.
	DestinationReportsSent uint64

	// DestinationReportsFailed is the number of failed destination report attempts.
	DestinationReportsFailed uint64

	// NEReportsSent is the number of NE reports sent.
	NEReportsSent uint64

	// NEReportsFailed is the number of failed NE report attempts.
	NEReportsFailed uint64

	// LastKeepalive is the time of the last successful keepalive.
	LastKeepalive time.Time

	// LastError is the most recent error (if any).
	LastError string
}

// Client sends X1 notifications to the ADMF.
//
// The client provides:
//   - Keepalive heartbeat messages
//   - Task issue reports (errors, progress)
//   - Destination issue reports (delivery errors)
//   - NE issue reports (startup, shutdown, warnings)
//   - Automatic retry with exponential backoff
type Client struct {
	config ClientConfig

	// httpClient is the HTTP client for ADMF communication.
	httpClient *http.Client

	// mu protects stats.
	mu sync.RWMutex

	// stats holds client statistics.
	stats ClientStats

	// stopChan signals shutdown.
	stopChan chan struct{}

	// wg tracks background goroutines.
	wg sync.WaitGroup

	// stopped indicates the client has been stopped.
	stopped atomic.Bool
}

// NewClient creates a new X1 client.
func NewClient(config ClientConfig) (*Client, error) {
	if config.ADMFEndpoint == "" {
		return nil, ErrNoADMFEndpoint
	}

	// Apply defaults.
	if config.NEIdentifier == "" {
		hostname, _ := os.Hostname()
		config.NEIdentifier = hostname
	}
	if config.Version == "" {
		config.Version = "v1.13.1"
	}
	if config.KeepaliveInterval == 0 {
		config.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = DefaultRequestTimeout
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = DefaultInitialBackoff
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = DefaultMaxBackoff
	}
	if config.BackoffMultiplier == 0 {
		config.BackoffMultiplier = DefaultBackoffMultiplier
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = DefaultMaxRetries
	}

	// Build TLS config.
	tlsConfig, err := buildClientTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	// Create HTTP client with TLS.
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
		stopChan:   make(chan struct{}),
	}, nil
}

// buildClientTLSConfig builds the TLS configuration for ADMF communication.
func buildClientTLSConfig(config ClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Secure cipher suites - TLS 1.3 suites are automatically preferred when available
		CipherSuites: []uint16{
			// TLS 1.2 cipher suites (TLS 1.3 ciphers are handled automatically by Go)
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	// Load client certificate if provided (for mutual TLS).
	if config.TLSCertFile != "" && config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided.
	if config.TLSCAFile != "" {
		caCert, err := os.ReadFile(config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = certPool
	}

	return tlsConfig, nil
}

// Start begins the client's background operations (keepalive).
func (c *Client) Start() {
	if c.config.KeepaliveInterval > 0 {
		c.wg.Add(1)
		go c.keepaliveLoop()
	}

	logger.Info("X1 client started",
		"admf_endpoint", c.config.ADMFEndpoint,
		"keepalive_interval", c.config.KeepaliveInterval,
	)
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	c.stopped.Store(true)
	close(c.stopChan)
	c.wg.Wait()

	c.mu.RLock()
	stats := c.stats
	c.mu.RUnlock()

	logger.Info("X1 client stopped",
		"keepalives_sent", stats.KeepalivesSent,
		"task_reports_sent", stats.TaskReportsSent,
	)
}

// keepaliveLoop sends periodic keepalive messages to ADMF.
func (c *Client) keepaliveLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			if err := c.SendKeepalive(context.Background()); err != nil {
				c.mu.Lock()
				c.stats.KeepalivesFailed++
				c.stats.LastError = err.Error()
				c.mu.Unlock()

				logger.Warn("X1 keepalive failed",
					"error", err,
					"admf", c.config.ADMFEndpoint,
				)
			} else {
				c.mu.Lock()
				c.stats.KeepalivesSent++
				c.stats.LastKeepalive = time.Now()
				c.mu.Unlock()

				logger.Debug("X1 keepalive sent", "admf", c.config.ADMFEndpoint)
			}
		}
	}
}

// SendKeepalive sends a keepalive message to ADMF.
func (c *Client) SendKeepalive(ctx context.Context) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	req := &schema.KeepaliveRequest{
		X1RequestMessage: c.buildRequestMessage(),
	}

	return c.sendRequestWithRetry(ctx, "keepaliveRequest", req)
}

// ReportTaskError sends an error report for a task to ADMF.
func (c *Client) ReportTaskError(ctx context.Context, xid uuid.UUID, errorCode int, details string) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	xidStr := schema.UUID(xid.String())
	req := &schema.ReportTaskIssueRequest{
		XId:                &xidStr,
		TaskReportType:     TaskReportTypeError,
		TaskIssueErrorCode: &errorCode,
		TaskIssueDetails:   &details,
		X1RequestMessage:   c.buildRequestMessage(),
	}

	err := c.sendRequestWithRetry(ctx, "reportTaskIssueRequest", req)
	c.mu.Lock()
	if err != nil {
		c.stats.TaskReportsFailed++
		c.stats.LastError = err.Error()
	} else {
		c.stats.TaskReportsSent++
	}
	c.mu.Unlock()

	return err
}

// ReportTaskProgress sends a progress report for a task to ADMF.
func (c *Client) ReportTaskProgress(ctx context.Context, xid uuid.UUID, details string) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	xidStr := schema.UUID(xid.String())
	req := &schema.ReportTaskIssueRequest{
		XId:              &xidStr,
		TaskReportType:   TaskReportTypeTaskProgress,
		TaskIssueDetails: &details,
		X1RequestMessage: c.buildRequestMessage(),
	}

	err := c.sendRequestWithRetry(ctx, "reportTaskIssueRequest", req)
	c.mu.Lock()
	if err != nil {
		c.stats.TaskReportsFailed++
		c.stats.LastError = err.Error()
	} else {
		c.stats.TaskReportsSent++
	}
	c.mu.Unlock()

	return err
}

// ReportTaskImplicitDeactivation sends an implicit deactivation report for a task to ADMF.
// This is sent when the NE autonomously deactivates a task (e.g., EndTime reached).
func (c *Client) ReportTaskImplicitDeactivation(ctx context.Context, xid uuid.UUID, reason string) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	xidStr := schema.UUID(xid.String())
	req := &schema.ReportTaskIssueRequest{
		XId:              &xidStr,
		TaskReportType:   TaskReportTypeImplicitDeactivation,
		TaskIssueDetails: &reason,
		X1RequestMessage: c.buildRequestMessage(),
	}

	err := c.sendRequestWithRetry(ctx, "reportTaskIssueRequest", req)
	c.mu.Lock()
	if err != nil {
		c.stats.TaskReportsFailed++
		c.stats.LastError = err.Error()
	} else {
		c.stats.TaskReportsSent++
	}
	c.mu.Unlock()

	if err != nil {
		logger.Error("X1 implicit deactivation report failed",
			"xid", xid,
			"error", err,
		)
	} else {
		logger.Info("X1 implicit deactivation reported",
			"xid", xid,
			"reason", reason,
		)
	}

	return err
}

// ReportDestinationIssue sends a destination issue report to ADMF.
// Used for X2/X3 delivery errors and recovery notifications.
func (c *Client) ReportDestinationIssue(ctx context.Context, did uuid.UUID, reportType string, errorCode *int, details string) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	didStr := schema.UUID(did.String())
	req := &schema.ReportDestinationIssueRequest{
		DId:                       &didStr,
		DestinationReportType:     reportType,
		DestinationIssueErrorCode: errorCode,
		DestinationIssueDetails:   &details,
		X1RequestMessage:          c.buildRequestMessage(),
	}

	err := c.sendRequestWithRetry(ctx, "reportDestinationIssueRequest", req)
	c.mu.Lock()
	if err != nil {
		c.stats.DestinationReportsFailed++
		c.stats.LastError = err.Error()
	} else {
		c.stats.DestinationReportsSent++
	}
	c.mu.Unlock()

	return err
}

// ReportDeliveryError sends a delivery error report for a destination.
func (c *Client) ReportDeliveryError(ctx context.Context, did uuid.UUID, errorCode int, details string) error {
	return c.ReportDestinationIssue(ctx, did, DestinationReportTypeDeliveryError, &errorCode, details)
}

// ReportDeliveryRecovered sends a delivery recovered notification for a destination.
func (c *Client) ReportDeliveryRecovered(ctx context.Context, did uuid.UUID) error {
	return c.ReportDestinationIssue(ctx, did, DestinationReportTypeDeliveryRecovered, nil, "Delivery recovered")
}

// ReportConnectionLost sends a connection lost report for a destination.
func (c *Client) ReportConnectionLost(ctx context.Context, did uuid.UUID, details string) error {
	return c.ReportDestinationIssue(ctx, did, DestinationReportTypeConnectionLost, nil, details)
}

// ReportConnectionEstablished sends a connection established notification for a destination.
func (c *Client) ReportConnectionEstablished(ctx context.Context, did uuid.UUID) error {
	return c.ReportDestinationIssue(ctx, did, DestinationReportTypeConnectionEstablished, nil, "Connection established")
}

// ReportNEIssue sends an NE issue report to ADMF.
// Used for startup, shutdown, warnings, and errors at the NE level.
func (c *Client) ReportNEIssue(ctx context.Context, issueType string, description string, issueCode *int) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}

	req := &schema.ReportNEIssueRequest{
		TypeOfNeIssueMessage: issueType,
		Description:          description,
		IssueCode:            issueCode,
		X1RequestMessage:     c.buildRequestMessage(),
	}

	err := c.sendRequestWithRetry(ctx, "reportNEIssueRequest", req)
	c.mu.Lock()
	if err != nil {
		c.stats.NEReportsFailed++
		c.stats.LastError = err.Error()
	} else {
		c.stats.NEReportsSent++
	}
	c.mu.Unlock()

	return err
}

// ReportStartup sends a startup notification to ADMF.
func (c *Client) ReportStartup(ctx context.Context) error {
	return c.ReportNEIssue(ctx, NEIssueTypeStartup, "Network element started", nil)
}

// ReportShutdown sends a shutdown notification to ADMF.
func (c *Client) ReportShutdown(ctx context.Context) error {
	return c.ReportNEIssue(ctx, NEIssueTypeShutdown, "Network element shutting down", nil)
}

// ReportWarning sends a warning notification to ADMF.
func (c *Client) ReportWarning(ctx context.Context, warningCode int, description string) error {
	return c.ReportNEIssue(ctx, NEIssueTypeWarning, description, &warningCode)
}

// ReportError sends an error notification to ADMF.
func (c *Client) ReportError(ctx context.Context, errorCode int, description string) error {
	return c.ReportNEIssue(ctx, NEIssueTypeError, description, &errorCode)
}

// buildRequestMessage creates the base X1 request message.
func (c *Client) buildRequestMessage() *schema.X1RequestMessage {
	now := schema.QualifiedMicrosecondDateTime(time.Now().Format(time.RFC3339Nano))
	transID := schema.UUID(uuid.New().String())

	return &schema.X1RequestMessage{
		NeIdentifier:     c.config.NEIdentifier,
		MessageTimestamp: &now,
		Version:          c.config.Version,
		X1TransactionId:  &transID,
	}
}

// sendRequestWithRetry sends an X1 request with exponential backoff retry.
func (c *Client) sendRequestWithRetry(ctx context.Context, rootElement string, req any) error {
	backoff := c.config.InitialBackoff
	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.stopChan:
				return ErrClientStopped
			case <-time.After(backoff):
			}

			// Increase backoff for next attempt.
			backoff = time.Duration(float64(backoff) * c.config.BackoffMultiplier)
			if backoff > c.config.MaxBackoff {
				backoff = c.config.MaxBackoff
			}
		}

		err := c.sendRequest(ctx, rootElement, req)
		if err == nil {
			return nil
		}

		lastErr = err
		logger.Debug("X1 request failed, will retry",
			"attempt", attempt+1,
			"max_retries", c.config.MaxRetries,
			"error", err,
			"backoff", backoff,
		)
	}

	return fmt.Errorf("%w: after %d retries: %v", ErrRequestFailed, c.config.MaxRetries, lastErr)
}

// sendRequest sends a single X1 request to ADMF.
func (c *Client) sendRequest(ctx context.Context, rootElement string, req any) error {
	// Marshal the request to XML.
	body, err := xml.MarshalIndent(req, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add XML header.
	xmlData := []byte(xml.Header + string(body))

	// Create HTTP request.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.ADMFEndpoint, bytes.NewReader(xmlData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", contentTypeXML)
	httpReq.Header.Set("Accept", contentTypeXML)

	// Send request.
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check HTTP status.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to check for X1 errors.
	// For now, we accept any 2xx response as success.
	// A more complete implementation would parse the X1 response and check for error codes.
	logger.Debug("X1 response received",
		"status", resp.StatusCode,
		"body_length", len(respBody),
	)

	return nil
}

// Stats returns current client statistics.
func (c *Client) Stats() ClientStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// IsConnected returns whether the client can reach ADMF.
// This is a simple check based on recent keepalive success.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.stats.LastKeepalive.IsZero() {
		return false
	}

	// Consider connected if last keepalive was within 2x the interval.
	threshold := 2 * c.config.KeepaliveInterval
	return time.Since(c.stats.LastKeepalive) < threshold
}

// Config returns the client configuration.
func (c *Client) Config() ClientConfig {
	return c.config
}
