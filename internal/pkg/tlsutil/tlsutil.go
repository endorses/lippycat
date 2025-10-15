// Package tlsutil provides shared TLS credential building utilities for gRPC services.
// This package consolidates TLS configuration logic used across processor, hunter, and TUI components.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc/credentials"
)

// ServerConfig contains configuration for building server TLS credentials
type ServerConfig struct {
	CertFile   string // Path to server certificate
	KeyFile    string // Path to server private key
	CAFile     string // Path to CA certificate (for client authentication)
	ClientAuth bool   // Require client certificate authentication (mutual TLS)
}

// ClientConfig contains configuration for building client TLS credentials
type ClientConfig struct {
	CAFile             string // Path to CA certificate (for server verification)
	CertFile           string // Path to client certificate (for mutual TLS)
	KeyFile            string // Path to client private key (for mutual TLS)
	SkipVerify         bool   // Skip certificate verification (INSECURE - testing only)
	ServerNameOverride string // Override server name for verification
	UseSystemCertPool  bool   // Use system certificate pool as fallback
}

// BuildServerCredentials creates TLS credentials for a gRPC server
// Supports optional mutual TLS (mTLS) with client certificate verification
func BuildServerCredentials(config ServerConfig) (credentials.TransportCredentials, error) {
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("TLS enabled but certificate or key file not specified")
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure client certificate authentication if enabled
	if config.ClientAuth {
		if config.CAFile == "" {
			return nil, fmt.Errorf("client auth enabled but CA file not specified")
		}

		// Load CA certificate for verifying client certificates
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		logger.Info("Mutual TLS enabled - requiring client certificates",
			"ca_file", config.CAFile)
	}

	logger.Info("TLS server credentials loaded",
		"cert", config.CertFile,
		"key", config.KeyFile,
		"min_version", "TLS 1.3",
		"client_auth", config.ClientAuth)

	return credentials.NewTLS(tlsConfig), nil
}

// BuildClientCredentials creates TLS credentials for a gRPC client
// Supports optional mutual TLS (mTLS) with client certificate authentication
func BuildClientCredentials(config ClientConfig) (credentials.TransportCredentials, error) {
	// Check for production mode (via environment variable)
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"

	// #nosec G402 -- InsecureSkipVerify is user-configurable, documented as testing-only
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipVerify,
		ServerName:         config.ServerNameOverride,
		MinVersion:         tls.VersionTLS13,
	}

	// Validate production mode security requirements
	if config.SkipVerify {
		logger.Warn("TLS certificate verification disabled",
			"security_risk", "vulnerable to man-in-the-middle attacks",
			"recommendation", "only use in testing environments",
			"severity", "HIGH")

		if productionMode {
			return nil, fmt.Errorf("LIPPYCAT_PRODUCTION=true blocks TLSSkipVerify=true (insecure certificate validation)")
		}
	}

	// Load CA certificate if provided
	var certPool *x509.CertPool
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		logger.Info("Loaded CA certificate", "file", config.CAFile)
	} else if config.UseSystemCertPool {
		// Use system certificate pool as fallback
		var err error
		certPool, err = x509.SystemCertPool()
		if err != nil {
			logger.Warn("Failed to load system cert pool, using empty pool", "error", err)
			certPool = x509.NewCertPool()
		} else {
			logger.Info("Using system certificate pool")
		}
	}

	if certPool != nil {
		tlsConfig.RootCAs = certPool
	}

	// Load client certificate for mutual TLS if provided
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		logger.Info("Loaded client certificate for mutual TLS",
			"cert", config.CertFile,
			"key", config.KeyFile)
	} else if config.CertFile != "" || config.KeyFile != "" {
		// Only one of cert/key provided - this is an error
		return nil, fmt.Errorf("both cert_file and key_file must be provided for mutual TLS")
	}

	logger.Info("TLS client credentials configured",
		"has_ca", config.CAFile != "",
		"has_client_cert", config.CertFile != "",
		"skip_verify", config.SkipVerify,
		"server_name_override", config.ServerNameOverride)

	return credentials.NewTLS(tlsConfig), nil
}
