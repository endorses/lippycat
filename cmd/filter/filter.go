//go:build cli || all
// +build cli all

// Package filter provides CLI commands for remote filter management.
// Commands use the filterclient package to communicate with processors via gRPC.
package filter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/filterclient"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Exit codes for CLI commands
const (
	ExitSuccess         = 0
	ExitGeneralError    = 1
	ExitConnectionError = 2
	ExitValidationError = 3
	ExitNotFoundError   = 4
)

// Common flags used across filter commands
var (
	processorAddr string
	tlsEnabled    bool
	tlsCAFile     string
	tlsCertFile   string
	tlsKeyFile    string
	tlsSkipVerify bool
)

// AddConnectionFlags adds common gRPC connection flags to a command
func AddConnectionFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&processorAddr, "processor", "P", "", "Processor address (host:port)")
	cmd.Flags().BoolVarP(&tlsEnabled, "tls", "T", false, "Enable TLS encryption")
	cmd.Flags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate file")
	cmd.Flags().StringVar(&tlsCertFile, "tls-cert", "", "Path to client certificate file (mTLS)")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-key", "", "Path to client key file (mTLS)")
	cmd.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (insecure)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("remote.processor", cmd.Flags().Lookup("processor"))
	_ = viper.BindPFlag("remote.tls.enabled", cmd.Flags().Lookup("tls"))
	_ = viper.BindPFlag("remote.tls.ca", cmd.Flags().Lookup("tls-ca"))
	_ = viper.BindPFlag("remote.tls.cert", cmd.Flags().Lookup("tls-cert"))
	_ = viper.BindPFlag("remote.tls.key", cmd.Flags().Lookup("tls-key"))
	_ = viper.BindPFlag("remote.tls.skip_verify", cmd.Flags().Lookup("tls-skip-verify"))
}

// GetClientConfig builds a ClientConfig from flags and viper settings
func GetClientConfig() filterclient.ClientConfig {
	addr := processorAddr
	if addr == "" {
		addr = viper.GetString("remote.processor")
	}

	tls := tlsEnabled
	if !tls {
		tls = viper.GetBool("remote.tls.enabled")
	}

	ca := tlsCAFile
	if ca == "" {
		ca = viper.GetString("remote.tls.ca")
	}

	cert := tlsCertFile
	if cert == "" {
		cert = viper.GetString("remote.tls.cert")
	}

	key := tlsKeyFile
	if key == "" {
		key = viper.GetString("remote.tls.key")
	}

	skip := tlsSkipVerify
	if !skip {
		skip = viper.GetBool("remote.tls.skip_verify")
	}

	return filterclient.ClientConfig{
		Address:       addr,
		TLSEnabled:    tls,
		TLSCAFile:     ca,
		TLSCertFile:   cert,
		TLSKeyFile:    key,
		TLSSkipVerify: skip,
	}
}

// NewClient creates a new filter client using the current configuration
func NewClient() (*filterclient.FilterClient, error) {
	config := GetClientConfig()
	if config.Address == "" {
		return nil, fmt.Errorf("processor address is required (use --processor or set remote.processor in config)")
	}
	return filterclient.NewFilterClient(config)
}

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// OutputError writes an error response to stderr in JSON format and exits
func OutputError(err error, exitCode int) {
	resp := ErrorResponse{
		Error: err.Error(),
		Code:  mapExitCodeToString(exitCode),
	}

	// Try to extract gRPC status code
	if st, ok := status.FromError(err); ok {
		resp.Code = st.Code().String()
		resp.Error = st.Message()
	}

	data, _ := json.Marshal(resp)
	fmt.Fprintln(os.Stderr, string(data))
	os.Exit(exitCode)
}

// OutputJSON writes a value to stdout as JSON
func OutputJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// MapGRPCError maps a gRPC error to an appropriate exit code
func MapGRPCError(err error) int {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return ExitConnectionError
		case codes.InvalidArgument, codes.FailedPrecondition:
			return ExitValidationError
		case codes.NotFound:
			return ExitNotFoundError
		}
	}
	return ExitGeneralError
}

func mapExitCodeToString(code int) string {
	switch code {
	case ExitSuccess:
		return "OK"
	case ExitConnectionError:
		return "UNAVAILABLE"
	case ExitValidationError:
		return "INVALID_ARGUMENT"
	case ExitNotFoundError:
		return "NOT_FOUND"
	default:
		return "UNKNOWN"
	}
}
