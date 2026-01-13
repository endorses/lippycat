//go:build cli || all

package filter

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/spf13/cobra"
)

var (
	setFilterID          string
	setFilterType        string
	setFilterPattern     string
	setFilterDescription string
	setFilterEnabled     bool
	setFilterHunters     []string
	setFilterFile        string
)

// SetFilterResult represents the result of a set operation
type SetFilterResult struct {
	ID             string   `json:"id"`
	Success        bool     `json:"success"`
	HuntersUpdated []string `json:"hunters_updated,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// SetBatchResult represents the result of a batch set operation
type SetBatchResult struct {
	Succeeded           []string          `json:"succeeded"`
	Failed              []SetFilterResult `json:"failed,omitempty"`
	TotalHuntersUpdated uint32            `json:"total_hunters_updated"`
}

// SetFilterCmd creates or updates a filter on a processor
var SetFilterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Create or update a filter",
	Long: `Create or update a filter on a remote processor (upsert).

The command can operate in two modes:
1. Inline mode: Specify filter properties via flags
2. File mode: Read filters from a YAML file (batch operation)

If --id is not provided, a UUID will be auto-generated.

Filter types:
  VoIP:
    sip_user      - Match SIP user/extension (glob patterns)
    sip_uri       - Match SIP URI (glob patterns)
    phone_number  - Match phone number (prefix/suffix wildcards)
    call_id       - Match SIP Call-ID
    codec         - Match RTP codec

  DNS:
    dns_domain    - Match DNS domain name (glob patterns: *.example.com)

  Email:
    email_address - Match email sender/recipient (glob patterns)
    email_subject - Match email subject line (glob patterns)

  TLS:
    tls_sni       - Match TLS SNI hostname (glob patterns)
    tls_ja3       - Match JA3 client fingerprint (32-char hex MD5)
    tls_ja3s      - Match JA3S server fingerprint (32-char hex MD5)
    tls_ja4       - Match JA4 fingerprint (e.g., t13d1516h2_8daaf6152771_b186095e22bb)

  HTTP:
    http_host     - Match HTTP Host header (glob patterns)
    http_url      - Match HTTP URL path (glob patterns)

  Universal:
    ip_address    - Match IP address or CIDR
    bpf           - Raw BPF filter expression

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Create a SIP user filter (TLS with CA verification)
  lc set filter -P processor.example.com:50051 --tls-ca ca.crt \
    --type sip_user --pattern alice@example.com

  # Create a DNS domain filter with wildcard
  lc set filter -P processor.example.com:50051 --tls-ca ca.crt \
    --type dns_domain --pattern "*.malware-domain.com"

  # Create a TLS JA3 fingerprint filter
  lc set filter -P processor.example.com:50051 --tls-ca ca.crt \
    --type tls_ja3 --pattern e7d705a3286e19ea42f587b344ee6865

  # Local testing without TLS
  lc set filter -P localhost:50051 --insecure \
    --type sip_user --pattern alice@example.com

  # Import filters from a file (batch)
  lc set filter -P processor.example.com:50051 --tls-ca ca.crt -f filters.yaml`,
	Run: runSetFilter,
}

func init() {
	AddConnectionFlags(SetFilterCmd)
	SetFilterCmd.Flags().StringVar(&setFilterID, "id", "", "Filter ID (auto-generated if not provided)")
	SetFilterCmd.Flags().StringVarP(&setFilterType, "type", "t", "", "Filter type (see --help for full list)")
	SetFilterCmd.Flags().StringVar(&setFilterPattern, "pattern", "", "Filter pattern")
	SetFilterCmd.Flags().StringVar(&setFilterDescription, "description", "", "Filter description")
	SetFilterCmd.Flags().BoolVar(&setFilterEnabled, "enabled", true, "Enable the filter")
	SetFilterCmd.Flags().StringSliceVar(&setFilterHunters, "hunters", nil, "Target hunter IDs (comma-separated)")
	SetFilterCmd.Flags().StringVarP(&setFilterFile, "file", "f", "", "YAML file containing filters (batch mode)")
}

func runSetFilter(cmd *cobra.Command, args []string) {
	// Determine mode: file or inline
	if setFilterFile != "" {
		runSetFilterBatch(cmd)
		return
	}

	// Inline mode - validate required flags
	if setFilterType == "" {
		OutputError(fmt.Errorf("filter type is required (use --type)"), ExitValidationError)
		return
	}
	if setFilterPattern == "" {
		OutputError(fmt.Errorf("filter pattern is required (use --pattern)"), ExitValidationError)
		return
	}

	// Parse filter type
	filterType, err := filtering.ParseFilterType(setFilterType)
	if err != nil {
		OutputError(err, ExitValidationError)
		return
	}

	// Validate pattern for the filter type
	if err := filtering.ValidatePattern(filterType, setFilterPattern); err != nil {
		OutputError(err, ExitValidationError)
		return
	}

	// Generate ID if not provided
	filterID := setFilterID
	if filterID == "" {
		filterID = uuid.New().String()
	}

	// Build filter proto
	filter := &management.Filter{
		Id:            filterID,
		Type:          filterType,
		Pattern:       setFilterPattern,
		Description:   setFilterDescription,
		Enabled:       setFilterEnabled,
		TargetHunters: setFilterHunters,
	}

	// Connect and set
	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	result, err := client.Set(filter)
	if err != nil {
		OutputError(err, MapGRPCError(err))
		return
	}

	// Build response
	resp := SetFilterResult{
		ID:      filterID,
		Success: result.Success,
	}
	if !result.Success {
		resp.Error = result.Error
	}
	if result.HuntersUpdated > 0 {
		// We don't have hunter names here, just the count
		resp.HuntersUpdated = make([]string, result.HuntersUpdated)
		for i := uint32(0); i < result.HuntersUpdated; i++ {
			resp.HuntersUpdated[i] = fmt.Sprintf("hunter-%d", i+1)
		}
	}

	if err := OutputJSON(resp); err != nil {
		OutputError(err, ExitGeneralError)
		return
	}
}

func runSetFilterBatch(cmd *cobra.Command) {
	// Parse filters from file
	filters, parseErrors, err := filtering.ParseFileWithErrors(setFilterFile)
	if err != nil {
		OutputError(err, ExitValidationError)
		return
	}

	// Convert to slice for batch operation
	filterSlice := make([]*management.Filter, 0, len(filters))
	for _, f := range filters {
		filterSlice = append(filterSlice, f)
	}

	// Connect to processor
	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	// Perform batch set
	batchResult, err := client.SetBatch(filterSlice)
	if err != nil {
		OutputError(err, MapGRPCError(err))
		return
	}

	// Build response including parse errors
	resp := SetBatchResult{
		Succeeded:           batchResult.Succeeded,
		TotalHuntersUpdated: batchResult.TotalHuntersUpdated,
	}

	// Add parse errors as failed items
	for _, parseErr := range parseErrors {
		resp.Failed = append(resp.Failed, SetFilterResult{
			ID:    extractFilterIDFromError(parseErr.Error()),
			Error: parseErr.Error(),
		})
	}

	// Add batch operation failures
	for _, batchErr := range batchResult.Failed {
		resp.Failed = append(resp.Failed, SetFilterResult{
			ID:    batchErr.ID,
			Error: batchErr.Error,
		})
	}

	// Output as JSON
	data, err := output.MarshalJSON(resp)
	if err != nil {
		OutputError(err, ExitGeneralError)
		return
	}
	cmd.Println(string(data))
}

// extractFilterIDFromError extracts a filter ID from an error message if present
func extractFilterIDFromError(errMsg string) string {
	// Error format is typically "filter \"id\": ..."
	if strings.HasPrefix(errMsg, "filter \"") {
		end := strings.Index(errMsg[8:], "\"")
		if end > 0 {
			return errMsg[8 : 8+end]
		}
	}
	return "(unknown)"
}
