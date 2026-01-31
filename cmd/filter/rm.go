//go:build cli || all

package filter

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/spf13/cobra"
)

var (
	rmFilterID   string
	rmFilterFile string
)

// RmFilterResult represents the result of a delete operation
type RmFilterResult struct {
	ID             string `json:"id"`
	Success        bool   `json:"success"`
	HuntersUpdated uint32 `json:"hunters_updated,omitempty"`
	Error          string `json:"error,omitempty"`
}

// RmBatchResult represents the result of a batch delete operation
type RmBatchResult struct {
	Succeeded           []string         `json:"succeeded"`
	Failed              []RmFilterResult `json:"failed,omitempty"`
	TotalHuntersUpdated uint32           `json:"total_hunters_updated"`
}

// RmFilterCmd removes a filter from a processor
var RmFilterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Remove a filter",
	Long: `Remove a filter from a remote processor.

The command can operate in two modes:
1. Single mode: Delete one filter by ID
2. File mode: Delete multiple filters from a file of IDs (one per line)

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Delete a single filter (TLS with CA verification)
  lc rm filter --id myfilter -P processor.example.com:55555 --tls-ca ca.crt

  # Delete multiple filters from a file
  lc rm filter -f filter-ids.txt -P processor.example.com:55555 --tls-ca ca.crt

  # Local testing without TLS
  lc rm filter --id myfilter -P localhost:55555 --insecure`,
	Run: runRmFilter,
}

func init() {
	AddConnectionFlags(RmFilterCmd)
	RmFilterCmd.Flags().StringVar(&rmFilterID, "id", "", "Filter ID to delete")
	RmFilterCmd.Flags().StringVarP(&rmFilterFile, "file", "f", "", "File containing filter IDs to delete (one per line)")
}

func runRmFilter(cmd *cobra.Command, args []string) {
	// Determine mode: file or single
	if rmFilterFile != "" {
		runRmFilterBatch(cmd)
		return
	}

	// Single mode - validate ID
	if rmFilterID == "" {
		OutputError(fmt.Errorf("filter ID is required (use --id)"), ExitValidationError)
		return
	}

	// Connect and delete
	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	result, err := client.Delete(rmFilterID)
	if err != nil {
		OutputError(err, MapGRPCError(err))
		return
	}

	// Build response
	resp := RmFilterResult{
		ID:             rmFilterID,
		Success:        result.Success,
		HuntersUpdated: result.HuntersUpdated,
	}
	if !result.Success {
		resp.Error = result.Error
	}

	if err := OutputJSON(resp); err != nil {
		OutputError(err, ExitGeneralError)
		return
	}
}

func runRmFilterBatch(cmd *cobra.Command) {
	// Read IDs from file
	ids, err := readIDsFromFile(rmFilterFile)
	if err != nil {
		OutputError(err, ExitValidationError)
		return
	}

	if len(ids) == 0 {
		OutputError(fmt.Errorf("no filter IDs found in file"), ExitValidationError)
		return
	}

	// Connect to processor
	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	// Perform batch delete
	batchResult, err := client.DeleteBatch(ids)
	if err != nil {
		OutputError(err, MapGRPCError(err))
		return
	}

	// Build response
	resp := RmBatchResult{
		Succeeded:           batchResult.Succeeded,
		TotalHuntersUpdated: batchResult.TotalHuntersUpdated,
	}

	// Add failures
	for _, batchErr := range batchResult.Failed {
		resp.Failed = append(resp.Failed, RmFilterResult{
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

// readIDsFromFile reads filter IDs from a file, one per line
func readIDsFromFile(path string) ([]string, error) {
	// #nosec G304 -- Path is from CLI flag, not user input
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ID file: %w", err)
	}
	defer file.Close()

	var ids []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids = append(ids, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read ID file: %w", err)
	}

	return ids, nil
}
