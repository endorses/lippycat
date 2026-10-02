//go:build cli || tui || hunter || all

package list

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// InterfaceInfo adds an optional capture-access check to discovery metadata.
type InterfaceInfo struct {
	capture.CaptureInterface
	CaptureAccess string `json:"capture_access,omitempty"`
	CaptureError  string `json:"capture_error,omitempty"`
}

// InterfacesOutput is shared by the human-readable and JSON renderers.
type InterfacesOutput struct {
	Interfaces  []InterfaceInfo `json:"interfaces"`
	HiddenCount int             `json:"hidden_count"`
	Warnings    []string        `json:"warnings,omitempty"`
}

var interfacesCmd = newInterfacesCommand(capture.DiscoverInterfaces, checkInterfaceCapture)

func newInterfacesCommand(discover func() (capture.InterfaceDiscovery, error), check func(string) error) *cobra.Command {
	var asJSON, names, all, checkAccess bool
	cmd := &cobra.Command{
		Use:   "interfaces",
		Short: "List network interfaces available for capture",
		Long: `List capture interfaces with their type, operational state, and IP addresses.
Use --all to include bridges, virtual interfaces, and special capture sources.
Listing does not test capture permissions; --check opens each displayed network
interface briefly without promiscuous mode and closes it without reading packets.
Special capture sources are not probed.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		discovery, err := discover()
		if err != nil {
			err = fmt.Errorf("unable to list network interfaces: %w", err)
			if asJSON {
				data, marshalErr := output.MarshalJSON(struct {
					Error string `json:"error"`
				}{err.Error()})
				if marshalErr != nil {
					return fmt.Errorf("encode discovery error: %w", marshalErr)
				}
				if _, writeErr := fmt.Fprintln(cmd.ErrOrStderr(), string(data)); writeErr != nil {
					return fmt.Errorf("write discovery error: %w", writeErr)
				}
				cmd.SilenceErrors = true
			}
			return err
		}
		result := InterfacesOutput{Interfaces: make([]InterfaceInfo, 0), Warnings: discovery.Warnings}
		for _, device := range discovery.Interfaces {
			if device.Hidden && !all {
				result.HiddenCount++
				continue
			}
			info := InterfaceInfo{CaptureInterface: device}
			if checkAccess {
				if device.Type == "Special" {
					info.CaptureAccess = "skipped"
				} else if err := check(device.Name); err != nil {
					info.CaptureAccess = "unavailable"
					info.CaptureError = err.Error()
				} else {
					info.CaptureAccess = "available"
				}
			}
			result.Interfaces = append(result.Interfaces, info)
		}
		if asJSON {
			data, err := output.MarshalJSON(result)
			if err != nil {
				return fmt.Errorf("encode interfaces: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return err
		}
		for _, warning := range result.Warnings {
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Warning: "+interfaceCell(warning)); err != nil {
				return err
			}
		}
		if names {
			for _, info := range result.Interfaces {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), info.Name); err != nil {
					return err
				}
			}
			return nil
		}
		return writeInterfacesTable(cmd.OutOrStdout(), result, checkAccess)
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output interface data as JSON")
	cmd.Flags().BoolVar(&names, "names", false, "Output one interface name per line")
	cmd.Flags().BoolVar(&all, "all", false, "Include bridges, virtual interfaces, and special capture sources")
	cmd.Flags().BoolVar(&checkAccess, "check", false, "Test capture access on displayed network interfaces")
	cmd.MarkFlagsMutuallyExclusive("json", "names")
	cmd.MarkFlagsMutuallyExclusive("names", "check")
	return cmd
}

func checkInterfaceCapture(name string) error {
	handle, err := pcap.OpenLive(name, 64, false, 100*time.Millisecond)
	if err != nil {
		return err
	}
	handle.Close()
	return nil
}

func writeInterfacesTable(out io.Writer, result InterfacesOutput, checked bool) error {
	if len(result.Interfaces) == 0 {
		if _, err := fmt.Fprintln(out, "No network capture interfaces found."); err != nil {
			return err
		}
	} else {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		header := "NAME\tTYPE\tSTATE\tADDRESSES\tNOTES"
		if checked {
			header += "\tCAPTURE"
		}
		if _, err := fmt.Fprintln(w, header); err != nil {
			return err
		}
		for _, info := range result.Interfaces {
			addresses := make([]string, 0, len(info.Addresses))
			for _, addr := range info.Addresses {
				value := addr.IP
				if addr.PrefixLen != nil {
					value += "/" + strconv.Itoa(*addr.PrefixLen)
				}
				addresses = append(addresses, value)
			}
			addressLines := interfaceAddressLines(addresses)
			notes := ""
			if info.DefaultRoute {
				notes = "default route"
			}
			if info.Type == "Aggregate" {
				notes = "all network interfaces"
			}
			if info.Type == "Special" {
				notes = info.Description
			}
			if info.CaptureError != "" {
				if notes != "" {
					notes += "; "
				}
				notes += info.CaptureError
			}
			state := info.State
			if info.Type == "Aggregate" || info.Type == "Special" {
				state = "—"
			}
			cells := []string{info.Name, info.Type, state, addressLines[0], notes}
			if checked {
				cells = append(cells, info.CaptureAccess)
			}
			for i := range cells {
				cells[i] = interfaceCell(cells[i])
			}
			if _, err := fmt.Fprintln(w, strings.Join(cells, "\t")); err != nil {
				return err
			}
			for _, line := range addressLines[1:] {
				continuation := []string{"", "", "", interfaceCell(line), ""}
				if checked {
					continuation = append(continuation, "")
				}
				if _, err := fmt.Fprintln(w, strings.Join(continuation, "\t")); err != nil {
					return err
				}
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	if result.HiddenCount > 0 {
		_, err := fmt.Fprintf(out, "\n%d additional capture devices hidden; use --all to show them.\n", result.HiddenCount)
		return err
	}
	return nil
}

// Keep all addresses visible without letting IPv6 aliases stretch the table.
func interfaceAddressLines(addresses []string) []string {
	if len(addresses) == 0 {
		return []string{"—"}
	}
	lines := []string{addresses[0]}
	for _, address := range addresses[1:] {
		last := len(lines) - 1
		if len(lines[last])+2+len(address) <= 48 {
			lines[last] += ", " + address
		} else {
			lines = append(lines, address)
		}
	}
	return lines
}

// Keep OS and libpcap strings from injecting terminal controls or table rows.
func interfaceCell(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
}
