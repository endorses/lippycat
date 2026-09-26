//go:build (all || cli || processor || tap) && !li

package migrate

import "github.com/spf13/cobra"

func addLICommands(*cobra.Command) {}
