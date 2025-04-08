package cmd

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var interfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List all network interfaces",
	Long:  `List all network interfaces that lippycat can monitor`,
	Run: func(cmd *cobra.Command, args []string) {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Available network interfaces:")
		for _, device := range devices {
			fmt.Println("- ", device.Name, device.Addresses)
			// fmt.Println("- ", device.Name, device.Description, device.Addresses)
		}
	},
}

func init() {
	rootCmd.AddCommand(interfacesCmd)
}
