//go:build tui || all
// +build tui all

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// NodeConfig represents a single remote node configuration
type NodeConfig struct {
	Name    string `yaml:"name"`    // Friendly name for the node
	Address string `yaml:"address"` // host:port

	// TLS settings (optional - uses global config if not specified)
	TLS *TLSConfig `yaml:"tls,omitempty"`

	// Hunter subscription filter (optional - subscribe to all if not specified)
	SubscribedHunters []string `yaml:"subscribed_hunters,omitempty"`
}

// TLSConfig holds TLS settings for a node connection
type TLSConfig struct {
	Enabled            bool   `yaml:"enabled"`               // Enable TLS
	CAFile             string `yaml:"ca_file,omitempty"`     // CA certificate file
	CertFile           string `yaml:"cert_file,omitempty"`   // Client certificate file (for mTLS)
	KeyFile            string `yaml:"key_file,omitempty"`    // Client key file (for mTLS)
	SkipVerify         bool   `yaml:"skip_verify,omitempty"` // Skip cert verification (insecure)
	ServerNameOverride string `yaml:"server_name_override,omitempty"`
}

// NodesConfig represents the YAML configuration for hunters and processors
type NodesConfig struct {
	Hunters    []NodeConfig `yaml:"hunters,omitempty"`
	Processors []NodeConfig `yaml:"processors,omitempty"`
}

// LoadNodesFromYAML loads node configurations from a YAML file
func LoadNodesFromYAML(path string) ([]NodeConfig, error) {
	// Expand tilde to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var config NodesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Combine hunters and processors into a single list
	var allNodes []NodeConfig
	allNodes = append(allNodes, config.Hunters...)
	allNodes = append(allNodes, config.Processors...)

	return allNodes, nil
}

// SaveNodesToYAML saves node configurations to a YAML file
// Note: This is a simplified version that saves all nodes as hunters
// In the future, could be enhanced to separate by detected node type
func SaveNodesToYAML(path string, nodes []NodeConfig) error {
	// Expand tilde to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	config := NodesConfig{Hunters: nodes}

	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
