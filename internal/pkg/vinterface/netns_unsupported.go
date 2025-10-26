//go:build !linux

package vinterface

import "github.com/vishvananda/netlink"

// NamespaceExists always returns false on unsupported platforms.
func NamespaceExists(name string) bool {
	return false
}

// CreateNamespace returns an error on unsupported platforms.
func CreateNamespace(name string) error {
	return ErrPlatformUnsupported
}

// DeleteNamespace returns an error on unsupported platforms.
func DeleteNamespace(name string) error {
	return ErrPlatformUnsupported
}

// ListNamespaces returns an error on unsupported platforms.
func ListNamespaces() ([]string, error) {
	return nil, ErrPlatformUnsupported
}

// GetInterfacesInNamespace returns an error on unsupported platforms.
func GetInterfacesInNamespace(nsName string) ([]netlink.Link, error) {
	return nil, ErrPlatformUnsupported
}
