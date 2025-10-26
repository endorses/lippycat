//go:build linux

package vinterface

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// createInterfaceInNamespace creates a virtual interface in the specified network namespace.
// If netnsName is empty, creates in the default namespace.
func (m *linuxManager) createInterfaceInNamespace() error {
	if m.config.NetNS == "" {
		// No namespace specified, create in default namespace
		return m.createInterface()
	}

	logger.Info("Creating virtual interface in network namespace",
		"interface", m.config.Name,
		"namespace", m.config.NetNS)

	// Get handle to the named namespace
	nsHandle, err := netns.GetFromName(m.config.NetNS)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrNetNSNotFound, m.config.NetNS)
		}
		if os.IsPermission(err) {
			return ErrNetNSPermissionDenied
		}
		return fmt.Errorf("failed to get namespace handle: %w", err)
	}
	defer nsHandle.Close()

	// Lock the OS thread to prevent the Go scheduler from switching threads
	// while we're operating in a different namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace to restore later
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current namespace: %w", err)
	}
	defer origNS.Close()
	defer netns.Set(origNS) // Restore original namespace

	// Switch to target namespace
	if err := netns.Set(nsHandle); err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.EPERM || errno == syscall.EACCES {
				return ErrNetNSPermissionDenied
			}
		}
		return fmt.Errorf("failed to switch to namespace: %w", err)
	}

	// Create interface in target namespace
	if err := m.createInterface(); err != nil {
		return err
	}

	logger.Info("Successfully created interface in namespace",
		"interface", m.config.Name,
		"namespace", m.config.NetNS)

	return nil
}

// bringUpInNamespace brings up the virtual interface in the specified namespace.
func (m *linuxManager) bringUpInNamespace() error {
	if m.config.NetNS == "" {
		// No namespace specified, use default
		return m.bringUp()
	}

	// Get handle to the named namespace
	nsHandle, err := netns.GetFromName(m.config.NetNS)
	if err != nil {
		return fmt.Errorf("failed to get namespace handle: %w", err)
	}
	defer nsHandle.Close()

	// Lock the OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace to restore later
	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current namespace: %w", err)
	}
	defer origNS.Close()
	defer netns.Set(origNS)

	// Switch to target namespace
	if err := netns.Set(nsHandle); err != nil {
		return fmt.Errorf("failed to switch to namespace: %w", err)
	}

	// Bring up interface in target namespace
	return m.bringUp()
}

// cleanupInNamespace cleans up the interface, handling namespace isolation if configured.
func (m *linuxManager) cleanupInNamespace() {
	if m.config.NetNS == "" {
		// No namespace, use regular cleanup
		m.cleanup()
		return
	}

	// Get handle to the named namespace
	nsHandle, err := netns.GetFromName(m.config.NetNS)
	if err != nil {
		logger.Warn("Failed to get namespace handle for cleanup",
			"namespace", m.config.NetNS,
			"error", err)
		// Still try regular cleanup
		m.cleanup()
		return
	}
	defer nsHandle.Close()

	// Lock the OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace to restore later
	origNS, err := netns.Get()
	if err != nil {
		logger.Warn("Failed to get current namespace for cleanup", "error", err)
		m.cleanup()
		return
	}
	defer origNS.Close()
	defer netns.Set(origNS)

	// Switch to target namespace
	if err := netns.Set(nsHandle); err != nil {
		logger.Warn("Failed to switch to namespace for cleanup", "error", err)
		m.cleanup()
		return
	}

	// Cleanup in target namespace
	m.cleanup()
}

// NamespaceExists checks if a network namespace with the given name exists.
func NamespaceExists(name string) bool {
	nsHandle, err := netns.GetFromName(name)
	if err != nil {
		return false
	}
	nsHandle.Close()
	return true
}

// CreateNamespace creates a new network namespace with the given name.
// Returns an error if the namespace already exists or if permission is denied.
func CreateNamespace(name string) error {
	// Check if namespace already exists
	if NamespaceExists(name) {
		return fmt.Errorf("namespace %s already exists", name)
	}

	// Create namespace using ip netns add command
	// Note: netns.NewNamed() creates but doesn't persist in /var/run/netns
	// We need to use the ip command or manually create the file
	nsPath := fmt.Sprintf("/var/run/netns/%s", name)

	// Create /var/run/netns directory if it doesn't exist
	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		if os.IsPermission(err) {
			return ErrNetNSPermissionDenied
		}
		return fmt.Errorf("failed to create netns directory: %w", err)
	}

	// Create the namespace file
	f, err := os.Create(nsPath)
	if err != nil {
		if os.IsPermission(err) {
			return ErrNetNSPermissionDenied
		}
		return fmt.Errorf("failed to create namespace file: %w", err)
	}
	f.Close()

	// Create a new namespace
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNS, err := netns.Get()
	if err != nil {
		os.Remove(nsPath)
		return fmt.Errorf("failed to get current namespace: %w", err)
	}
	defer origNS.Close()
	defer netns.Set(origNS)

	// Create new namespace
	newNS, err := netns.New()
	if err != nil {
		os.Remove(nsPath)
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.EPERM || errno == syscall.EACCES {
				return ErrNetNSPermissionDenied
			}
		}
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	defer newNS.Close()

	// Bind mount the namespace to make it persistent
	if err := syscall.Mount("/proc/self/ns/net", nsPath, "none", syscall.MS_BIND, ""); err != nil {
		os.Remove(nsPath)
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.EPERM || errno == syscall.EACCES {
				return ErrNetNSPermissionDenied
			}
		}
		return fmt.Errorf("failed to bind mount namespace: %w", err)
	}

	logger.Info("Created network namespace", "name", name)
	return nil
}

// DeleteNamespace deletes a network namespace with the given name.
func DeleteNamespace(name string) error {
	nsPath := fmt.Sprintf("/var/run/netns/%s", name)

	// Unmount the namespace
	if err := syscall.Unmount(nsPath, 0); err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.ENOENT {
				// Namespace doesn't exist, nothing to do
				return nil
			}
			if errno == syscall.EPERM || errno == syscall.EACCES {
				return ErrNetNSPermissionDenied
			}
		}
		logger.Warn("Failed to unmount namespace", "name", name, "error", err)
	}

	// Remove the file
	if err := os.Remove(nsPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if os.IsPermission(err) {
			return ErrNetNSPermissionDenied
		}
		return fmt.Errorf("failed to remove namespace file: %w", err)
	}

	logger.Info("Deleted network namespace", "name", name)
	return nil
}

// ListNamespaces returns a list of all network namespaces.
func ListNamespaces() ([]string, error) {
	entries, err := os.ReadDir("/var/run/netns")
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		if os.IsPermission(err) {
			return nil, ErrNetNSPermissionDenied
		}
		return nil, fmt.Errorf("failed to read netns directory: %w", err)
	}

	namespaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			namespaces = append(namespaces, entry.Name())
		}
	}

	return namespaces, nil
}

// GetInterfacesInNamespace returns a list of network interfaces in the specified namespace.
func GetInterfacesInNamespace(nsName string) ([]netlink.Link, error) {
	nsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNetNSNotFound, nsName)
		}
		return nil, fmt.Errorf("failed to get namespace handle: %w", err)
	}
	defer nsHandle.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get current namespace: %w", err)
	}
	defer origNS.Close()
	defer netns.Set(origNS)

	if err := netns.Set(nsHandle); err != nil {
		return nil, fmt.Errorf("failed to switch to namespace: %w", err)
	}

	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	return links, nil
}
