//go:build linux

package vinterface

import (
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceExists(t *testing.T) {
	// Test non-existent namespace
	assert.False(t, NamespaceExists("nonexistent-namespace-12345"))

	// Test default namespace (should exist)
	// Note: Cannot easily test this without creating a namespace
}

func TestCreateAndDeleteNamespace(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	nsName := "lippycat-test-ns"

	// Cleanup any existing namespace from previous test
	_ = DeleteNamespace(nsName)

	// Test creating namespace
	err := CreateNamespace(nsName)
	require.NoError(t, err, "Failed to create namespace")

	// Verify namespace exists
	assert.True(t, NamespaceExists(nsName), "Namespace should exist after creation")

	// Test creating duplicate namespace (should fail)
	err = CreateNamespace(nsName)
	assert.Error(t, err, "Creating duplicate namespace should fail")

	// Test deleting namespace
	err = DeleteNamespace(nsName)
	assert.NoError(t, err, "Failed to delete namespace")

	// Verify namespace no longer exists
	assert.False(t, NamespaceExists(nsName), "Namespace should not exist after deletion")

	// Test deleting non-existent namespace (should not error)
	err = DeleteNamespace(nsName)
	assert.NoError(t, err, "Deleting non-existent namespace should not error")
}

func TestListNamespaces(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	nsName := "lippycat-test-list-ns"

	// Cleanup
	_ = DeleteNamespace(nsName)

	// Create test namespace
	err := CreateNamespace(nsName)
	require.NoError(t, err)
	defer DeleteNamespace(nsName)

	// List namespaces
	namespaces, err := ListNamespaces()
	require.NoError(t, err)

	// Verify our namespace is in the list
	found := false
	for _, ns := range namespaces {
		if ns == nsName {
			found = true
			break
		}
	}
	assert.True(t, found, "Created namespace should be in the list")
}

func TestGetInterfacesInNamespace(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	nsName := "lippycat-test-iface-ns"

	// Cleanup
	_ = DeleteNamespace(nsName)

	// Create test namespace
	err := CreateNamespace(nsName)
	require.NoError(t, err)
	defer DeleteNamespace(nsName)

	// Get interfaces in namespace
	// New namespace should only have loopback
	interfaces, err := GetInterfacesInNamespace(nsName)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(interfaces), 1, "Namespace should have at least loopback interface")

	// Test non-existent namespace
	_, err = GetInterfacesInNamespace("nonexistent-ns-12345")
	assert.Error(t, err, "Getting interfaces from non-existent namespace should fail")
	assert.ErrorIs(t, err, ErrNetNSNotFound)
}

func TestVirtualInterfaceInNamespace(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	nsName := "lippycat-test-vif-ns"

	// Cleanup
	_ = DeleteNamespace(nsName)

	// Create test namespace
	err := CreateNamespace(nsName)
	require.NoError(t, err)
	defer DeleteNamespace(nsName)

	// Create virtual interface in namespace
	cfg := DefaultConfig()
	cfg.Name = "lc-test"
	cfg.NetNS = nsName

	mgr, err := NewManager(cfg)
	require.NoError(t, err, "Failed to create manager")

	// Start interface
	err = mgr.Start()
	require.NoError(t, err, "Failed to start interface")
	defer mgr.Shutdown()

	// Give interface time to start
	time.Sleep(100 * time.Millisecond)

	// Verify interface exists in namespace
	interfaces, err := GetInterfacesInNamespace(nsName)
	require.NoError(t, err)

	found := false
	for _, iface := range interfaces {
		if iface.Attrs().Name == "lc-test" {
			found = true
			break
		}
	}
	assert.True(t, found, "Virtual interface should exist in namespace")

	// Test packet injection
	testPacket := types.PacketDisplay{
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		RawData:  []byte("Test SIP packet"),
	}

	err = mgr.InjectPacketBatch([]types.PacketDisplay{testPacket})
	assert.NoError(t, err, "Packet injection should succeed")

	// Verify stats
	stats := mgr.Stats()
	assert.Greater(t, stats.PacketsInjected, uint64(0), "Should have injected at least one packet")
}

func TestNamespacePermissions(t *testing.T) {
	// Only run this test if not root
	if os.Geteuid() == 0 {
		t.Skip("Skipping permission test: running as root")
	}

	// Attempt to create namespace without privileges
	err := CreateNamespace("test-no-perms")
	assert.Error(t, err, "Creating namespace without privileges should fail")
	assert.ErrorIs(t, err, ErrNetNSPermissionDenied)

	// Attempt to delete namespace without privileges
	err = DeleteNamespace("test-no-perms")
	// Should not error if namespace doesn't exist
	// But if it does exist, should get permission denied
}

func TestVirtualInterfaceInNonExistentNamespace(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	// Try to create interface in non-existent namespace
	cfg := DefaultConfig()
	cfg.Name = "lc-test-bad"
	cfg.NetNS = "nonexistent-namespace-12345"

	mgr, err := NewManager(cfg)
	require.NoError(t, err, "Manager creation should succeed")

	// Start should fail because namespace doesn't exist
	err = mgr.Start()
	assert.Error(t, err, "Starting interface in non-existent namespace should fail")
	assert.ErrorIs(t, err, ErrNetNSNotFound)
}

func TestVirtualInterfaceNamespaceCleanup(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping namespace test: requires root privileges")
	}

	nsName := "lippycat-test-cleanup-ns"

	// Cleanup
	_ = DeleteNamespace(nsName)

	// Create test namespace
	err := CreateNamespace(nsName)
	require.NoError(t, err)
	defer DeleteNamespace(nsName)

	// Create virtual interface
	cfg := DefaultConfig()
	cfg.Name = "lc-cleanup"
	cfg.NetNS = nsName

	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	err = mgr.Start()
	require.NoError(t, err)

	// Shutdown interface
	err = mgr.Shutdown()
	assert.NoError(t, err, "Shutdown should succeed")

	// Verify interface is removed from namespace
	interfaces, err := GetInterfacesInNamespace(nsName)
	require.NoError(t, err)

	found := false
	for _, iface := range interfaces {
		if iface.Attrs().Name == "lc-cleanup" {
			found = true
			break
		}
	}
	assert.False(t, found, "Virtual interface should be removed after shutdown")
}
