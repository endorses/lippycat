package pcaptypes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateLiveInterface(t *testing.T) {
	deviceName := "eth0"

	iface := CreateLiveInterface(deviceName)

	assert.NotNil(t, iface, "CreateLiveInterface should return non-nil interface")
	assert.Equal(t, deviceName, iface.Name(), "Interface name should match input")
}

func TestCreateOfflineInterface(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pcap")

	file, err := os.Create(tmpFile)
	require.NoError(t, err, "Should create temporary file")
	defer file.Close()

	iface := CreateOfflineInterface(file)

	assert.NotNil(t, iface, "CreateOfflineInterface should return non-nil interface")
	assert.Equal(t, tmpFile, iface.Name(), "Interface name should match file path")
}

func TestLiveInterface_Name(t *testing.T) {
	tests := []struct {
		name       string
		deviceName string
	}{
		{
			name:       "Standard ethernet interface",
			deviceName: "eth0",
		},
		{
			name:       "Wireless interface",
			deviceName: "wlan0",
		},
		{
			name:       "Loopback interface",
			deviceName: "lo",
		},
		{
			name:       "Interface with special characters",
			deviceName: "veth-123abc",
		},
		{
			name:       "Empty device name",
			deviceName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := CreateLiveInterface(tt.deviceName)
			assert.Equal(t, tt.deviceName, iface.Name(), "Name should match device name")
		})
	}
}

func TestOfflineInterface_Name(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
	}{
		{
			name:     "Standard pcap file",
			filename: "capture.pcap",
		},
		{
			name:     "File with path",
			filename: "subdir/capture.pcap",
		},
		{
			name:     "File with extension",
			filename: "test.pcapng",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create subdirectory if needed
			fullPath := filepath.Join(tmpDir, tt.filename)
			err := os.MkdirAll(filepath.Dir(fullPath), 0755)
			require.NoError(t, err, "Should create directory")

			file, err := os.Create(fullPath)
			require.NoError(t, err, "Should create file")
			defer file.Close()

			iface := CreateOfflineInterface(file)
			assert.Equal(t, fullPath, iface.Name(), "Name should match full file path")
		})
	}
}

func TestOfflineInterface_Name_NilFile(t *testing.T) {
	// Test the edge case where file is nil
	iface := offlineInterface{file: nil}

	name := iface.Name()
	assert.Equal(t, "offline", name, "Should return 'offline' when file is nil")
}

func TestLiveInterface_Handle_NoHandle(t *testing.T) {
	// Test getting handle when none is set
	iface := liveInterface{Device: "test-device"}

	handle, err := iface.Handle()

	assert.Nil(t, handle, "Handle should be nil when not set")
	assert.Error(t, err, "Should return error when handle is not set")
	assert.Contains(t, err.Error(), "interface has no handle", "Error message should be descriptive")
}

func TestOfflineInterface_Handle_NoHandle(t *testing.T) {
	// Test getting handle when none is set
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pcap")

	file, err := os.Create(tmpFile)
	require.NoError(t, err, "Should create temporary file")
	defer file.Close()

	iface := offlineInterface{file: file}

	handle, err := iface.Handle()

	assert.Nil(t, handle, "Handle should be nil when not set")
	assert.Error(t, err, "Should return error when handle is not set")
	assert.Contains(t, err.Error(), "interface has no handle", "Error message should be descriptive")
}

func TestInterface_Consistency(t *testing.T) {
	// Test that both interface types implement the PcapInterface correctly
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pcap")

	file, err := os.Create(tmpFile)
	require.NoError(t, err, "Should create temporary file")
	defer file.Close()

	// Test that both types can be assigned to PcapInterface
	var liveIface PcapInterface = CreateLiveInterface("eth0")
	var offlineIface PcapInterface = CreateOfflineInterface(file)

	// Both should have all required methods
	assert.NotNil(t, liveIface.Name(), "Live interface should have Name method")
	assert.NotNil(t, offlineIface.Name(), "Offline interface should have Name method")

	// Both should be able to call Handle and SetHandle (even if they error)
	_, err1 := liveIface.Handle()
	_, err2 := offlineIface.Handle()
	assert.Error(t, err1, "Live interface Handle should error when not set")
	assert.Error(t, err2, "Offline interface Handle should error when not set")

	// SetHandle should not panic (actual functionality requires root/valid files)
	assert.NotPanics(t, func() {
		liveIface.SetHandle() // Will likely fail but shouldn't panic
	}, "Live interface SetHandle should not panic")

	assert.NotPanics(t, func() {
		offlineIface.SetHandle() // Will likely fail with empty file but shouldn't panic
	}, "Offline interface SetHandle should not panic")
}

func TestInterface_Types(t *testing.T) {
	// Ensure the concrete types are what we expect
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.pcap")

	file, err := os.Create(tmpFile)
	require.NoError(t, err, "Should create temporary file")
	defer file.Close()

	liveIface := CreateLiveInterface("eth0")
	offlineIface := CreateOfflineInterface(file)

	// Check that the underlying types are correct
	_, ok1 := liveIface.(*liveInterface)
	assert.True(t, ok1, "Should be a liveInterface")

	_, ok2 := offlineIface.(*offlineInterface)
	assert.True(t, ok2, "Should be an offlineInterface")

	// Check that they're different types
	assert.IsType(t, &liveInterface{}, liveIface, "Live interface should be correct type")
	assert.IsType(t, &offlineInterface{}, offlineIface, "Offline interface should be correct type")
}
