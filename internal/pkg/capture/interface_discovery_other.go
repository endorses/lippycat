//go:build !linux

package capture

func discoverInterfaceMetadata() (map[string]CaptureInterface, []string) {
	return portableInterfaceMetadata()
}
