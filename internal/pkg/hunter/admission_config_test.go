//go:build hunter || all

package hunter

import (
	"reflect"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func TestAdmissionNormalizesCaptureInterfaces(t *testing.T) {
	original := []string{" eth0, eth1 ", "eth2, , eth3"}
	for _, enabled := range []bool{false, true} {
		config := Config{HunterID: "interface-test", ProcessorAddr: "localhost:55555", Interfaces: original}
		if enabled {
			config.MediaAdmission = &admissionintegration.Session{Config: mediaadmission.Config{Enabled: true}}
		}
		h, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		want := original
		if enabled {
			want = []string{"eth0", "eth1", "eth2", "eth3"}
		}
		if !reflect.DeepEqual(h.config.Interfaces, want) {
			t.Fatalf("enabled=%v: interfaces=%q, want %q", enabled, h.config.Interfaces, want)
		}
	}
	if original[0] != " eth0, eth1 " {
		t.Fatal("constructor mutated caller's interface slice")
	}
}
