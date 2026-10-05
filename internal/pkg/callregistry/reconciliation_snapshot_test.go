package callregistry

import (
	"testing"
	"time"
)

func TestCompleteEndpointSnapshotsHoldLifetimeAndRevisionDuringPublication(t *testing.T) {
	core := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 2, MaxEndpointAssociations: 4})
	t.Cleanup(core.Close)
	core.Upsert(Call{CallID: "synthetic"})
	core.TryAssociateEndpoint("synthetic", "192.0.2.1:9000")
	entered, release := make(chan struct{}), make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- core.WithEndpointSnapshots([]string{"synthetic"}, func(observations []EndpointObservation) error {
			if len(observations) != 1 || len(observations[0].Endpoints) != 1 {
				t.Error("incomplete snapshot")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	mutationStarted, mutationDone := make(chan struct{}), make(chan struct{})
	go func() { close(mutationStarted); core.Remove("synthetic", EndCompleted); close(mutationDone) }()
	<-mutationStarted
	select {
	case <-mutationDone:
		t.Error("lifetime changed before snapshot publication finished")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	<-mutationDone
	if _, ok := core.Call("synthetic"); ok {
		t.Fatal("mutation did not resume after publication")
	}
}
