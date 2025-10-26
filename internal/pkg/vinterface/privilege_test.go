package vinterface

import (
	"os/user"
	"testing"
)

func TestCanDropPrivileges(t *testing.T) {
	// Just verify the function doesn't crash
	canDrop := CanDropPrivileges()
	t.Logf("Can drop privileges: %v", canDrop)
}

func TestDropPrivilegesEmptyUsername(t *testing.T) {
	// Should do nothing and return nil when username is empty
	err := DropPrivileges("")
	if err != nil {
		t.Errorf("Expected nil error for empty username, got: %v", err)
	}
}

func TestDropPrivilegesNonRoot(t *testing.T) {
	// When not running as root, should be a no-op
	// Get current user for testing
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Try to "drop" to same user - should be no-op if not root
	err = DropPrivileges(currentUser.Username)
	if err != nil {
		t.Logf("Drop privileges returned error (expected if not root): %v", err)
	} else {
		t.Log("Drop privileges succeeded or was skipped (running as non-root)")
	}
}

func TestDropPrivilegesInvalidUser(t *testing.T) {
	// Skip if running as root (would actually try to change)
	if CanDropPrivileges() {
		t.Skip("Skipping invalid user test when running as root")
	}

	// Try to drop to non-existent user
	err := DropPrivileges("nonexistent_user_12345")
	if err == nil {
		// If no error, must be running as non-root (which is fine)
		t.Log("No error (running as non-root)")
	} else {
		// Should get "user not found" error
		t.Logf("Got expected error for invalid user: %v", err)
	}
}
