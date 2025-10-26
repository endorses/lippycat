//go:build linux

package vinterface

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// DropPrivileges drops root privileges to the specified user after interface creation.
// This should be called after creating the virtual interface which requires CAP_NET_ADMIN.
//
// The function performs the following steps:
// 1. Looks up the target user
// 2. Clears supplementary group IDs
// 3. Sets the group ID (must be done before UID)
// 4. Sets the user ID
//
// Note: This requires Go 1.16+ for reliable setuid support.
func DropPrivileges(username string) error {
	if username == "" {
		return nil // No privilege dropping requested
	}

	// Get current UID to check if we're root
	currentUID := syscall.Getuid()
	if currentUID != 0 {
		logger.Debug("Not running as root, skipping privilege drop", "uid", currentUID)
		return nil
	}

	// Look up the target user
	targetUser, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", username, err)
	}

	// Convert UID and GID from strings to integers
	uid, err := strconv.Atoi(targetUser.Uid)
	if err != nil {
		return fmt.Errorf("invalid UID for user %s: %w", username, err)
	}

	gid, err := strconv.Atoi(targetUser.Gid)
	if err != nil {
		return fmt.Errorf("invalid GID for user %s: %w", username, err)
	}

	logger.Info("Dropping privileges", "from_uid", currentUID, "to_user", username, "to_uid", uid, "to_gid", gid)

	// Clear supplementary group IDs
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("failed to clear supplementary groups: %w", err)
	}

	// Set group ID first (must be done before UID since we need root to change group)
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set GID to %d: %w", gid, err)
	}

	// Set user ID last (after this, we lose root privileges)
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set UID to %d: %w", uid, err)
	}

	// Verify we successfully dropped privileges
	newUID := syscall.Getuid()
	newGID := syscall.Getgid()

	if newUID != uid || newGID != gid {
		return fmt.Errorf("privilege drop verification failed: expected UID=%d GID=%d, got UID=%d GID=%d",
			uid, gid, newUID, newGID)
	}

	logger.Info("Privileges dropped successfully", "uid", newUID, "gid", newGID, "user", username)
	return nil
}

// CanDropPrivileges returns true if the current process can drop privileges.
// This is true if running as root (UID 0).
func CanDropPrivileges() bool {
	return syscall.Getuid() == 0
}
