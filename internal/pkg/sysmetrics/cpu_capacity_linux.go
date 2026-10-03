//go:build linux

package sysmetrics

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// processAffinityCount uses the process leader rather than whichever runtime
// thread happens to collect the sample. Lippycat does not set per-thread affinity.
func processAffinityCount() (int, error) {
	for size := 1024; size <= 1<<20; size *= 2 {
		set := unix.NewCPUSet(size)
		if err := unix.SchedGetaffinityDynamic(os.Getpid(), set); err != nil {
			if errors.Is(err, unix.EINVAL) {
				continue
			}
			return 0, fmt.Errorf("read process CPU affinity: %w", err)
		}
		return set.Count(), nil
	}
	return 0, fmt.Errorf("process CPU affinity mask exceeds supported size")
}

type cpuCgroupMount struct {
	root, point string
	version     int
}

// readCPUCapacity refreshes membership and quotas each sample, including visible
// ancestor limits. Hidden ancestors and contention with other processes cannot
// be measured here: capacity is an upper bound, not a reserved CPU allocation.
func readCPUCapacity(readFile func(string) ([]byte, error), affinity func() (int, error)) (float64, error) {
	count, err := affinity()
	if err != nil {
		return 0, err
	}
	if count <= 0 {
		return 0, fmt.Errorf("empty CPU affinity")
	}
	capacity := float64(count)
	membership, err := readFile("/proc/self/cgroup")
	if err != nil {
		return 0, fmt.Errorf("read CPU cgroup membership: %w", err)
	}
	group, version, err := cpuCgroupMembership(string(membership))
	if err != nil {
		return 0, err
	}
	if version == 0 {
		return capacity, nil // No CPU controller membership.
	}
	mountinfo, err := readFile("/proc/self/mountinfo")
	if err != nil {
		return 0, fmt.Errorf("read CPU cgroup mounts: %w", err)
	}
	mount, err := findCPUCgroupMount(string(mountinfo), group, version)
	if err != nil {
		return 0, err
	}
	rel, err := filepath.Rel(mount.root, group)
	if err != nil {
		return 0, fmt.Errorf("resolve CPU cgroup: %w", err)
	}
	for dir := filepath.Join(mount.point, rel); ; dir = filepath.Dir(dir) {
		quota, err := readCPUQuota(readFile, dir, mount)
		if err != nil {
			return 0, err
		}
		if quota > 0 {
			capacity = math.Min(capacity, quota)
		}
		if dir == mount.point {
			break
		}
	}
	return capacity, nil
}

func cpuCgroupMembership(contents string) (string, int, error) {
	var unified, legacy string
	for _, line := range strings.Split(strings.TrimSpace(contents), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return "", 0, fmt.Errorf("malformed cgroup membership")
		}
		if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil || parts[2] == "" {
			return "", 0, fmt.Errorf("malformed cgroup membership fields")
		}
		if parts[0] == "0" && parts[1] == "" {
			if unified != "" {
				return "", 0, fmt.Errorf("duplicate unified cgroup membership")
			}
			unified = parts[2]
		} else if containsController(parts[1], "cpu", ",") {
			if legacy != "" {
				return "", 0, fmt.Errorf("duplicate CPU cgroup membership")
			}
			legacy = parts[2]
		}
	}
	group, version := legacy, 1 // A v1 CPU controller takes precedence on hybrid hosts.
	if group == "" {
		group, version = unified, 2
	}
	if group == "" {
		return "", 0, nil
	}
	if !cleanAbsolutePath(group) {
		return "", 0, fmt.Errorf("CPU cgroup path is outside the visible hierarchy")
	}
	return group, version, nil
}

func findCPUCgroupMount(contents, group string, version int) (cpuCgroupMount, error) {
	var best cpuCgroupMount
	for _, line := range strings.Split(strings.TrimSpace(contents), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			return best, fmt.Errorf("malformed mountinfo")
		}
		before, after := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(before) < 6 || len(after) < 3 {
			return best, fmt.Errorf("malformed mountinfo fields")
		}
		if version == 2 && after[0] != "cgroup2" || version == 1 && (after[0] != "cgroup" || !containsController(after[2], "cpu", ",")) {
			continue
		}
		root, err := unescapeMountPath(before[3])
		if err != nil {
			return best, err
		}
		point, err := unescapeMountPath(before[4])
		if err != nil {
			return best, err
		}
		if !cleanAbsolutePath(root) || !cleanAbsolutePath(point) {
			return best, fmt.Errorf("invalid CPU cgroup mount path")
		}
		if root != "/" && group != root && !strings.HasPrefix(group, root+"/") {
			continue
		}
		// Prefer the mount exposing the most ancestors, including parent quotas.
		if best.point == "" || len(root) < len(best.root) {
			best = cpuCgroupMount{root: root, point: point, version: version}
		}
	}
	if best.point == "" {
		return best, fmt.Errorf("CPU cgroup mount unavailable")
	}
	return best, nil
}

func cleanAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}

func unescapeMountPath(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", fmt.Errorf("invalid mountinfo path escape")
		}
		escape := value[i+1 : i+4]
		switch escape {
		case "040", "011", "012", "134":
			v, err := strconv.ParseUint(escape, 8, 8)
			if err != nil {
				return "", fmt.Errorf("decode mountinfo path: %w", err)
			}
			out.WriteByte(byte(v))
		default:
			return "", fmt.Errorf("invalid mountinfo path escape")
		}
		i += 3
	}
	return out.String(), nil
}

func containsController(value, controller, separator string) bool {
	for _, field := range strings.Split(strings.TrimSpace(value), separator) {
		if field == controller {
			return true
		}
	}
	return false
}

func readCPUQuota(readFile func(string) ([]byte, error), dir string, mount cpuCgroupMount) (float64, error) {
	if mount.version == 2 {
		data, err := readFile(filepath.Join(dir, "cpu.max"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				controllers, controllerErr := readFile(filepath.Join(dir, "cgroup.controllers"))
				if controllerErr != nil {
					return 0, fmt.Errorf("read CPU controller availability at %s: %w", dir, controllerErr)
				}
				// The actual hierarchy root has no cpu.max. Elsewhere, absent
				// cpu.max is normal only when the CPU controller is unavailable.
				if dir == mount.point && mount.root == "/" || !containsController(string(controllers), "cpu", " ") {
					return 0, nil
				}
			}
			return 0, fmt.Errorf("read CPU quota at %s: %w", dir, err)
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return 0, fmt.Errorf("malformed CPU quota at %s", dir)
		}
		return parseCPUQuota(fields[0], fields[1], "max")
	}
	quota, err := readFile(filepath.Join(dir, "cpu.cfs_quota_us"))
	if err != nil {
		return 0, fmt.Errorf("read CPU quota at %s: %w", dir, err)
	}
	period, err := readFile(filepath.Join(dir, "cpu.cfs_period_us"))
	if err != nil {
		return 0, fmt.Errorf("read CPU period at %s: %w", dir, err)
	}
	return parseCPUQuota(strings.TrimSpace(string(quota)), strings.TrimSpace(string(period)), "-1")
}

func parseCPUQuota(quota, period, unlimited string) (float64, error) {
	p, err := strconv.ParseUint(period, 10, 64)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid CPU quota period %q", period)
	}
	if quota == unlimited {
		return 0, nil
	}
	q, err := strconv.ParseUint(quota, 10, 64)
	if err != nil || q == 0 {
		return 0, fmt.Errorf("invalid CPU quota %q", quota)
	}
	return float64(q) / float64(p), nil
}
