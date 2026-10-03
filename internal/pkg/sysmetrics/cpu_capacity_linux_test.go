//go:build linux

package sysmetrics

import (
	"errors"
	"io/fs"
	"testing"
)

func capacityFixture(files map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, fs.ErrNotExist
	}
}

func TestCPUCapacityVisibleLimits(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		affinity int
		want     float64
	}{
		{"no CPU controller", map[string]string{"/proc/self/cgroup": "2:memory:/worker\n"}, 8, 8},
		{"no cgroups", map[string]string{"/proc/self/cgroup": ""}, 4, 4},
		{"v2 fractional parent", map[string]string{
			"/proc/self/cgroup":        "0::/parent/child\n",
			"/proc/self/mountinfo":     "1 2 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/parent/child/cpu.max": "max 100000\n",
			"/cg/parent/cpu.max":       "50000 100000\n",
			"/cg/cgroup.controllers":   "cpu memory\n",
		}, 8, 0.5},
		{"v2 affinity below quota", map[string]string{
			"/proc/self/cgroup":      "0::/child\n",
			"/proc/self/mountinfo":   "1 2 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/child/cpu.max":      "350000 100000\n",
			"/cg/cgroup.controllers": "cpu memory\n",
		}, 2, 2},
		{"v2 disabled leaf inherits parent", map[string]string{
			"/proc/self/cgroup":                   "0::/parent/child\n",
			"/proc/self/mountinfo":                "1 2 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/parent/child/cgroup.controllers": "memory\n",
			"/cg/parent/cpu.max":                  "200000 100000\n",
			"/cg/cgroup.controllers":              "cpu memory\n",
		}, 8, 2},
		{"v2 absent CPU controller", map[string]string{
			"/proc/self/cgroup":            "0::/child\n",
			"/proc/self/mountinfo":         "1 2 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/child/cgroup.controllers": "memory\n",
			"/cg/cgroup.controllers":       "memory\n",
		}, 8, 8},
		{"v2 escaped bind mount root", map[string]string{
			"/proc/self/cgroup":       "0::/parent group/child\n",
			"/proc/self/mountinfo":    "1 2 0:1 /parent\\040group /cg\\040mount rw - cgroup2 cgroup rw\n",
			"/cg mount/child/cpu.max": "max 100000\n",
			"/cg mount/cpu.max":       "150000 100000\n",
		}, 8, 1.5},
		{"v2 wider mount includes ancestors", map[string]string{
			"/proc/self/cgroup":        "0::/parent/child\n",
			"/proc/self/mountinfo":     "1 2 0:1 /parent/child /bind rw - cgroup2 cgroup rw\n2 3 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/parent/child/cpu.max": "max 100000\n",
			"/cg/parent/cpu.max":       "50000 100000\n",
			"/cg/cgroup.controllers":   "cpu\n",
		}, 8, 0.5},
		{"hybrid v1 CPU takes precedence", map[string]string{
			"/proc/self/cgroup":                  "0::/unified\n2:cpu,cpuacct:/parent/child\n",
			"/proc/self/mountinfo":               "1 2 0:1 / /cg rw - cgroup cgroup rw,cpu,cpuacct\n2 3 0:2 / /cg2 rw - cgroup2 cgroup rw\n",
			"/cg/parent/child/cpu.cfs_quota_us":  "-1\n",
			"/cg/parent/child/cpu.cfs_period_us": "100000\n",
			"/cg/parent/cpu.cfs_quota_us":        "250000\n",
			"/cg/parent/cpu.cfs_period_us":       "100000\n",
			"/cg/cpu.cfs_quota_us":               "-1\n",
			"/cg/cpu.cfs_period_us":              "100000\n",
		}, 8, 2.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readCPUCapacity(capacityFixture(tt.files), func() (int, error) { return tt.affinity, nil })
			if err != nil || got != tt.want {
				t.Fatalf("capacity = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestCPUCapacityUnknownOnIndeterminateLimits(t *testing.T) {
	baseline := map[string]string{
		"/proc/self/cgroup":      "0::/child\n",
		"/proc/self/mountinfo":   "1 2 0:1 / /cg rw - cgroup2 cgroup rw\n",
		"/cg/child/cpu.max":      "50000 100000\n",
		"/cg/cgroup.controllers": "cpu\n",
	}
	tests := []struct {
		name, path, value string
		remove            bool
	}{
		{"missing membership", "/proc/self/cgroup", "", true},
		{"bad membership", "/proc/self/cgroup", "broken", false},
		{"empty membership path", "/proc/self/cgroup", "0::", false},
		{"invalid hierarchy ID", "/proc/self/cgroup", "x:cpu:/child", false},
		{"duplicate membership", "/proc/self/cgroup", "0::/child\n0::/other", false},
		{"out of namespace", "/proc/self/cgroup", "0::/../../child", false},
		{"relative membership", "/proc/self/cgroup", "0::child", false},
		{"missing mounts", "/proc/self/mountinfo", "", true},
		{"bad mounts", "/proc/self/mountinfo", "broken", false},
		{"unmatched mount", "/proc/self/mountinfo", "1 2 0:1 /other /cg rw - cgroup2 cgroup rw", false},
		{"prefix not ancestor", "/proc/self/mountinfo", "1 2 0:1 /chi /cg rw - cgroup2 cgroup rw", false},
		{"traversal mount", "/proc/self/mountinfo", "1 2 0:1 / /cg/../other rw - cgroup2 cgroup rw", false},
		{"invalid escape", "/proc/self/mountinfo", "1 2 0:1 / /cg\\999 rw - cgroup2 cgroup rw", false},
		{"missing quota and controller availability", "/cg/child/cpu.max", "", true},
		{"missing root availability", "/cg/cgroup.controllers", "", true},
		{"zero period", "/cg/child/cpu.max", "50000 0", false},
		{"negative quota", "/cg/child/cpu.max", "-1 100000", false},
		{"zero quota", "/cg/child/cpu.max", "0 100000", false},
		{"extra quota fields", "/cg/child/cpu.max", "50000 100000 extra", false},
		{"invalid unlimited period", "/cg/child/cpu.max", "max garbage", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := make(map[string]string, len(baseline))
			for k, v := range baseline {
				files[k] = v
			}
			if tt.remove {
				delete(files, tt.path)
			} else {
				files[tt.path] = tt.value
			}
			got, err := readCPUCapacity(capacityFixture(files), func() (int, error) { return 8, nil })
			if got != 0 || err == nil {
				t.Fatalf("capacity = %v, %v; want unknown with error", got, err)
			}
		})
	}
	t.Run("permission denied", func(t *testing.T) {
		read := capacityFixture(baseline)
		got, err := readCPUCapacity(func(path string) ([]byte, error) {
			if path == "/cg/child/cpu.max" {
				return nil, fs.ErrPermission
			}
			return read(path)
		}, func() (int, error) { return 8, nil })
		if got != 0 || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("capacity = %v, %v", got, err)
		}
	})
	for _, count := range []int{0, -1} {
		if got, err := readCPUCapacity(capacityFixture(baseline), func() (int, error) { return count, nil }); got != 0 || err == nil {
			t.Fatalf("empty affinity: %v, %v", got, err)
		}
	}
	if got, err := readCPUCapacity(capacityFixture(baseline), func() (int, error) { return 0, fs.ErrPermission }); got != 0 || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("failed affinity: %v, %v", got, err)
	}
}

func TestCPUCapacityRefreshesLimitsAndMembership(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":      "0::/child",
		"/proc/self/mountinfo":   "1 2 0:1 / /cg rw - cgroup2 cgroup rw",
		"/cg/child/cpu.max":      "50000 100000",
		"/cg/cgroup.controllers": "cpu",
	}
	affinity := 8
	read := func() float64 {
		got, err := readCPUCapacity(capacityFixture(files), func() (int, error) { return affinity, nil })
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(); got != 0.5 {
		t.Fatal(got)
	}
	files["/cg/child/cpu.max"] = "350000 100000"
	if got := read(); got != 3.5 {
		t.Fatal(got)
	}
	affinity = 2
	if got := read(); got != 2 {
		t.Fatal(got)
	}
	files["/proc/self/cgroup"] = "0::/new"
	files["/cg/new/cpu.max"] = "100000 100000"
	if got := read(); got != 1 {
		t.Fatal(got)
	}
}

func TestProcessAffinityCount(t *testing.T) {
	count, err := processAffinityCount()
	if err != nil || count <= 0 {
		t.Fatalf("affinity = %d, %v", count, err)
	}
}

func TestCPUQuotaParsing(t *testing.T) {
	for _, tt := range []struct {
		quota, period, unlimited string
		want                     float64
		valid                    bool
	}{
		{"-1", "100000", "-1", 0, true},
		{"350000", "100000", "-1", 3.5, true},
		{"-2", "100000", "-1", 0, false},
		{"-1", "0", "-1", 0, false},
		{"18446744073709551616", "100000", "max", 0, false},
		{"1", "-1", "max", 0, false},
	} {
		got, err := parseCPUQuota(tt.quota, tt.period, tt.unlimited)
		if (err == nil) != tt.valid || got != tt.want {
			t.Errorf("quota %q / %q = %v, %v", tt.quota, tt.period, got, err)
		}
	}
}

func TestMissingQuotaWithAvailableControllerIsUnknown(t *testing.T) {
	files := map[string]string{
		"/proc/self/cgroup":            "0::/child",
		"/proc/self/mountinfo":         "1 2 0:1 / /cg rw - cgroup2 cgroup rw",
		"/cg/child/cgroup.controllers": "cpu memory",
		"/cg/cgroup.controllers":       "cpu memory",
	}
	if got, err := readCPUCapacity(capacityFixture(files), func() (int, error) { return 8, nil }); got != 0 || err == nil {
		t.Fatalf("capacity = %v, %v", got, err)
	}
}
