package packetdedup

import "time"

// Settings enables conservative overlap suppression for independent consumers.
// Bounds are operator settings, not performance acceptance requirements.
type Settings struct {
	Enabled    bool          `mapstructure:"enabled"`
	Window     time.Duration `mapstructure:"window"`
	MaxEntries int           `mapstructure:"max_entries"`
	MaxBytes   int64         `mapstructure:"max_bytes"`
}

func (s Settings) Normalize() (Settings, error) {
	if s.Window == 0 {
		s.Window = 2 * time.Second
	}
	if s.MaxEntries == 0 {
		s.MaxEntries = 10000
	}
	if s.MaxBytes == 0 {
		s.MaxBytes = 32 << 20
	}
	_, err := New(s.Config())
	return s, err
}

func (s Settings) Config() Config {
	return Config{Window: s.Window, MaxEntries: s.MaxEntries, MaxBytes: s.MaxBytes}
}
