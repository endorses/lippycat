package eventconfig

import "fmt"

// SSHPolicy bounds initial-handshake analysis across all sources in a runtime.
// TCP reassembly expiry uses the runtime's shared connection idle timeout.
// Ports are deliberately absent: a recognized SSH identification admits state
// on any port, while a port number alone is never protocol or role evidence.
type SSHPolicy struct {
	Enabled  bool
	MaxFlows int
	MaxBytes int64
}

func DefaultSSH() SSHPolicy {
	return SSHPolicy{Enabled: true, MaxFlows: 1024, MaxBytes: 32 << 20}
}

// EffectiveSSH preserves defaults for older embedded Config literals.
func (c Config) EffectiveSSH() SSHPolicy {
	if c.SSH != nil {
		return *c.SSH
	}
	return DefaultSSH()
}

func (s SSHPolicy) Validate() error {
	if s.MaxFlows <= 0 || s.MaxBytes <= 0 {
		return fmt.Errorf("SSH handshake limits must be positive")
	}
	return nil
}
