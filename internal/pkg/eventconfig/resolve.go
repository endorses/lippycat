package eventconfig

// Resolve validates an owned policy snapshot. Nil means defaults; a supplied
// configuration preserves explicit zero limits so they fail validation.
func Resolve(config *Config) (*Config, error) {
	owned := Default()
	if config != nil {
		owned = config.Clone()
	}
	if err := owned.Validate(); err != nil {
		return nil, err
	}
	return &owned, nil
}
