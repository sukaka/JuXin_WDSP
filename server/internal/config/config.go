package config

// Config holds server configuration.
type Config struct {
	Env string
}

// Load returns a placeholder config for stage 0.
func Load() (*Config, error) {
	return &Config{Env: "dev"}, nil
}
