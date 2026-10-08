package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type RateLimit struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type AIConfig struct {
	Model     string `yaml:"model"`
	MaxTokens int    `yaml:"max_tokens"`
}

type Config struct {
	Program    string    `yaml:"program"`
	InScope    []string  `yaml:"in_scope"`
	OutOfScope []string  `yaml:"out_of_scope"`
	RateLimit  RateLimit `yaml:"rate_limit"`
	AI         AIConfig  `yaml:"ai"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(c.InScope) == 0 {
		return nil, fmt.Errorf("no in-scope targets defined; refusing to run")
	}
	if c.RateLimit.RequestsPerSecond <= 0 {
		c.RateLimit.RequestsPerSecond = 1
	}
	return &c, nil
}

// AIEndpoint returns AI connection details from the environment.
func (c *Config) AIEndpoint() (baseURL, apiKey, model string) {
	baseURL = os.Getenv("AI_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	apiKey = os.Getenv("AI_API_KEY")
	model = c.AI.Model
	return
}
