package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port    int      `yaml:"port"`
	Issuer  string   `yaml:"issuer"`
	Clients []Client `yaml:"clients"`
	Users   []User   `yaml:"users"`
}

type Client struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

type User struct {
	Sub    string         `yaml:"sub"`
	Email  string         `yaml:"email"`
	Name   string         `yaml:"name"`
	Claims map[string]any `yaml:",inline"`
}

func DefaultConfig() Config {
	return Config{
		Port:   8080,
		Issuer: "http://localhost:8080",
		Clients: []Client{
			{
				ID:           "default",
				Secret:       "secret",
				RedirectURIs: []string{"http://localhost:8080/callback"},
			},
		},
		Users: []User{
			{Sub: "user1", Email: "alice@example.com", Name: "Alice", Claims: map[string]any{"roles": []any{"admin"}}},
			{Sub: "user2", Email: "bob@example.com", Name: "Bob", Claims: map[string]any{"roles": []any{"viewer"}}},
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
	}

	if v := os.Getenv("OIDC_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.Port = port
		}
	}
	if v := os.Getenv("OIDC_ISSUER"); v != "" {
		cfg.Issuer = v
	}

	return cfg, nil
}
