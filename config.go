package main

import (
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Sessions  SessionsConfig   `yaml:"sessions"`
	Users     []UserConfig     `yaml:"users"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`
}

type SessionsConfig struct {
	CookieDomain string `yaml:"cookieDomain"`
	CookieName   string `yaml:"cookieName"`
	TTLSeconds   int    `yaml:"ttlSeconds"`
}

type UserConfig struct {
	Username         string   `yaml:"username"`
	TOTPSecret       string   `yaml:"totpSecret"`
	AvailableDomains []string `yaml:"availableDomains"`
}

type UpstreamConfig struct {
	Host        string `yaml:"host"`
	Destination string `yaml:"destination"`
}

func ReadConfig() (*Config, error) {
	config := &Config{}

	configPath := "config.yaml"
	if path := os.Getenv("CONFIG_PATH"); path != "" {
		configPath = path
	}

	err := cleanenv.ReadConfig(configPath, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
