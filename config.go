package main

import (
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"gopkg.in/yaml.v3"
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
	Username     string   `yaml:"username"`
	TOTPSecret   string   `yaml:"totpSecret"`
	AllowedPaths []string `yaml:"allowedPaths"`
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

func SaveConfig() error {
	configPath := "config.yaml"
	if path := os.Getenv("CONFIG_PATH"); path != "" {
		configPath = path
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}
