package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	System   SystemConfig   `yaml:"system"`
	Storage  StorageConfig  `yaml:"storage"`
	Network  NetworkConfig  `yaml:"network"`
	Security SecurityConfig `yaml:"security"`
	Mesh     MeshConfig     `yaml:"mesh"`
	UI       UIConfig       `yaml:"ui"`
}

type SystemConfig struct {
	RamLimitMB int    `yaml:"ram_limit_mb"`
	CPULimit   int    `yaml:"cpu_limit"`
	Locale     string `yaml:"locale"`
	Edition    string `yaml:"edition"`
}

type StorageConfig struct {
	Persistent        bool   `yaml:"persistent"`
	Shared            bool   `yaml:"shared"`
	RecoveryCodesPath string `yaml:"recovery_codes"`
}

type NetworkConfig struct {
	Proxy            string `yaml:"proxy"`
	DNSProfile       string `yaml:"dns_profile"`
	DNSCustom        string `yaml:"dns_custom"`
	DoHURL           string `yaml:"doh_url"`
	DoHListen        string `yaml:"doh_listen"`
	Tor              bool   `yaml:"tor"`
	MACSpoof         bool   `yaml:"mac_spoof"`
	WifiEnabled      bool   `yaml:"wifi_enabled"`
	BluetoothEnabled bool   `yaml:"bluetooth_enabled"`
	PortsOpen        bool   `yaml:"ports_open"`
}

type SecurityConfig struct {
	IdentityKeyPath string `yaml:"identity_key_path"`
	IdentityLength  int    `yaml:"identity_length"`
	IdentityGroup   int    `yaml:"identity_group"`
}

type MeshConfig struct {
	RelayURL      string `yaml:"relay_url"`
	OnionDepth    int    `yaml:"onion_depth"`
	MetadataLevel string `yaml:"metadata_level"`
}

type UIConfig struct {
	Theme    string `yaml:"theme"`
	Language string `yaml:"language"`
}

func DefaultConfig() Config {
	return Config{
		System: SystemConfig{
			RamLimitMB: 2048,
			CPULimit:   2,
			Locale:     "ru",
			Edition:    "public",
		},
		Storage: StorageConfig{
			Persistent:        true,
			Shared:            false,
			RecoveryCodesPath: "recovery_codes.txt",
		},
		Network: NetworkConfig{
			Proxy:            "",
			DNSProfile:       "system",
			DNSCustom:        "",
			DoHURL:           "",
			DoHListen:        "127.0.0.1:5353",
			Tor:              false,
			MACSpoof:         true,
			WifiEnabled:      true,
			BluetoothEnabled: false,
			PortsOpen:        false,
		},
		Security: SecurityConfig{
			IdentityKeyPath: "keys/identity.key",
			IdentityLength:  256,
			IdentityGroup:   15,
		},
		Mesh: MeshConfig{
			RelayURL:      "",
			OnionDepth:    3,
			MetadataLevel: "standard",
		},
		UI: UIConfig{
			Theme:    "dark",
			Language: "ru",
		},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadOptional(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return Config{}, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if err := validate(cfg); err != nil {
		return err
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func validate(cfg Config) error {
	if cfg.Mesh.OnionDepth < 1 || cfg.Mesh.OnionDepth > 10 {
		return errors.New("mesh.onion_depth must be 1..10")
	}
	switch cfg.Mesh.MetadataLevel {
	case "off", "standard", "max":
	default:
		return errors.New("mesh.metadata_level must be off|standard|max")
	}
	if cfg.UI.Language == "" {
		return errors.New("ui.language is required")
	}
	if cfg.UI.Theme == "" {
		return errors.New("ui.theme is required")
	}
	if cfg.Security.IdentityLength != 256 {
		return errors.New("security.identity_length must be 256")
	}
	if cfg.Security.IdentityGroup <= 0 || cfg.Security.IdentityGroup > cfg.Security.IdentityLength {
		return errors.New("security.identity_group must be in range")
	}
	if cfg.Network.DNSProfile == "" {
		return errors.New("network.dns_profile is required")
	}
	return nil
}
