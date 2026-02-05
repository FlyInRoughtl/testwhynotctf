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
	Emulate  EmulateConfig  `yaml:"emulate"`
	Tunnel   TunnelConfig   `yaml:"tunnel"`
	Mail     MailConfig     `yaml:"mail"`
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
	USBEnabled        bool   `yaml:"usb_enabled"`
	USBReadOnly       bool   `yaml:"usb_read_only"`
	RAMOnly           bool   `yaml:"ram_only"`
}

type NetworkConfig struct {
	Proxy            string `yaml:"proxy"`
	Mode             string `yaml:"mode"`
	VPNType          string `yaml:"vpn_type"`
	VPNProfile       string `yaml:"vpn_profile"`
	GatewayIP        string `yaml:"gateway_ip"`
	ProxyEngine      string `yaml:"proxy_engine"`
	ProxyConfig      string `yaml:"proxy_config"`
	DNSProfile       string `yaml:"dns_profile"`
	DNSCustom        string `yaml:"dns_custom"`
	DoHURL           string `yaml:"doh_url"`
	DoHListen        string `yaml:"doh_listen"`
	Tor              bool   `yaml:"tor"`
	TorAlwaysOn      bool   `yaml:"tor_always_on"`
	TorStrict        bool   `yaml:"tor_strict"`
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

type EmulateConfig struct {
	PrivacyMode  bool   `yaml:"privacy_mode"`
	TempDir      string `yaml:"temp_dir"`
	DownloadsDir string `yaml:"downloads_dir"`
}

type TunnelConfig struct {
	Type   string `yaml:"type"`
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
}

type MailConfig struct {
	Mode        string `yaml:"mode"`
	Sink        bool   `yaml:"sink"`
	LocalServer bool   `yaml:"local_server"`
	SinkListen  string `yaml:"sink_listen"`
	SinkUI      string `yaml:"sink_ui"`
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
			USBEnabled:        false,
			USBReadOnly:       false,
			RAMOnly:           false,
		},
		Network: NetworkConfig{
			Proxy:            "",
			Mode:             "direct",
			VPNType:          "",
			VPNProfile:       "",
			GatewayIP:        "",
			ProxyEngine:      "",
			ProxyConfig:      "",
			DNSProfile:       "system",
			DNSCustom:        "",
			DoHURL:           "",
			DoHListen:        "127.0.0.1:5353",
			Tor:              false,
			TorAlwaysOn:      false,
			TorStrict:        false,
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
		Emulate: EmulateConfig{
			PrivacyMode:  true,
			TempDir:      "ram",
			DownloadsDir: "downloads",
		},
		Tunnel: TunnelConfig{
			Type:   "frp",
			Server: "",
			Token:  "",
		},
		Mail: MailConfig{
			Mode:        "local",
			Sink:        true,
			LocalServer: true,
			SinkListen:  "127.0.0.1:1025",
			SinkUI:      "127.0.0.1:8025",
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
	switch cfg.Emulate.TempDir {
	case "", "ram", "disk":
	default:
		return errors.New("emulate.temp_dir must be ram|disk")
	}
	switch cfg.Tunnel.Type {
	case "", "frp", "relay":
	default:
		return errors.New("tunnel.type must be frp|relay")
	}
	switch cfg.Mail.Mode {
	case "", "local", "tunnel":
	default:
		return errors.New("mail.mode must be local|tunnel")
	}
	if cfg.Mail.Mode == "tunnel" && cfg.Tunnel.Server == "" {
		return errors.New("mail.mode tunnel requires tunnel.server")
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
	switch cfg.Network.Mode {
	case "", "direct", "vpn", "gateway", "proxy":
	default:
		return errors.New("network.mode must be direct|vpn|gateway|proxy")
	}
	switch cfg.Network.VPNType {
	case "", "openvpn", "wireguard":
	default:
		return errors.New("network.vpn_type must be openvpn|wireguard")
	}
	switch cfg.Network.ProxyEngine {
	case "", "sing-box", "xray":
	default:
		return errors.New("network.proxy_engine must be sing-box|xray")
	}
	if cfg.Network.Mode == "vpn" {
		if cfg.Network.VPNType == "" {
			return errors.New("network.vpn_type required for vpn mode")
		}
		if cfg.Network.VPNProfile == "" {
			return errors.New("network.vpn_profile required for vpn mode")
		}
	}
	if cfg.Network.Mode == "gateway" && cfg.Network.GatewayIP == "" {
		return errors.New("network.gateway_ip required for gateway mode")
	}
	if cfg.Network.Mode == "proxy" {
		if cfg.Network.ProxyEngine == "" {
			return errors.New("network.proxy_engine required for proxy mode")
		}
		if cfg.Network.ProxyConfig == "" {
			return errors.New("network.proxy_config required for proxy mode")
		}
	}
	return nil
}
