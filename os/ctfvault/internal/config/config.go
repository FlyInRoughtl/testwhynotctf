package config

import (
	"errors"
	"os"
	"strings"

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
	Tools    ToolsConfig    `yaml:"tools"`
	Update   UpdateConfig   `yaml:"update"`
	Telegram TelegramConfig `yaml:"telegram"`
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
	TorTransPort     int    `yaml:"tor_trans_port"`
	TorDNSPort       int    `yaml:"tor_dns_port"`
	TorUseBridges    bool   `yaml:"tor_use_bridges"`
	TorTransport     string `yaml:"tor_transport"`
	TorBridgeLines   []string `yaml:"tor_bridge_lines"`
	TorrcPath        string `yaml:"torrc_path"`
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
	Transport     string `yaml:"transport"`
	PaddingBytes  int    `yaml:"padding_bytes"`
	DiscoveryEnabled bool   `yaml:"discovery_enabled"`
	DiscoveryPort    int    `yaml:"discovery_port"`
	DiscoveryKey     string `yaml:"discovery_key"`
	AutoJoin         bool   `yaml:"auto_join"`
	ChatEnabled      bool   `yaml:"chat_enabled"`
	ClipboardShare   bool   `yaml:"clipboard_share"`
	ClipboardWarn    bool   `yaml:"clipboard_warn"`
	TunEnabled       bool   `yaml:"tun_enabled"`
	TunDevice        string `yaml:"tun_device"`
	TunCIDR          string `yaml:"tun_cidr"`
	TunPeerCIDR      string `yaml:"tun_peer_cidr"`
}

type EmulateConfig struct {
	PrivacyMode  bool   `yaml:"privacy_mode"`
	TempDir      string `yaml:"temp_dir"`
	DownloadsDir string `yaml:"downloads_dir"`
	DisplayServer string `yaml:"display_server"`
}

type TunnelConfig struct {
	Type    string `yaml:"type"`
	Server  string `yaml:"server"`
	Token   string `yaml:"token"`
	LocalIP string `yaml:"local_ip"`
}

type MailConfig struct {
	Mode        string `yaml:"mode"`
	Sink        bool   `yaml:"sink"`
	LocalServer bool   `yaml:"local_server"`
	SinkListen  string `yaml:"sink_listen"`
	SinkUI      string `yaml:"sink_ui"`
	MeshEnabled bool   `yaml:"mesh_enabled"`
	MeshListen  string `yaml:"mesh_listen"`
	MeshPSK     string `yaml:"mesh_psk"`
	MeshPSKFile string `yaml:"mesh_psk_file"`
}

type UIConfig struct {
	Theme    string `yaml:"theme"`
	Language string `yaml:"language"`
	BossKey  bool   `yaml:"boss_key"`
	BossMode string `yaml:"boss_mode"`
}

type ToolsConfig struct {
	File        string `yaml:"file"`
	AutoInstall bool   `yaml:"auto_install"`
}

type UpdateConfig struct {
	URL       string `yaml:"url"`
	Channel   string `yaml:"channel"`
	PublicKey string `yaml:"public_key"`
	Auto      bool   `yaml:"auto"`
}

type TelegramConfig struct {
	Enabled        bool   `yaml:"enabled"`
	BotToken       string `yaml:"bot_token"`
	AllowedUserID  int64  `yaml:"allowed_user_id"`
	PairingTTL     int    `yaml:"pairing_ttl"`
	AllowCLI       bool   `yaml:"allow_cli"`
	AllowWipe      bool   `yaml:"allow_wipe"`
	AllowStats     bool   `yaml:"allow_stats"`
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
			TorTransPort:     9040,
			TorDNSPort:       9053,
			TorUseBridges:    false,
			TorTransport:     "",
			TorBridgeLines:   nil,
			TorrcPath:        "",
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
			Transport:     "tls",
			PaddingBytes:  256,
			DiscoveryEnabled: false,
			DiscoveryPort:    19998,
			DiscoveryKey:     "",
			AutoJoin:         false,
			ChatEnabled:      true,
			ClipboardShare:   false,
			ClipboardWarn:    true,
			TunEnabled:       false,
			TunDevice:        "gargoyle0",
			TunCIDR:          "10.42.0.1/24",
			TunPeerCIDR:      "10.42.0.0/24",
		},
		Emulate: EmulateConfig{
			PrivacyMode:  true,
			TempDir:      "ram",
			DownloadsDir: "downloads",
			DisplayServer: "direct",
		},
		Tunnel: TunnelConfig{
			Type:    "frp",
			Server:  "",
			Token:   "",
			LocalIP: "127.0.0.1",
		},
		Mail: MailConfig{
			Mode:        "local",
			Sink:        true,
			LocalServer: true,
			SinkListen:  "127.0.0.1:1025",
			SinkUI:      "127.0.0.1:8025",
			MeshEnabled: true,
			MeshListen:  ":20025",
			MeshPSK:     "",
			MeshPSKFile: "",
		},
		UI: UIConfig{
			Theme:    "dark",
			Language: "ru",
			BossKey:  true,
			BossMode: "update",
		},
		Tools: ToolsConfig{
			File:        "tools.yaml",
			AutoInstall: false,
		},
		Update: UpdateConfig{
			URL:       "",
			Channel:   "stable",
			PublicKey: "",
			Auto:      false,
		},
		Telegram: TelegramConfig{
			Enabled:       false,
			BotToken:      "",
			AllowedUserID: 0,
			PairingTTL:    60,
			AllowCLI:      false,
			AllowWipe:     false,
			AllowStats:    true,
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
	switch cfg.Mesh.Transport {
	case "", "tcp", "tls":
	default:
		return errors.New("mesh.transport must be tcp|tls")
	}
	if cfg.Mesh.PaddingBytes < 0 {
		return errors.New("mesh.padding_bytes must be >= 0")
	}
	if cfg.Mesh.DiscoveryPort < 0 || cfg.Mesh.DiscoveryPort > 65535 {
		return errors.New("mesh.discovery_port must be 0..65535")
	}
	if cfg.Mesh.TunEnabled {
		if cfg.Mesh.TunDevice == "" {
			return errors.New("mesh.tun_device is required when tun_enabled=true")
		}
		if cfg.Mesh.TunCIDR == "" {
			return errors.New("mesh.tun_cidr is required when tun_enabled=true")
		}
		if cfg.Mesh.TunPeerCIDR == "" {
			return errors.New("mesh.tun_peer_cidr is required when tun_enabled=true")
		}
	}
	switch cfg.Emulate.TempDir {
	case "", "ram", "disk":
	default:
		return errors.New("emulate.temp_dir must be ram|disk")
	}
	switch cfg.Emulate.DisplayServer {
	case "", "direct", "cage", "gamescope", "weston":
	default:
		return errors.New("emulate.display_server must be direct|cage|gamescope|weston")
	}
	switch cfg.Tunnel.Type {
	case "", "frp", "relay", "wss":
	default:
		return errors.New("tunnel.type must be frp|relay|wss")
	}
	if strings.ContainsAny(cfg.Tunnel.LocalIP, "\r\n") {
		return errors.New("tunnel.local_ip contains invalid characters")
	}
	switch cfg.Mail.Mode {
	case "", "local", "tunnel":
	default:
		return errors.New("mail.mode must be local|tunnel")
	}
	if cfg.Mail.Mode == "tunnel" && cfg.Tunnel.Server == "" {
		return errors.New("mail.mode tunnel requires tunnel.server")
	}
	if cfg.Mail.MeshEnabled && cfg.Mail.MeshListen == "" {
		return errors.New("mail.mesh_listen is required when mesh_enabled=true")
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
	if cfg.Network.TorTransPort < 0 || cfg.Network.TorTransPort > 65535 {
		return errors.New("network.tor_trans_port must be 0..65535")
	}
	if cfg.Network.TorDNSPort < 0 || cfg.Network.TorDNSPort > 65535 {
		return errors.New("network.tor_dns_port must be 0..65535")
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
	case "", "sing-box", "xray", "hiddify":
	default:
		return errors.New("network.proxy_engine must be sing-box|xray|hiddify")
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
	if cfg.UI.BossMode != "" {
		switch cfg.UI.BossMode {
		case "update", "htop", "blank":
		default:
			return errors.New("ui.boss_mode must be update|htop|blank")
		}
	}
	if cfg.Telegram.PairingTTL < 0 || cfg.Telegram.PairingTTL > 3600 {
		return errors.New("telegram.pairing_ttl must be 0..3600")
	}
	return nil
}
