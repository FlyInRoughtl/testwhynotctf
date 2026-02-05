package ui

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gargoyle/internal/config"
	"gargoyle/internal/mesh"
	"gargoyle/internal/paths"
	"gargoyle/internal/services"
	"gargoyle/internal/system"
	"gargoyle/internal/version"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type view int

const (
	viewHome view = iota
	viewNetwork
	viewStorage
	viewEmulate
	viewHub
	viewTools
	viewMesh
	viewStatus
	viewSystem
)

const tickRate = 150 * time.Millisecond

type tickMsg time.Time

const gargoyleBanner = `  ######  #####  ######  ######  #####  ##   ## ##     #######
 ##      ##   ## ##   ## ##     ##   ##  ## ##  ##     ##
 ##  ### ####### ######  ##  ### #######   ###   ##     #####
 ##   ## ##   ## ##   ## ##   ## ##   ##   ##    ##     ##
  ###### ##   ## ##   ##  ###### ##   ##   ##    ###### #######

           /\\  G A R G O Y L E  /\\`

type model struct {
	cfg         config.Config
	home        string
	identity    string
	view        view
	cursor      int
	menu        []string
	tick        int
	width       int
	height      int
	networks    []string
	netStatus   string
	lastScanAt  time.Time
	usbDevices  []string
	usbStatus   string
	meshPeers   []string
	meshErr     string
	services    *services.Manager
	status      services.Status
	lastMsg     string
	lastErr     string
	confirmWipe bool
	usbLocked   bool
	usbEvents   <-chan system.USBEvent
	bossMode    bool
}

type netScanMsg struct {
	Networks []string
	Err      error
}

type statusMsg struct {
	Status services.Status
}

type usbScanMsg struct {
	Devices []string
	Err     error
}

type usbEventMsg struct {
	Event system.USBEvent
}

type meshDiscoverMsg struct {
	Peers []string
	Err   error
}

func initialModel(cfg config.Config, home string, identity string, svc *services.Manager, usbEvents <-chan system.USBEvent) model {
	return model{
		cfg:       cfg,
		home:      home,
		identity:  identity,
		menu:      []string{"Home", "Network", "Storage", "Emulate", "Hub", "Tools", "Mesh", "Status", "System"},
		view:      viewHome,
		netStatus: "scan pending",
		usbStatus: usbStatusDefault(cfg),
		services:  svc,
		usbEvents: usbEvents,
	}
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd(), scanNetworksCmd(), statusCmd(m.services)}
	if m.cfg.Storage.USBEnabled {
		cmds = append(cmds, scanUSBsCmd())
	}
	if m.usbEvents != nil {
		cmds = append(cmds, usbWatchCmd(m.usbEvents))
	}
	if m.cfg.Mesh.DiscoveryEnabled {
		cmds = append(cmds, discoverMeshCmd(m.cfg))
	}
	return tea.Batch(cmds...)
}

func tickCmd() tea.Cmd {
	return tea.Tick(tickRate, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.tick++
		if m.tick%20 == 0 {
			cmds := []tea.Cmd{tickCmd(), scanNetworksCmd(), statusCmd(m.services)}
			if m.cfg.Storage.USBEnabled {
				cmds = append(cmds, scanUSBsCmd())
			}
			return m, tea.Batch(cmds...)
		}
		return m, tea.Batch(tickCmd(), statusCmd(m.services))
	case netScanMsg:
		if msg.Err != nil {
			m.netStatus = msg.Err.Error()
		} else {
			m.netStatus = fmt.Sprintf("found %d", len(msg.Networks))
			m.networks = msg.Networks
		}
		m.lastScanAt = time.Now()
	case usbScanMsg:
		if msg.Err != nil {
			m.usbStatus = msg.Err.Error()
		} else {
			m.usbStatus = fmt.Sprintf("found %d", len(msg.Devices))
			m.usbDevices = msg.Devices
		}
	case statusMsg:
		m.status = msg.Status
	case wipeMsg:
		if msg.Err != nil {
			m.lastErr = msg.Err.Error()
		} else {
			m.lastMsg = "emergency wipe completed"
			m.usbLocked = false
		}
	case usbEventMsg:
		if msg.Event.Removed {
			m.usbLocked = true
			m.lastErr = "USB removed: emergency wipe required"
			m.lastMsg = ""
			m.confirmWipe = false
		}
	case meshDiscoverMsg:
		if msg.Err != nil {
			m.meshErr = msg.Err.Error()
		} else {
			m.meshPeers = msg.Peers
			m.meshErr = ""
		}
	case tea.KeyMsg:
		if m.cfg.UI.BossKey && msg.String() == "f10" {
			m.bossMode = !m.bossMode
			return m, nil
		}
		if m.usbLocked {
			if msg.String() == "x" {
				if !m.confirmWipe {
					m.confirmWipe = true
					m.lastMsg = "press x again to confirm emergency wipe"
					m.lastErr = ""
					break
				}
				m.confirmWipe = false
				return m, wipeCmd(m.home, m.cfg.Security.IdentityKeyPath)
			}
			return m, nil
		}
		if m.view == viewEmulate {
			if m.services == nil {
				m.lastErr = "services unavailable"
				break
			}
			switch msg.String() {
			case "f":
				m.lastErr = ""
				if err := m.services.StartEmulate("firefox", nil, m.cfg.Emulate, m.home); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "emulate: firefox"
				}
			case "t":
				m.lastErr = ""
				if err := m.services.StartEmulate("torbrowser-launcher", nil, m.cfg.Emulate, m.home); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "emulate: torbrowser-launcher"
				}
			case "o":
				m.lastErr = ""
				if err := m.services.StartEmulate("xdg-open", []string{m.home}, m.cfg.Emulate, m.home); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "emulate: xdg-open"
				}
			case "s":
				m.lastErr = ""
				if err := m.services.StopEmulate(); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "emulate: stopped"
				}
			}
		}
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.view = view(m.cursor)
			}
		case "down", "j":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
				m.view = view(m.cursor)
			}
		case "left", "h":
			if m.cursor > 0 {
				m.cursor--
				m.view = view(m.cursor)
			}
		case "right", "l":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
				m.view = view(m.cursor)
			}
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			key := msg.String()
			if len(key) > 0 {
				idx := int(key[0] - '1')
				if idx >= 0 && idx < len(m.menu) {
					m.cursor = idx
					m.view = view(idx)
				}
			}
		case "r":
			m.lastErr = ""
			m.lastMsg = ""
			if m.services == nil {
				m.lastErr = "services unavailable"
				break
			}
			if m.status.RelayRunning {
				if err := m.services.StopRelay(); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "relay stopped"
				}
			} else {
				if err := m.services.StartRelay(":18080"); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "relay started on :18080"
				}
			}
		case "d":
			m.lastErr = ""
			m.lastMsg = ""
			if m.services == nil {
				m.lastErr = "services unavailable"
				break
			}
			if m.status.DoHRunning {
				if err := m.services.StopDoH(); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = "doh stopped"
				}
			} else {
				if m.cfg.Network.DoHURL == "" {
					m.lastErr = "doh url not configured"
					break
				}
				if err := m.services.StartDoH(m.cfg.Network.DoHListen, m.cfg.Network.DoHURL); err != nil {
					m.lastErr = err.Error()
				} else {
					m.lastMsg = fmt.Sprintf("doh started on %s", m.cfg.Network.DoHListen)
				}
			}
		case "x":
			if !m.confirmWipe {
				m.confirmWipe = true
				m.lastMsg = "press x again to confirm emergency wipe"
				m.lastErr = ""
				break
			}
			m.confirmWipe = false
			return m, wipeCmd(m.home, m.cfg.Security.IdentityKeyPath)
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.bossMode {
		return bossView(m)
	}
	appStyle := lipgloss.NewStyle().Padding(1, 2)
	header := headerView(m)
	sidebar := sidebarView(m)
	main := mainView(m)
	footer := footerView(m)

	layout := lipgloss.JoinVertical(lipgloss.Left,
		header,
		lipgloss.JoinHorizontal(lipgloss.Top, sidebar, main),
		footer,
	)

	return appStyle.Render(layout)
}

func headerView(m model) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Render("GARGOYLE")
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("v" + version.Version + " - TUI")
	return lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", subtitle)
}

func sidebarView(m model) string {
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
	var b strings.Builder
	b.WriteString("Menu\n\n")
	for i, item := range m.menu {
		cursor := " "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			cursor = ">"
			style = style.Bold(true).Foreground(lipgloss.Color("229"))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", cursor, style.Render(item)))
	}

	b.WriteString("\n")
	b.WriteString("WiFi: " + wifiAnim(m.tick) + "\n")
	b.WriteString("BT: " + onOff(m.cfg.Network.BluetoothEnabled) + "\n")
	torOn := m.cfg.Network.Tor || m.cfg.Network.TorAlwaysOn
	b.WriteString("Tor: " + onOff(torOn) + "\n")

	return box.Render(b.String())
}

func mainView(m model) string {
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Width(max(40, m.width-30))
	switch m.view {
	case viewHome:
		return box.Render(homeView(m))
	case viewNetwork:
		return box.Render(networkView(m))
	case viewStorage:
		return box.Render(storageView(m))
	case viewEmulate:
		return box.Render(emulateView(m))
	case viewHub:
		return box.Render(hubView(m))
	case viewTools:
		return box.Render(toolsView(m))
	case viewMesh:
		return box.Render(meshView(m))
	case viewStatus:
		return box.Render(statusView(m))
	case viewSystem:
		return box.Render(systemView(m))
	default:
		return box.Render("Unknown view")
	}
}

func footerView(m model) string {
	hint := "Arrows: navigate | 1-9: jump | r: relay | d: doh | x: wipe | f10: boss | q/esc: quit"
	return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(hint)
}

func bossView(m model) string {
	switch m.cfg.UI.BossMode {
	case "blank":
		return ""
	case "htop":
		return "top - 22:10:15 up  2:41,  1 user,  load average: 0.12, 0.09, 0.08\n\n" +
			"Tasks: 109 total,   1 running, 108 sleeping,   0 stopped,   0 zombie\n" +
			"%Cpu(s):  2.1 us,  1.0 sy,  0.0 ni, 96.5 id,  0.3 wa,  0.0 hi,  0.1 si,  0.0 st\n" +
			"MiB Mem :   7800.0 total,   6211.5 free,    999.2 used,    589.3 buff/cache\n" +
			"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   6400.0 avail Mem\n\n" +
			"  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND\n" +
			"  972 root      20   0  102932   9876   8420 S   0.7  0.1   0:01.23 NetworkManager\n" +
			" 1442 user      20   0  318400  30500  22000 S   1.3  0.4   0:12.88 gnome-shell\n"
	default:
		return "Configuring updates 35%...\n\n" +
			"Do not turn off your computer."
	}
}

func homeView(m model) string {
	cpu := bar(m.tick%100, 100, 20)
	ram := bar((m.tick*3)%100, 100, 20)
	disk := bar((m.tick*7)%100, 100, 20)
	net := bar((m.tick*5)%100, 100, 20)
	ctfLabel, ctfHints := ctfSafeSummary(m.cfg)
	hintText := "-"
	if len(ctfHints) > 0 {
		hintText = strings.Join(ctfHints, "; ")
	}

	banner := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Render(gargoyleBanner)

	return fmt.Sprintf(
		"%s\n\nDashboard\n\nCPU  [%s]\nRAM  [%s]\nDisk [%s]\nNet  [%s]\n\nCTF-safe: %s\nHints: %s",
		banner,
		cpu, ram, disk, net,
		ctfLabel, hintText,
	)
}

func networkView(m model) string {
	scan := spinner(m.tick)
	netLines := "no networks detected"
	if len(m.networks) > 0 {
		netLines = strings.Join(m.networks, "\n")
	}
	return fmt.Sprintf(
		"Network\n\nScan: %s (%s)\n\nProfiles:\n- Mode: %s\n- VPN: %s\n- Proxy: %s\n- Gateway: %s\n- DNS: %s\n- Tor always: %s\n- Tor strict: %s\n- MAC spoof: %s\n- Ports open: %s\n\nNetworks:\n%s\n",
		scan,
		m.netStatus,
		m.cfg.Network.Mode,
		netVPN(m.cfg.Network.VPNType, m.cfg.Network.VPNProfile),
		netProxy(m.cfg.Network.ProxyEngine, m.cfg.Network.ProxyConfig),
		emptyIf(m.cfg.Network.GatewayIP),
		m.cfg.Network.DNSProfile,
		onOff(m.cfg.Network.TorAlwaysOn),
		onOff(m.cfg.Network.TorStrict),
		onOff(m.cfg.Network.MACSpoof),
		onOff(m.cfg.Network.PortsOpen),
		netLines,
	)
}

func storageView(m model) string {
	usbList := "(none)"
	if len(m.usbDevices) > 0 {
		usbList = strings.Join(m.usbDevices, "\n")
	}
	return fmt.Sprintf(
		"Storage\n\nHome: %s\nPersistent: %s\nShared: %s\nUSB access: %s\nRAM-only: %s\nUSB devices: %s (%s)\n\nActions:\n- gargoyle wipe\n- gargoyle wipe --emergency\n",
		m.home,
		onOff(m.cfg.Storage.Persistent),
		onOff(m.cfg.Storage.Shared),
		usbAccessLabel(m.cfg.Storage.USBEnabled, m.cfg.Storage.USBReadOnly),
		onOff(m.cfg.Storage.RAMOnly),
		usbList,
		m.usbStatus,
	)
}

func emulateView(m model) string {
	state := "stopped"
	pid := 0
	app := "-"
	if m.status.Emulate.Running {
		state = "running"
		pid = m.status.Emulate.PID
		app = m.status.Emulate.App
	}
	privacy := "best-effort"
	if !m.cfg.Emulate.PrivacyMode {
		privacy = "off"
	}
	return fmt.Sprintf(
		"EmulateEL (Linux GUI)\n\nStatus: %s\nApp: %s\nPID: %d\nPrivacy: %s\n\nActions:\n- f: firefox\n- t: torbrowser-launcher\n- o: file manager (xdg-open)\n- s: stop\n- CLI: gargoyle emulate run <app>\n",
		state,
		app,
		pid,
		privacy,
	)
}

func hubView(m model) string {
	hubState := onOff(m.status.HubRunning)
	tunnelState := onOff(m.status.TunnelRunning)
	mailState := "sink " + onOff(m.status.MailSinkRunning) + " / local " + onOff(m.status.MailLocalRunning) + " / mesh " + onOff(m.status.MailMeshRunning)
	return fmt.Sprintf(
		"Resource Hub\n\nHub: %s (%s)\nTunnel: %s (%s)\nMail: %s\n\nHints:\n- hub start --listen 127.0.0.1:8080\n- tunnel expose <service> <port>\n- mail start --mode local|tunnel\n",
		hubState,
		emptyIf(m.status.HubListen),
		tunnelState,
		emptyIf(m.status.TunnelServer),
		mailState,
	)
}

func toolsView(m model) string {
	return "Tools\n\n- Crypto\n- Web\n- Pwn\n- Forensics\n- Reversing\n- Wireless\n\nStatus: use `gargoyle tools list|install|edit`"
}

func meshView(m model) string {
	peers := "-"
	if len(m.meshPeers) > 0 {
		peers = strings.Join(m.meshPeers, "\n")
	}
	errLine := ""
	if m.meshErr != "" {
		errLine = "\nDiscovery error: " + m.meshErr
	}
	return fmt.Sprintf(
		"Mesh\n\nStatus: direct mode\nSend/Recv: available\nRelay/Onion: available via CLI\nDiscovery: %s (port %d)\nPeers:\n%s\nClipboard share: %s\nTun: %s%s",
		onOff(m.cfg.Mesh.DiscoveryEnabled),
		m.cfg.Mesh.DiscoveryPort,
		peers,
		onOff(m.cfg.Mesh.ClipboardShare),
		onOff(m.cfg.Mesh.TunEnabled),
		errLine,
	)
}

func statusView(m model) string {
	relayState := "stopped"
	if m.status.RelayRunning {
		relayState = "running"
	}
	relayPID := "-"
	dohState := "stopped"
	if m.status.DoHRunning {
		dohState = "running"
	}

	var statusLine strings.Builder
	if m.lastErr != "" {
		statusLine.WriteString("Last error: ")
		statusLine.WriteString(m.lastErr)
	} else if m.lastMsg != "" {
		statusLine.WriteString("Last action: ")
		statusLine.WriteString(m.lastMsg)
	} else {
		statusLine.WriteString("Last action: none")
	}

	return fmt.Sprintf(
		"Status\n\nRelay: %s\nListen: %s\nPID: %s\nError: %s\n\nDoH: %s\nListen: %s\nURL: %s\nPID: %d\nError: %s\n\nEmulate: %s (%s)\nTunnel: %s (%s)\nProxy: %s (%s)\nMail: sink %s / local %s / mesh %s\nHub: %s (%s)\nTelegram: %s\n\n%s",
		relayState,
		emptyIf(m.status.RelayListen),
		relayPID,
		emptyIf(m.status.RelayError),
		dohState,
		emptyIf(m.status.DoHListen),
		emptyIf(m.status.DoHURL),
		m.status.DoHPID,
		emptyIf(m.status.DoHError),
		onOff(m.status.Emulate.Running),
		emptyIf(m.status.Emulate.App),
		onOff(m.status.TunnelRunning),
		emptyIf(m.status.TunnelServer),
		onOff(m.status.ProxyRunning),
		emptyIf(m.status.ProxyEngine),
		onOff(m.status.MailSinkRunning),
		onOff(m.status.MailLocalRunning),
		onOff(m.status.MailMeshRunning),
		onOff(m.status.HubRunning),
		emptyIf(m.status.HubListen),
		onOff(m.status.TelegramRunning),
		statusLine.String(),
	)
}

func systemView(m model) string {
	return fmt.Sprintf(
		"System\n\nEdition: %s\nLocale: %s\nIdentity: %s\n\nPrivacy: MAC spoof %s, Tor %s, Strict %s\nEmulate privacy: %s",
		m.cfg.System.Edition,
		m.cfg.System.Locale,
		m.identity,
		onOff(m.cfg.Network.MACSpoof),
		onOff(m.cfg.Network.TorAlwaysOn || m.cfg.Network.Tor),
		onOff(m.cfg.Network.TorStrict),
		onOff(m.cfg.Emulate.PrivacyMode),
	)
}

func wifiAnim(tick int) string {
	steps := []string{"o    ", "o|   ", "o||  ", "o||| ", "o||||"}
	return steps[tick%len(steps)]
}

func spinner(tick int) string {
	frames := []string{"-", "\\", "|", "/"}
	return frames[tick%len(frames)]
}

func bar(value, maxVal, width int) string {
	if maxVal <= 0 {
		maxVal = 1
	}
	if value < 0 {
		value = 0
	}
	if value > maxVal {
		value = maxVal
	}
	filled := (value * width) / maxVal
	if filled > width {
		filled = width
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func emptyIf(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func netVPN(vpnType, profile string) string {
	if vpnType == "" && profile == "" {
		return "-"
	}
	if profile == "" {
		return vpnType
	}
	return fmt.Sprintf("%s (%s)", vpnType, profile)
}

func netProxy(engine, cfg string) string {
	if engine == "" && cfg == "" {
		return "-"
	}
	if cfg == "" {
		return engine
	}
	return fmt.Sprintf("%s (%s)", engine, cfg)
}

func usbAccessLabel(enabled, readOnly bool) string {
	if !enabled {
		return "off"
	}
	if readOnly {
		return "on (ro)"
	}
	return "on"
}

func usbStatusDefault(cfg config.Config) string {
	if cfg.Storage.USBEnabled {
		return "scan pending"
	}
	return "disabled"
}

func ctfSafeSummary(cfg config.Config) (string, []string) {
	var hints []string
	safe := true
	if !(cfg.Network.TorAlwaysOn || cfg.Network.TorStrict || cfg.Network.Mode == "vpn" || cfg.Network.Mode == "gateway" || cfg.Network.Mode == "proxy") {
		safe = false
		hints = append(hints, "no anonymizing")
	}
	if !cfg.Network.MACSpoof {
		safe = false
		hints = append(hints, "mac spoof off")
	}
	if cfg.Network.PortsOpen {
		hints = append(hints, "ports open")
	}
	if cfg.Storage.USBEnabled && !cfg.Storage.USBReadOnly {
		hints = append(hints, "usb rw")
	}
	if cfg.Storage.RAMOnly {
		hints = append(hints, "ram-only")
	}
	if safe {
		return "ok", hints
	}
	return "warn", hints
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Run(cfg config.Config, home string, identity string, svc *services.Manager) error {
	var usbEvents <-chan system.USBEvent
	var stop func()
	if runtime.GOOS == "linux" {
		usbEvents, stop = system.StartUSBWatcher(home, 2*time.Second)
	}
	if stop != nil {
		defer stop()
	}
	p := tea.NewProgram(initialModel(cfg, home, identity, svc, usbEvents))
	_, err := p.Run()
	return err
}

func scanNetworksCmd() tea.Cmd {
	return func() tea.Msg {
		nets, err := scanNetworks()
		return netScanMsg{Networks: nets, Err: err}
	}
}

func discoverMeshCmd(cfg config.Config) tea.Cmd {
	return func() tea.Msg {
		peers, err := mesh.DiscoverPeers(context.Background(), cfg.Mesh.DiscoveryPort, cfg.Mesh.DiscoveryKey)
		return meshDiscoverMsg{Peers: peers, Err: err}
	}
}

func statusCmd(svc *services.Manager) tea.Cmd {
	return func() tea.Msg {
		if svc == nil {
			return statusMsg{}
		}
		return statusMsg{Status: svc.Status()}
	}
}

func scanUSBsCmd() tea.Cmd {
	return func() tea.Msg {
		devs, err := system.ListUSBDevices()
		return usbScanMsg{Devices: devs, Err: err}
	}
}

func usbWatchCmd(ch <-chan system.USBEvent) tea.Cmd {
	return func() tea.Msg {
		if ch == nil {
			return usbEventMsg{}
		}
		ev, ok := <-ch
		if !ok {
			return usbEventMsg{}
		}
		return usbEventMsg{Event: ev}
	}
}

type wipeMsg struct {
	Err error
}

func wipeCmd(home, identityRel string) tea.Cmd {
	return func() tea.Msg {
		identityAbs := identityRel
		if identityRel != "" && home != "" && !filepath.IsAbs(identityRel) {
			identityAbs = paths.ResolveInHome(home, identityRel)
		}
		err := system.Wipe(home, identityAbs, system.WipeEmergency)
		return wipeMsg{Err: err}
	}
}

func scanNetworks() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("nmcli"); err != nil {
			return nil, fmt.Errorf("nmcli not found")
		}
		cmd := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL", "dev", "wifi")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return compactNetworks(lines), nil
	case "windows":
		cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=Bssid")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return parseNetshNetworks(out)
	default:
		return nil, fmt.Errorf("scan not supported on %s", runtime.GOOS)
	}
}

func compactNetworks(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		out = append(out, "(none)")
	}
	return out
}

func parseNetshNetworks(out []byte) ([]string, error) {
	var nets []string
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		text := strings.TrimSpace(string(line))
		lower := strings.ToLower(text)
		if (strings.Contains(lower, "ssid") && !strings.Contains(lower, "bssid")) || strings.Contains(lower, "имя сети") || strings.Contains(lower, "сеть") {
			parts := strings.SplitN(text, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				if name != "" {
					nets = append(nets, name)
				}
			}
		}
	}
	if len(nets) == 0 {
		nets = append(nets, "(none)")
	}
	return nets, nil
}
