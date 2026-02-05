package ui

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"ctfvault/internal/config"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type view int

const (
	viewHome view = iota
	viewNetwork
	viewStorage
	viewTools
	viewMesh
	viewSystem
)

const tickRate = 150 * time.Millisecond

type tickMsg time.Time

type model struct {
	cfg        config.Config
	home       string
	identity   string
	view       view
	cursor     int
	menu       []string
	tick       int
	width      int
	height     int
	networks   []string
	netStatus  string
	lastScanAt time.Time
}

type netScanMsg struct {
	Networks []string
	Err      error
}

func initialModel(cfg config.Config, home string, identity string) model {
	return model{
		cfg:       cfg,
		home:      home,
		identity:  identity,
		menu:      []string{"Home", "Network", "Storage", "Tools", "Mesh", "System"},
		view:      viewHome,
		netStatus: "scan pending",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), scanNetworksCmd())
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
			return m, tea.Batch(tickCmd(), scanNetworksCmd())
		}
		return m, tickCmd()
	case netScanMsg:
		if msg.Err != nil {
			m.netStatus = msg.Err.Error()
		} else {
			m.netStatus = fmt.Sprintf("found %d", len(msg.Networks))
			m.networks = msg.Networks
		}
		m.lastScanAt = time.Now()
	case tea.KeyMsg:
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
		case "1", "2", "3", "4", "5", "6":
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(m.menu) {
				m.cursor = idx
				m.view = view(idx)
			}
		}
	}
	return m, nil
}

func (m model) View() string {
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
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("v1 MVP - TUI")
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
	b.WriteString("Tor: " + onOff(m.cfg.Network.Tor) + "\n")

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
	case viewTools:
		return box.Render(toolsView(m))
	case viewMesh:
		return box.Render(meshView(m))
	case viewSystem:
		return box.Render(systemView(m))
	default:
		return box.Render("Unknown view")
	}
}

func footerView(m model) string {
	hint := "Arrows: navigate | 1-6: jump | q/esc: quit"
	return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(hint)
}

func homeView(m model) string {
	cpu := bar(m.tick%100, 100, 20)
	ram := bar((m.tick*3)%100, 100, 20)
	disk := bar((m.tick*7)%100, 100, 20)
	net := bar((m.tick*5)%100, 100, 20)

	return fmt.Sprintf(
		"Dashboard\n\nCPU  [%s]\nRAM  [%s]\nDisk [%s]\nNet  [%s]\n\nStatus: ready",
		cpu, ram, disk, net,
	)
}

func networkView(m model) string {
	scan := spinner(m.tick)
	netLines := "no networks detected"
	if len(m.networks) > 0 {
		netLines = strings.Join(m.networks, "\n")
	}
	return fmt.Sprintf(
		"Network\n\nScan: %s (%s)\n\nProfiles:\n- DNS: %s\n- MAC spoof: %s\n- Ports open: %s\n\nNetworks:\n%s\n",
		scan,
		m.netStatus,
		m.cfg.Network.DNSProfile,
		onOff(m.cfg.Network.MACSpoof),
		onOff(m.cfg.Network.PortsOpen),
		netLines,
	)
}

func storageView(m model) string {
	return fmt.Sprintf(
		"Storage\n\nHome: %s\nPersistent: %s\nShared: %s\n\nActions:\n- ctfvault wipe\n- ctfvault wipe --emergency\n",
		m.home,
		onOff(m.cfg.Storage.Persistent),
		onOff(m.cfg.Storage.Shared),
	)
}

func toolsView(m model) string {
	return "Tools\n\n- Crypto\n- Web\n- Pwn\n- Forensics\n- Reversing\n- Wireless\n\nStatus: not installed (use installer/wizard)"
}

func meshView(m model) string {
	return "Mesh\n\nStatus: direct mode\nSend/Recv: available\nRelay/Onion: disabled in V1"
}

func systemView(m model) string {
	return fmt.Sprintf(
		"System\n\nEdition: %s\nLocale: %s\nIdentity: %s\n\nPrivacy: MAC spoof %s, Tor %s",
		m.cfg.System.Edition,
		m.cfg.System.Locale,
		m.identity,
		onOff(m.cfg.Network.MACSpoof),
		onOff(m.cfg.Network.Tor),
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Run(cfg config.Config, home string, identity string) error {
	p := tea.NewProgram(initialModel(cfg, home, identity))
	_, err := p.Run()
	return err
}

func scanNetworksCmd() tea.Cmd {
	return func() tea.Msg {
		nets, err := scanNetworks()
		return netScanMsg{Networks: nets, Err: err}
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
		return parseNetshNetworks(out), nil
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
		if strings.HasPrefix(text, "SSID ") {
			parts := strings.SplitN(text, ":", 2)
			if len(parts) == 2 {
				nets = append(nets, strings.TrimSpace(parts[1]))
			}
		}
	}
	if len(nets) == 0 {
		nets = append(nets, "(none)")
	}
	return nets, nil
}
