package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gargoyle/internal/config"
	"gargoyle/internal/mesh"
	"gargoyle/internal/paths"
	"gargoyle/internal/services"
	"gargoyle/internal/syncer"
	"gargoyle/internal/system"
	"gargoyle/internal/version"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

type view int

const (
	viewHome view = iota
	viewActions
	viewNetwork
	viewStorage
	viewEmulate
	viewHub
	viewTools
	viewMesh
	viewHotspot
	viewGateway
	viewSync
	viewBroadcast
	viewWarnings
	viewStatus
	viewTerminal
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
	cfg             config.Config
	home            string
	identity        string
	view            view
	cursor          int
	menu            []string
	tick            int
	width           int
	height          int
	networks        []string
	netStatus       string
	lastScanAt      time.Time
	usbDevices      []string
	usbStatus       string
	hotspotStatus   string
	meshPeers       []string
	meshErr         string
	services        *services.Manager
	status          services.Status
	lastMsg         string
	lastErr         string
	confirmWipe     bool
	usbLocked       bool
	usbEvents       <-chan system.USBEvent
	bossMode        bool
	broadcastActive bool
	broadcastInput  string
	broadcastAlert  bool
	showHelp        bool
	torStrictActive bool
	torStrictErr    string
	pendingQuit     bool
	inMenu          bool
	metrics         metricsSnapshot
	lastNetRx       uint64
	lastNetTx       uint64
	lastMetricsAt   time.Time
	actions         []config.QuickAction
	actionsCursor   int
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

type hotspotStatusMsg struct {
	Status string
	Err    error
}

type usbEventMsg struct {
	Event system.USBEvent
}

type meshDiscoverMsg struct {
	Peers []string
	Err   error
}

type broadcastResultMsg struct {
	Count int
	Err   error
}

type torCheckMsg struct {
	Active bool
	Err    error
}

type shellDoneMsg struct {
	Err error
}

type metricsSnapshot struct {
	CPUPercent  float64
	MemUsed     uint64
	MemTotal    uint64
	MemPercent  float64
	DiskUsed    uint64
	DiskTotal   uint64
	DiskPercent float64
	NetRxBytes  uint64
	NetTxBytes  uint64
	NetRxRate   float64
	NetTxRate   float64
}

type metricsMsg struct {
	Stats metricsSnapshot
	Err   error
}

func initialModel(cfg config.Config, home string, identity string, svc *services.Manager, usbEvents <-chan system.USBEvent) model {
	return model{
		cfg:           cfg,
		home:          home,
		identity:      identity,
		menu:          []string{"Home", "Actions", "Network", "Storage", "Emulate", "Hub", "Tools", "Mesh", "Hotspot", "Gateway", "Sync", "Broadcast", "Warnings", "Status", "Terminal", "System"},
		view:          viewHome,
		netStatus:     "scan pending",
		usbStatus:     usbStatusDefault(cfg),
		hotspotStatus: "unknown",
		services:      svc,
		usbEvents:     usbEvents,
		inMenu:        true,
		actions:       cfg.QuickActionsFor(cfg.System.Mode),
	}
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd(), scanNetworksCmd(), statusCmd(m.services), metricsCmd(m.home)}
	if m.cfg.Storage.USBEnabled {
		cmds = append(cmds, scanUSBsCmd())
	}
	if runtime.GOOS == "linux" {
		cmds = append(cmds, hotspotStatusCmd())
	}
	if m.usbEvents != nil {
		cmds = append(cmds, usbWatchCmd(m.usbEvents))
	}
	if m.cfg.Mesh.DiscoveryEnabled {
		cmds = append(cmds, discoverMeshCmd(m.cfg))
	}
	if m.cfg.Network.TorStrict {
		cmds = append(cmds, torCheckCmd())
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
		cmds := []tea.Cmd{tickCmd(), statusCmd(m.services)}
		if m.tick%7 == 0 {
			cmds = append(cmds, metricsCmd(m.home))
		}
		if m.tick%20 == 0 {
			cmds = append(cmds, scanNetworksCmd())
			if m.cfg.Storage.USBEnabled {
				cmds = append(cmds, scanUSBsCmd())
			}
			if runtime.GOOS == "linux" {
				cmds = append(cmds, hotspotStatusCmd())
			}
			if m.cfg.Network.TorStrict {
				cmds = append(cmds, torCheckCmd())
			}
		}
		return m, tea.Batch(cmds...)
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
	case hotspotStatusMsg:
		if msg.Err != nil {
			m.hotspotStatus = msg.Err.Error()
		} else {
			m.hotspotStatus = msg.Status
		}
	case statusMsg:
		m.status = msg.Status
	case wipeMsg:
		if msg.Err != nil {
			m.lastErr = msg.Err.Error()
		} else {
			m.lastMsg = "emergency wipe completed"
			m.usbLocked = false
			if m.pendingQuit {
				return m, tea.Quit
			}
		}
	case usbEventMsg:
		if msg.Event.Removed {
			if m.cfg.Storage.AutoWipeOnRemove {
				m.lastErr = ""
				m.lastMsg = "USB removed: auto wipe"
				return m, wipeCmd(m.home, m.cfg.Security.IdentityKeyPath)
			}
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
	case broadcastResultMsg:
		if msg.Err != nil {
			m.lastErr = msg.Err.Error()
			m.lastMsg = ""
		} else {
			m.lastErr = ""
			m.lastMsg = fmt.Sprintf("broadcast sent (%d peers)", msg.Count)
		}
	case torCheckMsg:
		if msg.Err != nil {
			m.torStrictErr = msg.Err.Error()
			m.torStrictActive = false
		} else {
			m.torStrictErr = ""
			m.torStrictActive = msg.Active
		}
	case metricsMsg:
		if msg.Err != nil {
			m.lastErr = msg.Err.Error()
			break
		}
		now := time.Now()
		if !m.lastMetricsAt.IsZero() {
			dt := now.Sub(m.lastMetricsAt).Seconds()
			if dt > 0 {
				m.metrics.NetRxRate = float64(msg.Stats.NetRxBytes-m.lastNetRx) / dt
				m.metrics.NetTxRate = float64(msg.Stats.NetTxBytes-m.lastNetTx) / dt
			}
		}
		m.lastNetRx = msg.Stats.NetRxBytes
		m.lastNetTx = msg.Stats.NetTxBytes
		m.lastMetricsAt = now
		msg.Stats.NetRxRate = m.metrics.NetRxRate
		msg.Stats.NetTxRate = m.metrics.NetTxRate
		m.metrics = msg.Stats
	case shellDoneMsg:
		if msg.Err != nil {
			m.lastErr = fmt.Sprintf("shell: %v", msg.Err)
		} else {
			m.lastErr = ""
			m.lastMsg = "shell closed"
		}
	case tea.KeyMsg:
		if m.cfg.UI.BossKey && msg.String() == "f10" {
			m.bossMode = !m.bossMode
			return m, nil
		}
		if msg.String() == "?" || msg.String() == "H" {
			m.showHelp = !m.showHelp
			return m, nil
		}
		if m.broadcastActive {
			switch msg.Type {
			case tea.KeyEsc:
				m.broadcastActive = false
				m.broadcastInput = ""
				return m, nil
			case tea.KeyEnter:
				text := strings.TrimSpace(m.broadcastInput)
				m.broadcastActive = false
				m.broadcastInput = ""
				if text == "" {
					m.lastErr = "broadcast: empty message"
					m.lastMsg = ""
					return m, nil
				}
				return m, broadcastCmd(m.cfg, text, m.broadcastAlert)
			case tea.KeyBackspace, tea.KeyDelete:
				m.broadcastInput = trimLastRune(m.broadcastInput)
				return m, nil
			case tea.KeyRunes:
				m.broadcastInput += string(msg.Runes)
				return m, nil
			default:
				return m, nil
			}
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
		if m.view == viewHotspot {
			switch msg.String() {
			case "h":
				m.lastErr = ""
				m.lastMsg = ""
				if runtime.GOOS != "linux" {
					m.lastErr = "hotspot: Linux only"
					break
				}
				if strings.Contains(m.hotspotStatus, "active") {
					if err := system.StopHotspot(); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = "hotspot stopped"
					}
				} else {
					cfg := system.HotspotConfig{
						SSID:     m.cfg.Mesh.Hotspot.SSID,
						Password: m.cfg.Mesh.Hotspot.Password,
						Ifname:   m.cfg.Mesh.Hotspot.Ifname,
						Shared:   m.cfg.Mesh.Hotspot.Shared,
					}
					if err := system.StartHotspot(cfg); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = "hotspot started"
					}
				}
				return m, hotspotStatusCmd()
			}
		}
		if m.view == viewGateway {
			switch msg.String() {
			case "g":
				m.lastErr = ""
				m.lastMsg = ""
				if m.services == nil {
					m.lastErr = "services unavailable"
					break
				}
				if m.status.MeshGatewayRunning {
					if err := m.services.StopMeshGateway(); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = "mesh gateway stopped"
					}
				} else {
					listen := ":1090"
					upstream := "127.0.0.1:1080"
					if err := m.services.StartMeshGateway(listen, upstream); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = fmt.Sprintf("mesh gateway %s -> %s", listen, upstream)
					}
				}
			}
		}
		if m.view == viewSync {
			switch msg.String() {
			case "y":
				m.lastErr = ""
				m.lastMsg = ""
				if m.services == nil {
					m.lastErr = "services unavailable"
					break
				}
				if m.status.SyncRunning {
					if err := m.services.StopSync(); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = "sync stopped"
					}
				} else {
					if m.cfg.Sync.Target == "" || m.cfg.Sync.Dir == "" {
						m.lastErr = "sync target/dir not configured"
						break
					}
					opts := syncer.Options{
						Dir:           m.cfg.Sync.Dir,
						Target:        m.cfg.Sync.Target,
						PSK:           m.cfg.Sync.PSK,
						PSKFile:       m.cfg.Sync.PSKFile,
						Transport:     m.cfg.Sync.Transport,
						PaddingBytes:  m.cfg.Sync.PaddingBytes,
						Depth:         m.cfg.Sync.Depth,
						MetadataLevel: m.cfg.Mesh.MetadataLevel,
					}
					if err := m.services.StartSync(opts); err != nil {
						m.lastErr = err.Error()
					} else {
						m.lastMsg = "sync started"
					}
				}
			}
		}
		if m.view == viewBroadcast {
			switch msg.String() {
			case "b":
				m.broadcastActive = true
				m.broadcastInput = ""
				return m, nil
			case "a":
				m.broadcastAlert = !m.broadcastAlert
				return m, nil
			}
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
		case "ctrl+c", "q":
			if m.cfg.Storage.AutoWipeOnExit {
				m.pendingQuit = true
				m.lastMsg = "exit: auto wipe"
				return m, wipeCmd(m.home, m.cfg.Security.IdentityKeyPath)
			}
			return m, tea.Quit
		case "enter", "right":
			if m.inMenu {
				m.inMenu = false
				m.view = view(m.cursor)
				return m, nil
			}
			if msg.String() == "enter" {
				if m.view == viewActions {
					if len(m.actions) == 0 {
						m.lastErr = "no quick actions configured"
						m.lastMsg = ""
						break
					}
					if m.actionsCursor < 0 || m.actionsCursor >= len(m.actions) {
						m.lastErr = "invalid action selection"
						m.lastMsg = ""
						break
					}
					return m, openActionTerminalCmd(m.actions[m.actionsCursor], m.home)
				}
				return m, openSectionTerminalCmd(m.view, m.home)
			}
		case "left", "esc":
			if !m.inMenu {
				m.inMenu = true
				return m, nil
			}
		case "c":
			return m, shellCmd(m.home)
		case "up", "k":
			if m.inMenu && m.cursor > 0 {
				m.cursor--
				m.view = view(m.cursor)
			} else if !m.inMenu && m.view == viewActions && m.actionsCursor > 0 {
				m.actionsCursor--
			}
		case "down", "j":
			if m.inMenu && m.cursor < len(m.menu)-1 {
				m.cursor++
				m.view = view(m.cursor)
			} else if !m.inMenu && m.view == viewActions && m.actionsCursor < len(m.actions)-1 {
				m.actionsCursor++
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
	if m.showHelp {
		appStyle := lipgloss.NewStyle().Padding(1, 2)
		header := headerView(m)
		help := helpView(m)
		footer := footerView(m)
		layout := lipgloss.JoinVertical(lipgloss.Left, header, help, footer)
		return appStyle.Render(layout)
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
	if m.inMenu {
		b.WriteString("Menu (focus)\n\n")
	} else {
		b.WriteString("Menu (left/esc to return)\n\n")
	}
	for i, item := range m.menu {
		cursor := " "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			cursor = ">"
			if m.inMenu {
				style = style.Bold(true).Foreground(lipgloss.Color("229"))
			} else {
				style = style.Foreground(lipgloss.Color("245"))
			}
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
	case viewActions:
		return box.Render(actionsView(m))
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
	case viewHotspot:
		return box.Render(hotspotView(m))
	case viewGateway:
		return box.Render(gatewayView(m))
	case viewSync:
		return box.Render(syncView(m))
	case viewBroadcast:
		return box.Render(broadcastView(m))
	case viewWarnings:
		return box.Render(warningsView(m))
	case viewStatus:
		return box.Render(statusView(m))
	case viewTerminal:
		return box.Render(terminalView(m))
	case viewSystem:
		return box.Render(systemView(m))
	default:
		return box.Render("Unknown view")
	}
}

func footerView(m model) string {
	hint := "Up/Down: menu | Enter/Right: open | Left/Esc: back | r: relay | d: doh | h: hotspot | g: gateway | y: sync | b: broadcast | c: shell | ?: help | f10: boss | q: quit"
	return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(hint)
}

func warningsView(m model) string {
	warnings := collectWarnings(m)
	if len(warnings) == 0 {
		return "Warnings\n\nNo active risks detected."
	}
	return "Warnings\n\n- " + strings.Join(warnings, "\n- ")
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
	cpu := bar(int(m.metrics.CPUPercent), 100, 20)
	ram := bar(int(m.metrics.MemPercent), 100, 20)
	disk := bar(int(m.metrics.DiskPercent), 100, 20)
	netRate := fmt.Sprintf("RX %.0f KB/s | TX %.0f KB/s", m.metrics.NetRxRate/1024, m.metrics.NetTxRate/1024)
	ctfLabel, ctfHints := ctfSafeSummary(m.cfg)
	hintText := "-"
	if len(ctfHints) > 0 {
		hintText = strings.Join(ctfHints, "; ")
	}
	actionsInfo := "none"
	if len(m.actions) > 0 {
		actionsInfo = fmt.Sprintf("%d configured", len(m.actions))
	}

	banner := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Render(gargoyleBanner)

	return fmt.Sprintf(
		"%s\n\nDashboard\n\nCPU  [%s] %.1f%%\nRAM  [%s] %s / %s\nDisk [%s] %s / %s\nNet  %s\n\nQuick actions: %s\nCTF-safe: %s\nHints: %s",
		banner,
		cpu, m.metrics.CPUPercent,
		ram, fmtBytes(m.metrics.MemUsed), fmtBytes(m.metrics.MemTotal),
		disk, fmtBytes(m.metrics.DiskUsed), fmtBytes(m.metrics.DiskTotal),
		netRate,
		actionsInfo,
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

func collectWarnings(m model) []string {
	var out []string
	torOn := m.cfg.Network.Tor || m.cfg.Network.TorAlwaysOn
	if !torOn {
		out = append(out, "Tor is OFF")
	}
	if m.cfg.Network.TorStrict {
		if m.torStrictErr != "" {
			out = append(out, "Tor strict check failed: "+m.torStrictErr)
		} else if !m.torStrictActive {
			out = append(out, "Tor strict enabled, kill-switch not active")
		}
	}
	if m.cfg.Storage.USBEnabled && !m.cfg.Storage.USBReadOnly {
		out = append(out, "USB read-write enabled")
	}
	if m.cfg.Network.PortsOpen {
		out = append(out, "Ports open by default")
	}
	if !m.cfg.Network.MACSpoof {
		out = append(out, "MAC spoofing disabled")
	}
	return out
}

func hotspotView(m model) string {
	status := m.hotspotStatus
	if status == "" {
		status = "unknown"
	}
	return fmt.Sprintf(
		"Hotspot / NAT\n\nStatus: %s\nSSID: %s\nIfname: %s\nShared: %s\n\nActions:\n- h: start/stop hotspot\n- CLI: gargoyle hotspot start --ssid ... --password ... --shared\n",
		status,
		emptyIf(m.cfg.Mesh.Hotspot.SSID),
		emptyIf(m.cfg.Mesh.Hotspot.Ifname),
		onOff(m.cfg.Mesh.Hotspot.Shared),
	)
}

func gatewayView(m model) string {
	state := onOff(m.status.MeshGatewayRunning)
	return fmt.Sprintf(
		"Mesh Gateway\n\nRunning: %s\nListen: %s\nUpstream: %s\n\nActions:\n- g: start/stop gateway\n- CLI: gargoyle mesh gateway start --listen :1090 --upstream 127.0.0.1:1080\n",
		state,
		emptyIf(m.status.MeshGatewayListen),
		emptyIf(m.status.MeshGatewayUpstream),
	)
}

func syncView(m model) string {
	state := onOff(m.status.SyncRunning)
	return fmt.Sprintf(
		"Sync (Loot auto-send)\n\nRunning: %s\nDir: %s\nTarget: %s\n\nActions:\n- y: start/stop sync\n- CLI: gargoyle sync start --dir ./loot --target host:port\n",
		state,
		emptyIf(m.cfg.Sync.Dir),
		emptyIf(m.cfg.Sync.Target),
	)
}

func broadcastView(m model) string {
	alert := onOff(m.broadcastAlert)
	line := "Press b to compose broadcast."
	if m.broadcastActive {
		line = fmt.Sprintf("Message: %s", m.broadcastInput)
	}
	return fmt.Sprintf(
		"Broadcast\n\nAlert mode: %s\n%s\n\nActions:\n- b: compose/send\n- a: toggle alert\n",
		alert,
		line,
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
		"Status\n\nRelay: %s\nListen: %s\nPID: %s\nError: %s\n\nDoH: %s\nListen: %s\nURL: %s\nPID: %d\nError: %s\n\nEmulate: %s (%s)\nTunnel: %s (%s)\nProxy: %s (%s)\nMail: sink %s / local %s / mesh %s\nHub: %s (%s)\nMeshGateway: %s (%s -> %s)\nSync: %s (dir=%s, target=%s)\nTelegram: %s\n\n%s",
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
		onOff(m.status.MeshGatewayRunning),
		emptyIf(m.status.MeshGatewayListen),
		emptyIf(m.status.MeshGatewayUpstream),
		onOff(m.status.SyncRunning),
		emptyIf(m.status.SyncDir),
		emptyIf(m.status.SyncTarget),
		onOff(m.status.TelegramRunning),
		statusLine.String(),
	)
}

func actionsView(m model) string {
	if len(m.actions) == 0 {
		return "Quick Actions\n\nNo actions configured for this profile.\nEdit gargoyle.yaml -> ui.quick_actions."
	}
	var b strings.Builder
	b.WriteString("Quick Actions\n\n")
	for i, action := range m.actions {
		cursor := " "
		if i == m.actionsCursor {
			cursor = ">"
		}
		b.WriteString(fmt.Sprintf("%s %s\n    %s\n", cursor, action.Label, action.Cmd))
	}
	b.WriteString("\nEnter: run in new terminal")
	return b.String()
}

func terminalView(m model) string {
	return fmt.Sprintf(
		"Terminal\n\nPress Enter to open a new terminal window.\nThe terminal inherits GARGOYLE_HOME:\n%s\n\nExamples:\n- gargoyle status\n- gargoyle mesh status\n- gargoyle doctor\n",
		emptyIf(m.home),
	)
}

func systemView(m model) string {
	return fmt.Sprintf(
		"System\n\nEdition: %s\nLocale: %s\nMode: %s\nIdentity: %s\n\nPrivacy: MAC spoof %s, Tor %s, Strict %s\nEmulate privacy: %s",
		m.cfg.System.Edition,
		m.cfg.System.Locale,
		m.cfg.System.Mode,
		m.identity,
		onOff(m.cfg.Network.MACSpoof),
		onOff(m.cfg.Network.TorAlwaysOn || m.cfg.Network.Tor),
		onOff(m.cfg.Network.TorStrict),
		onOff(m.cfg.Emulate.PrivacyMode),
	)
}

func helpView(m model) string {
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Width(max(60, m.width-10))
	text := "Help\n\n" +
		"Navigation:\n" +
		"- Up/Down: move menu\n" +
		"- Enter/Right: open view\n" +
		"- Left/Esc: back to menu\n" +
		"- 1-9: jump to section\n" +
		"- ?: toggle help\n\n" +
		"Global hotkeys:\n" +
		"- r: relay start/stop\n" +
		"- d: DoH start/stop\n" +
		"- c: open shell (exit to return)\n" +
		"- x: emergency wipe (double-press)\n" +
		"- f10: boss key\n\n" +
		"Screens:\n" +
		"- Emulate: f (firefox), t (tor), o (file manager), s (stop)\n" +
		"- Hotspot: h start/stop\n" +
		"- Gateway: g start/stop\n" +
		"- Sync: y start/stop\n" +
		"- Broadcast: b compose, a alert toggle\n\n" +
		"- Actions: Enter runs selected quick action\n\n" +
		"CLI help: gargoyle help / gargoyle help-gargoyle"
	return box.Render(text)
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
	if home != "" {
		_ = os.Setenv(paths.EnvHome, home)
	}
	p := tea.NewProgram(initialModel(cfg, home, identity, svc, usbEvents))
	_, err := p.Run()
	return err
}

func shellCmd(home string) tea.Cmd {
	shell := ""
	var args []string
	switch runtime.GOOS {
	case "windows":
		shell = "cmd.exe"
		args = []string{}
	default:
		shell = "bash"
		args = []string{"-l"}
	}
	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", paths.EnvHome, home))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return shellDoneMsg{Err: err}
	})
}

func metricsCmd(home string) tea.Cmd {
	return func() tea.Msg {
		if home == "" {
			home = "."
		}
		cpuPct, err := cpu.Percent(0, false)
		if err != nil || len(cpuPct) == 0 {
			return metricsMsg{Err: fmt.Errorf("cpu: %v", err)}
		}
		memStat, err := mem.VirtualMemory()
		if err != nil {
			return metricsMsg{Err: fmt.Errorf("mem: %v", err)}
		}
		diskStat, err := disk.Usage(home)
		if err != nil {
			return metricsMsg{Err: fmt.Errorf("disk: %v", err)}
		}
		netStat, err := gnet.IOCounters(false)
		if err != nil {
			return metricsMsg{Err: fmt.Errorf("net: %v", err)}
		}
		var rx, tx uint64
		for _, n := range netStat {
			rx += n.BytesRecv
			tx += n.BytesSent
		}
		snap := metricsSnapshot{
			CPUPercent:  cpuPct[0],
			MemUsed:     memStat.Used,
			MemTotal:    memStat.Total,
			MemPercent:  memStat.UsedPercent,
			DiskUsed:    diskStat.Used,
			DiskTotal:   diskStat.Total,
			DiskPercent: diskStat.UsedPercent,
			NetRxBytes:  rx,
			NetTxBytes:  tx,
		}
		return metricsMsg{Stats: snap}
	}
}

func openSectionTerminalCmd(v view, home string) tea.Cmd {
	if v == viewTerminal {
		return openShellTerminalCmd()
	}
	cmdline := sectionCommand(v, home)
	if cmdline == "" {
		return func() tea.Msg { return shellDoneMsg{Err: errors.New("no command for this view")} }
	}
	return openCmdInTerminal(cmdline)
}

func openActionTerminalCmd(action config.QuickAction, home string) tea.Cmd {
	cmdline := strings.TrimSpace(action.Cmd)
	if cmdline == "" {
		return func() tea.Msg { return shellDoneMsg{Err: errors.New("action cmd is empty")} }
	}
	if home != "" {
		if runtime.GOOS == "windows" {
			cmdline = fmt.Sprintf("set %s=%s && %s", paths.EnvHome, home, cmdline)
		} else {
			cmdline = fmt.Sprintf("%s=%q %s", paths.EnvHome, home, cmdline)
		}
	}
	return openCmdInTerminal(cmdline)
}

func openShellTerminalCmd() tea.Cmd {
	if runtime.GOOS == "windows" {
		return tea.ExecProcess(exec.Command("cmd.exe", "/c", "start", "Gargoyle Shell", "cmd", "/k"), func(err error) tea.Msg {
			return shellDoneMsg{Err: err}
		})
	}
	candidates := []struct {
		bin  string
		args []string
	}{
		{"x-terminal-emulator", []string{"-e", "bash", "-l"}},
		{"gnome-terminal", []string{"--", "bash", "-l"}},
		{"konsole", []string{"-e", "bash", "-l"}},
		{"xfce4-terminal", []string{"-e", "bash", "-l"}},
		{"xterm", []string{"-e", "bash", "-l"}},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err == nil {
			return tea.ExecProcess(exec.Command(c.bin, c.args...), func(err error) tea.Msg {
				return shellDoneMsg{Err: err}
			})
		}
	}
	return func() tea.Msg { return shellDoneMsg{Err: errors.New("no terminal emulator found")} }
}

func openCmdInTerminal(cmdline string) tea.Cmd {
	if runtime.GOOS == "windows" {
		return tea.ExecProcess(exec.Command("cmd.exe", "/c", "start", "Gargoyle", "cmd", "/k", cmdline), func(err error) tea.Msg {
			return shellDoneMsg{Err: err}
		})
	}
	term, args, err := pickTerminal(cmdline)
	if err != nil {
		return func() tea.Msg { return shellDoneMsg{Err: err} }
	}
	return tea.ExecProcess(exec.Command(term, args...), func(err error) tea.Msg {
		return shellDoneMsg{Err: err}
	})
}

func sectionCommand(v view, home string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	homeArg := fmt.Sprintf("--home %q", home)
	base := fmt.Sprintf("%q %s", exe, homeArg)
	switch v {
	case viewHome:
		return base + " status"
	case viewActions:
		return ""
	case viewNetwork:
		return base + " doctor"
	case viewStorage:
		return base + " status"
	case viewEmulate:
		return base + " emulate status"
	case viewHub:
		return base + " hub status"
	case viewTools:
		return base + " tools list"
	case viewMesh:
		return base + " mesh status"
	case viewHotspot:
		return base + " hotspot status"
	case viewSync:
		return base + " sync status"
	case viewWarnings:
		return base + " status"
	case viewStatus:
		return base + " status"
	case viewTerminal:
		return ""
	case viewSystem:
		return base + " version"
	default:
		return ""
	}
}

func pickTerminal(cmdline string) (string, []string, error) {
	candidates := []struct {
		bin  string
		args []string
	}{
		{"x-terminal-emulator", []string{"-e", cmdline}},
		{"gnome-terminal", []string{"--", "bash", "-lc", cmdline}},
		{"konsole", []string{"-e", "bash", "-lc", cmdline}},
		{"xfce4-terminal", []string{"--command", "bash -lc " + cmdline}},
		{"xterm", []string{"-e", cmdline}},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err == nil {
			return c.bin, c.args, nil
		}
	}
	return "", nil, errors.New("no terminal emulator found")
}

func fmtBytes(v uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case v >= GB:
		return fmt.Sprintf("%.1f GB", float64(v)/GB)
	case v >= MB:
		return fmt.Sprintf("%.1f MB", float64(v)/MB)
	case v >= KB:
		return fmt.Sprintf("%.1f KB", float64(v)/KB)
	default:
		return fmt.Sprintf("%d B", v)
	}
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

func torCheckCmd() tea.Cmd {
	return func() tea.Msg {
		active, err := system.TorKillswitchActive()
		return torCheckMsg{Active: active, Err: err}
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

func hotspotStatusCmd() tea.Cmd {
	return func() tea.Msg {
		status, err := system.HotspotStatus()
		return hotspotStatusMsg{Status: status, Err: err}
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

func broadcastCmd(cfg config.Config, message string, alert bool) tea.Cmd {
	return func() tea.Msg {
		if cfg.Mesh.OnionOnly {
			return broadcastResultMsg{Err: errors.New("broadcast disabled in onion-only mode")}
		}
		if !cfg.Mesh.DiscoveryEnabled {
			return broadcastResultMsg{Err: errors.New("mesh discovery disabled")}
		}
		peers, err := mesh.DiscoverPeers(context.Background(), cfg.Mesh.DiscoveryPort, cfg.Mesh.DiscoveryKey)
		if err != nil {
			return broadcastResultMsg{Err: err}
		}
		if len(peers) == 0 {
			return broadcastResultMsg{Err: errors.New("no peers found")}
		}
		op := "chat"
		if alert {
			op = "alert"
		}
		opts := mesh.MessageOptions{
			PSK:          cfg.Mesh.ChatPSK,
			PSKFile:      cfg.Mesh.ChatPSKFile,
			Transport:    cfg.Mesh.Transport,
			PaddingBytes: cfg.Mesh.PaddingBytes,
			Security:     true,
			Depth:        cfg.Mesh.OnionDepth,
			Op:           op,
		}
		okCount := 0
		for _, peer := range peers {
			opts.Target = mergeHostPort(peer, cfg.Mesh.ChatListen)
			if err := mesh.SendMessage(context.Background(), message, opts); err == nil {
				okCount++
			}
		}
		if okCount == 0 {
			return broadcastResultMsg{Err: errors.New("broadcast failed")}
		}
		return broadcastResultMsg{Count: okCount}
	}
}

func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return string(r[:len(r)-1])
}

func mergeHostPort(peer string, listen string) string {
	host := peer
	if h, _, err := net.SplitHostPort(peer); err == nil {
		host = h
	}
	port := ""
	if strings.HasPrefix(listen, ":") {
		port = strings.TrimPrefix(listen, ":")
	} else if _, p, err := net.SplitHostPort(listen); err == nil {
		port = p
	}
	if port == "" {
		return peer
	}
	return net.JoinHostPort(host, port)
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
