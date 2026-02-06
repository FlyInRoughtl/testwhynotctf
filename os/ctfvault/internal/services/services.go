package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gargoyle/internal/config"
	"gargoyle/internal/doh"
	"gargoyle/internal/emulate"
	"gargoyle/internal/hub"
	"gargoyle/internal/mail"
	"gargoyle/internal/mesh"
	"gargoyle/internal/meshgateway"
	"gargoyle/internal/system"
	"gargoyle/internal/syncer"
	"gargoyle/internal/telegram"
	"gargoyle/internal/proxy"
	"gargoyle/internal/tunnel"
)

type Manager struct {
	mu sync.Mutex

	relayRunning bool
	relayListen  string
	relayErr     string
	relayStop    func()

	dohRunning bool
	dohListen  string
	dohURL     string
	dohPID     int
	dohErr     string
	dohStop    func() error

	emulateRunner *emulate.Runner
	emulateErr    string

	tunnelRunning bool
	tunnelType    string
	tunnelServer  string
	tunnelService string
	tunnelPort    int
	tunnelPID     int
	tunnelErr     string
	tunnelStop    func() error

	mailSinkRunning bool
	mailSinkListen  string
	mailSinkErr     string
	mailSinkStop    func() error
	mailLocalErr    string
	mailLocalOn     bool
	mailMeshRunning bool
	mailMeshListen  string
	mailMeshErr     string
	mailMeshStop    func() error

	hubRunning bool
	hubListen  string
	hubErr     string
	hubStop    func() error

	proxyRunning bool
	proxyEngine  string
	proxyConfig  string
	proxyPID     int
	proxyErr     string
	proxyStop    func() error

	meshGatewayRunning bool
	meshGatewayListen  string
	meshGatewayUpstream string
	meshGatewayErr     string
	meshGatewayStop    func() error

	syncRunning bool
	syncTarget  string
	syncDir     string
	syncErr     string
	syncStop    func() error

	telegramRunning bool
	telegramErr     string
	telegramBot     *telegram.Bot
}

func New() *Manager {
	return &Manager{
		emulateRunner: &emulate.Runner{},
	}
}

func (m *Manager) StartRelay(listen string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.relayRunning {
		return errors.New("relay already running")
	}

	stop, errCh := mesh.RunRelayAsync(listen)
	m.relayRunning = true
	m.relayListen = listen
	m.relayErr = ""
	m.relayStop = stop

	go func() {
		err := <-errCh
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil {
			m.relayErr = err.Error()
		}
		m.relayRunning = false
		m.relayStop = nil
	}()

	return nil
}

func (m *Manager) StopRelay() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.relayRunning || m.relayStop == nil {
		return errors.New("relay not running")
	}
	m.relayStop()
	m.relayRunning = false
	m.relayStop = nil
	return nil
}

func (m *Manager) StartDoH(listen, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.dohRunning {
		return errors.New("doh already running")
	}

	runner := doh.Runner{Listen: listen, URL: url}
	cmd, stop, err := runner.Start()
	if err != nil {
		m.dohErr = err.Error()
		return err
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	m.dohRunning = true
	m.dohListen = listen
	m.dohURL = url
	m.dohPID = pid
	m.dohErr = ""
	m.dohStop = stop

	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.dohRunning = false
		m.dohStop = nil
	}()

	return nil
}

func (m *Manager) StopDoH() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dohRunning || m.dohStop == nil {
		return errors.New("doh not running")
	}
	if err := m.dohStop(); err != nil {
		m.dohErr = err.Error()
		return err
	}
	m.dohRunning = false
	m.dohStop = nil
	return nil
}

func (m *Manager) StartEmulate(app string, args []string, cfg config.EmulateConfig, home string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.emulateRunner == nil {
		m.emulateRunner = &emulate.Runner{}
	}
	m.emulateErr = ""
	return m.emulateRunner.Start(app, args, cfg, home)
}

func (m *Manager) StopEmulate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.emulateRunner == nil {
		return errors.New("emulate not running")
	}
	return m.emulateRunner.Stop()
}

func (m *Manager) StartTunnel(cfg config.TunnelConfig, service string, port int, home string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnelRunning {
		return errors.New("tunnel already running")
	}
	if cfg.Type == "relay" {
		return errors.New("tunnel relay mode not implemented")
	}
	if cfg.Type == "wss" {
		local := cfg.LocalIP
		if local == "" {
			local = "127.0.0.1"
		}
		target := fmt.Sprintf("%s:%d", local, port)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			err := tunnel.RunWSSClient(ctx, tunnel.WSSClient{
				Server:  cfg.Server,
				Service: service,
				Token:   cfg.Token,
				Local:   target,
			})
			if err != nil {
				m.mu.Lock()
				m.tunnelErr = err.Error()
				m.mu.Unlock()
			}
		}()
		m.tunnelRunning = true
		m.tunnelType = cfg.Type
		m.tunnelServer = cfg.Server
		m.tunnelService = service
		m.tunnelPort = port
		m.tunnelPID = 0
		m.tunnelErr = ""
		m.tunnelStop = func() error {
			cancel()
			return nil
		}
		return nil
	}
	cmd, stop, err := tunnel.StartFRP(cfg.Server, service, port, cfg.Token, cfg.LocalIP, home)
	if err != nil {
		m.tunnelErr = err.Error()
		return err
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	m.tunnelRunning = true
	m.tunnelType = cfg.Type
	m.tunnelServer = cfg.Server
	m.tunnelService = service
	m.tunnelPort = port
	m.tunnelPID = pid
	m.tunnelErr = ""
	m.tunnelStop = stop
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tunnelRunning = false
		m.tunnelStop = nil
	}()
	return nil
}

func (m *Manager) StopTunnel() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.tunnelRunning || m.tunnelStop == nil {
		return errors.New("tunnel not running")
	}
	if err := m.tunnelStop(); err != nil {
		m.tunnelErr = err.Error()
		return err
	}
	m.tunnelRunning = false
	m.tunnelStop = nil
	return nil
}

func (m *Manager) StartMailSink(listen, dataDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mailSinkRunning {
		return errors.New("mail sink already running")
	}
	server := &mail.SinkServer{Listen: listen, DataDir: dataDir}
	stop, err := server.Start()
	if err != nil {
		m.mailSinkErr = err.Error()
		return err
	}
	m.mailSinkRunning = true
	m.mailSinkListen = listen
	m.mailSinkErr = ""
	m.mailSinkStop = stop
	return nil
}

func (m *Manager) StopMailSink() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mailSinkRunning || m.mailSinkStop == nil {
		return errors.New("mail sink not running")
	}
	if err := m.mailSinkStop(); err != nil {
		m.mailSinkErr = err.Error()
		return err
	}
	m.mailSinkRunning = false
	m.mailSinkStop = nil
	return nil
}

func (m *Manager) StartMailLocal() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := mail.StartLocal(); err != nil {
		m.mailLocalErr = err.Error()
		return err
	}
	m.mailLocalOn = true
	m.mailLocalErr = ""
	return nil
}

func (m *Manager) StopMailLocal() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := mail.StopLocal(); err != nil {
		m.mailLocalErr = err.Error()
		return err
	}
	m.mailLocalOn = false
	return nil
}

func (m *Manager) StartMailMesh(listen, psk, pskFile, transport, dataDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mailMeshRunning {
		return errors.New("mail mesh already running")
	}
	if dataDir == "" {
		dataDir = "."
	}
	outDir := filepath.Join(dataDir, "mail", "mesh_tmp")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		m.mailMeshErr = err.Error()
		return err
	}
	stop, err := mesh.Listen(mesh.ReceiveOptions{
		Listen:    listen,
		OutDir:    outDir,
		PSK:       psk,
		PSKFile:   pskFile,
		Transport: transport,
	}, func(path string) error {
		if err := mail.StoreMeshMessage(dataDir, path); err != nil {
			return err
		}
		_ = os.Remove(path)
		return nil
	})
	if err != nil {
		m.mailMeshErr = err.Error()
		return err
	}
	m.mailMeshRunning = true
	m.mailMeshListen = listen
	m.mailMeshErr = ""
	m.mailMeshStop = stop
	return nil
}

func (m *Manager) StopMailMesh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mailMeshRunning || m.mailMeshStop == nil {
		return errors.New("mail mesh not running")
	}
	if err := m.mailMeshStop(); err != nil {
		m.mailMeshErr = err.Error()
		return err
	}
	m.mailMeshRunning = false
	m.mailMeshStop = nil
	return nil
}

func (m *Manager) StartHub(listen, dataDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hubRunning {
		return errors.New("hub already running")
	}
	server := &hub.Server{Listen: listen, DataDir: dataDir}
	if err := server.Start(); err != nil {
		m.hubErr = err.Error()
		return err
	}
	m.hubRunning = true
	m.hubListen = listen
	m.hubErr = ""
	m.hubStop = server.Stop
	return nil
}

func (m *Manager) StopHub() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hubRunning || m.hubStop == nil {
		return errors.New("hub not running")
	}
	if err := m.hubStop(); err != nil {
		m.hubErr = err.Error()
		return err
	}
	m.hubRunning = false
	m.hubStop = nil
	return nil
}

func (m *Manager) StartProxy(engine, configPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proxyRunning {
		return errors.New("proxy already running")
	}
	cmd, stop, err := proxy.Start(engine, configPath)
	if err != nil {
		m.proxyErr = err.Error()
		return err
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	m.proxyRunning = true
	m.proxyEngine = engine
	m.proxyConfig = configPath
	m.proxyPID = pid
	m.proxyErr = ""
	m.proxyStop = stop
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.proxyRunning = false
		m.proxyStop = nil
	}()
	return nil
}

func (m *Manager) StopProxy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.proxyRunning || m.proxyStop == nil {
		return errors.New("proxy not running")
	}
	if err := m.proxyStop(); err != nil {
		m.proxyErr = err.Error()
		return err
	}
	m.proxyRunning = false
	m.proxyStop = nil
	return nil
}

func (m *Manager) StartMeshGateway(listen, upstream string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.meshGatewayRunning {
		return errors.New("mesh gateway already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := meshgateway.Start(ctx, meshgateway.Options{
		Listen:   listen,
		Upstream: upstream,
	})
	if err != nil {
		m.meshGatewayErr = err.Error()
		cancel()
		return err
	}
	m.meshGatewayRunning = true
	m.meshGatewayListen = listen
	m.meshGatewayUpstream = upstream
	m.meshGatewayErr = ""
	m.meshGatewayStop = func() error {
		cancel()
		return stop()
	}
	return nil
}

func (m *Manager) StopMeshGateway() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.meshGatewayRunning || m.meshGatewayStop == nil {
		return errors.New("mesh gateway not running")
	}
	if err := m.meshGatewayStop(); err != nil {
		m.meshGatewayErr = err.Error()
		return err
	}
	m.meshGatewayRunning = false
	m.meshGatewayStop = nil
	return nil
}

func (m *Manager) StartSync(opts syncer.Options) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncRunning {
		return errors.New("sync already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := syncer.Start(ctx, opts, func(msg string) {
		log.Printf("[sync] %s", msg)
	})
	if err != nil {
		m.syncErr = err.Error()
		cancel()
		return err
	}
	m.syncRunning = true
	m.syncTarget = opts.Target
	m.syncDir = opts.Dir
	m.syncErr = ""
	m.syncStop = func() error {
		cancel()
		return stop()
	}
	return nil
}

func (m *Manager) StopSync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.syncRunning || m.syncStop == nil {
		return errors.New("sync not running")
	}
	if err := m.syncStop(); err != nil {
		m.syncErr = err.Error()
		return err
	}
	m.syncRunning = false
	m.syncStop = nil
	return nil
}

func (m *Manager) StartTelegram(cfg config.TelegramConfig, cfgPath string, home string, identityPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.telegramRunning {
		return errors.New("telegram already running")
	}
	saveUser := func(id int64) error {
		if cfgPath == "" {
			return nil
		}
		current, err := config.LoadOptional(cfgPath)
		if err != nil {
			return err
		}
		current.Telegram.AllowedUserID = id
		return config.Save(cfgPath, current)
	}
	execFn := func(cmd string) (string, error) {
		return system.RunShellCommand(cmd)
	}
	statsFn := func() string {
		metrics, err := system.Snapshot()
		if err != nil {
			return "stats unavailable"
		}
		return system.FormatMetrics(metrics)
	}
	wipeFn := func() error {
		return system.Wipe(home, identityPath, system.WipeEmergency)
	}

	bot, err := telegram.Start(telegram.Options{
		Config:   cfg,
		SaveUser: saveUser,
		ExecFn:   execFn,
		StatsFn:  statsFn,
		WipeFn:   wipeFn,
		Logf:     log.Printf,
	})
	if err != nil {
		m.telegramErr = err.Error()
		return err
	}
	m.telegramBot = bot
	m.telegramRunning = true
	m.telegramErr = ""
	return nil
}

func (m *Manager) StopTelegram() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.telegramRunning || m.telegramBot == nil {
		return errors.New("telegram not running")
	}
	m.telegramBot.Stop()
	m.telegramRunning = false
	m.telegramBot = nil
	return nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var emulateStatus emulate.Status
	if m.emulateRunner != nil {
		emulateStatus = m.emulateRunner.Status()
	}
	return Status{
		RelayRunning:     m.relayRunning,
		RelayListen:      m.relayListen,
		RelayError:       m.relayErr,
		DoHRunning:       m.dohRunning,
		DoHListen:        m.dohListen,
		DoHURL:           m.dohURL,
		DoHPID:           m.dohPID,
		DoHError:         m.dohErr,
		Emulate:          emulateStatus,
		TunnelRunning:    m.tunnelRunning,
		TunnelType:       m.tunnelType,
		TunnelServer:     m.tunnelServer,
		TunnelService:    m.tunnelService,
		TunnelPort:       m.tunnelPort,
		TunnelPID:        m.tunnelPID,
		TunnelError:      m.tunnelErr,
		MailSinkRunning:  m.mailSinkRunning,
		MailSinkListen:   m.mailSinkListen,
		MailSinkError:    m.mailSinkErr,
		MailLocalRunning: m.mailLocalOn,
		MailLocalError:   m.mailLocalErr,
		MailMeshRunning:  m.mailMeshRunning,
		MailMeshListen:   m.mailMeshListen,
		MailMeshError:    m.mailMeshErr,
		HubRunning:       m.hubRunning,
		HubListen:        m.hubListen,
		HubError:         m.hubErr,
		ProxyRunning:     m.proxyRunning,
		ProxyEngine:      m.proxyEngine,
		ProxyConfig:      m.proxyConfig,
		ProxyPID:         m.proxyPID,
		ProxyError:       m.proxyErr,
		MeshGatewayRunning: m.meshGatewayRunning,
		MeshGatewayListen: m.meshGatewayListen,
		MeshGatewayUpstream: m.meshGatewayUpstream,
		MeshGatewayError:  m.meshGatewayErr,
		SyncRunning:      m.syncRunning,
		SyncTarget:       m.syncTarget,
		SyncDir:          m.syncDir,
		SyncError:        m.syncErr,
		TelegramRunning:  m.telegramRunning,
		TelegramError:    m.telegramErr,
	}
}

type Status struct {
	RelayRunning     bool
	RelayListen      string
	RelayError       string
	DoHRunning       bool
	DoHListen        string
	DoHURL           string
	DoHPID           int
	DoHError         string
	Emulate          emulate.Status
	TunnelRunning    bool
	TunnelType       string
	TunnelServer     string
	TunnelService    string
	TunnelPort       int
	TunnelPID        int
	TunnelError      string
	MailSinkRunning  bool
	MailSinkListen   string
	MailSinkError    string
	MailLocalRunning bool
	MailLocalError   string
	MailMeshRunning  bool
	MailMeshListen   string
	MailMeshError    string
	HubRunning       bool
	HubListen        string
	HubError         string
	ProxyRunning     bool
	ProxyEngine      string
	ProxyConfig      string
	ProxyPID         int
	ProxyError       string
	MeshGatewayRunning bool
	MeshGatewayListen  string
	MeshGatewayUpstream string
	MeshGatewayError   string
	SyncRunning      bool
	SyncTarget       string
	SyncDir          string
	SyncError        string
	TelegramRunning  bool
	TelegramError    string
}
