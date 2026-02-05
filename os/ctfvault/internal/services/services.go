package services

import (
	"errors"
	"sync"

	"gargoyle/internal/config"
	"gargoyle/internal/doh"
	"gargoyle/internal/emulate"
	"gargoyle/internal/hub"
	"gargoyle/internal/mail"
	"gargoyle/internal/mesh"
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

	hubRunning bool
	hubListen  string
	hubErr     string
	hubStop    func() error
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
	cmd, stop, err := tunnel.StartFRP(cfg.Server, service, port, cfg.Token, home)
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
		HubRunning:       m.hubRunning,
		HubListen:        m.hubListen,
		HubError:         m.hubErr,
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
	HubRunning       bool
	HubListen        string
	HubError         string
}
