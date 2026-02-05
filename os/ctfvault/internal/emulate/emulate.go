package emulate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"gargoyle/internal/config"
)

type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	app     string
	args    []string
	pid     int
	err     string
	started time.Time
	tmpDir  string
}

func (r *Runner) Start(app string, args []string, cfg config.EmulateConfig, home string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cmd != nil && r.cmd.Process != nil {
		return errors.New("emulate already running")
	}
	if app == "" {
		return errors.New("app is required")
	}
	path, err := exec.LookPath(app)
	if err != nil {
		return fmt.Errorf("app not found: %s", app)
	}

	env, tmpDir, err := buildEnv(cfg, home)
	if err != nil {
		return err
	}

	cmd := exec.Command(path, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	r.cmd = cmd
	r.app = app
	r.args = args
	r.pid = cmd.Process.Pid
	r.err = ""
	r.started = time.Now()
	r.tmpDir = tmpDir

	go func() {
		_ = cmd.Wait()
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cmd = nil
		r.pid = 0
		if r.tmpDir != "" {
			_ = os.RemoveAll(r.tmpDir)
		}
		r.tmpDir = ""
	}()

	return nil
}

func (r *Runner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return errors.New("emulate not running")
	}
	if err := r.cmd.Process.Kill(); err != nil {
		return err
	}
	r.cmd = nil
	r.pid = 0
	if r.tmpDir != "" {
		_ = os.RemoveAll(r.tmpDir)
	}
	r.tmpDir = ""
	return nil
}

func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{
		Running: r.cmd != nil && r.pid != 0,
		App:     r.app,
		Args:    r.args,
		PID:     r.pid,
		Error:   r.err,
		Started: r.started,
	}
}

type Status struct {
	Running bool
	App     string
	Args    []string
	PID     int
	Error   string
	Started time.Time
}

func buildEnv(cfg config.EmulateConfig, home string) ([]string, string, error) {
	env := os.Environ()
	if home != "" {
		env = append(env, "HOME="+home)
		env = append(env, "XDG_DATA_HOME="+filepath.Join(home, "data"))
		env = append(env, "XDG_CACHE_HOME="+filepath.Join(home, "cache"))
		if cfg.DownloadsDir != "" {
			env = append(env, "XDG_DOWNLOAD_DIR="+filepath.Join(home, cfg.DownloadsDir))
		}
	}
	if cfg.PrivacyMode {
		env = append(env, "GARGOYLE_PRIVACY=1")
	}

	var tmpDir string
	switch cfg.TempDir {
	case "ram":
		base := "/dev/shm"
		if _, err := os.Stat(base); err != nil {
			base = os.TempDir()
		}
		dir, err := os.MkdirTemp(base, "gargoyle-emulate-")
		if err != nil {
			return nil, "", err
		}
		tmpDir = dir
		env = append(env, "TMPDIR="+dir)
	case "disk":
		if home == "" {
			break
		}
		dir := filepath.Join(home, "tmp")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, "", err
		}
		tmpDir = dir
		env = append(env, "TMPDIR="+dir)
	}
	return env, tmpDir, nil
}
