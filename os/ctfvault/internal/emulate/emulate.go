package emulate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

	cmd, warn, err := buildCommand(path, args, cfg, home, env, tmpDir)
	if err != nil {
		return err
	}
	r.err = warn
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	r.cmd = cmd
	r.app = app
	r.args = args
	r.pid = cmd.Process.Pid
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
	mode := normalizeMode(cfg.Mode)
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
		env = append(env, "GDK_BACKEND=wayland")
		env = append(env, "QT_QPA_PLATFORM=wayland")
		env = append(env, "MOZ_ENABLE_WAYLAND=1")
		env = append(env, "SDL_VIDEODRIVER=wayland")
	}
	if mode == "tor" {
		env = append(env, "http_proxy=socks5h://127.0.0.1:9050")
		env = append(env, "https_proxy=socks5h://127.0.0.1:9050")
		env = append(env, "all_proxy=socks5h://127.0.0.1:9050")
	}

	var tmpDir string
	switch cfg.TempDir {
	case "ram":
		base := "/dev/shm"
		if _, err := os.Stat(base); err != nil {
			base = os.TempDir()
		}
		cleanupEmulateTmp(base)
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
		cleanupEmulateTmp(dir)
		tmpDir = dir
		env = append(env, "TMPDIR="+dir)
	}
	return env, tmpDir, nil
}

func buildCommand(path string, args []string, cfg config.EmulateConfig, home string, env []string, tmpDir string) (*exec.Cmd, string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command(path, args...)
		cmd.Env = env
		return cmd, "privacy mode unavailable on Windows", nil
	}
	if !cfg.PrivacyMode || runtime.GOOS != "linux" {
		cmd := exec.Command(path, args...)
		cmd.Env = env
		return cmd, "", nil
	}

	mode := normalizeMode(cfg.Mode)
	args = decorateArgsForMode(path, args, mode)

	wrapperCmd, wrapperArgs, warn := buildDisplayWrapper(cfg.DisplayServer, path, args)
	if wrapperCmd != "" {
		cmd := exec.Command(wrapperCmd, wrapperArgs...)
		cmd.Env = env
		return cmd, warn, nil
	}

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		cmd := exec.Command(path, args...)
		cmd.Env = env
		return cmd, "privacy mode: bwrap not found (fallback to env isolation)", nil
	}

	sandboxBase := tmpDir
	if sandboxBase == "" {
		dir, err := os.MkdirTemp("", "gargoyle-emulate-")
		if err != nil {
			return nil, "", err
		}
		sandboxBase = dir
	}
	sandboxHome := filepath.Join(sandboxBase, "home")
	_ = os.MkdirAll(sandboxHome, 0700)

	bwrapArgs := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-ipc",
		"--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", sandboxHome, "/home/gargoyle",
		"--setenv", "HOME", "/home/gargoyle",
	}
	if mode == "silent" {
		bwrapArgs = append(bwrapArgs, "--unshare-net")
	} else {
		bwrapArgs = append(bwrapArgs, "--share-net")
	}

	if home != "" && mode != "amnesic" && mode != "silent" {
		downloads := filepath.Join(home, cfg.DownloadsDir)
		dataDir := filepath.Join(home, "data")
		sharedDir := filepath.Join(home, "shared")
		_ = os.MkdirAll(downloads, 0700)
		_ = os.MkdirAll(dataDir, 0700)
		_ = os.MkdirAll(sharedDir, 0700)
		bwrapArgs = append(bwrapArgs,
			"--bind", downloads, "/home/gargoyle/Downloads",
			"--bind", dataDir, "/home/gargoyle/data",
			"--bind", sharedDir, "/home/gargoyle/shared",
			"--setenv", "XDG_DOWNLOAD_DIR", "/home/gargoyle/Downloads",
			"--setenv", "XDG_DATA_HOME", "/home/gargoyle/data",
		)
	}

	bwrapArgs = append(bwrapArgs, "--", path)
	bwrapArgs = append(bwrapArgs, args...)

	cmd := exec.Command(bwrap, bwrapArgs...)
	cmd.Env = env
	return cmd, "", nil
}

func normalizeMode(mode string) string {
	switch mode {
	case "silent", "amnesic", "host":
		return mode
	default:
		return "tor"
	}
}

func decorateArgsForMode(path string, args []string, mode string) []string {
	if mode == "host" {
		return args
	}
	base := filepath.Base(path)
	switch base {
	case "firefox", "firefox-esr", "torbrowser-launcher":
		class := "GargoyleTor"
		if mode == "silent" {
			class = "GargoyleSilent"
		} else if mode == "amnesic" {
			class = "GargoyleAmnesic"
		}
		return append([]string{"--class", class}, args...)
	default:
		return args
	}
}

func buildDisplayWrapper(display string, app string, args []string) (string, []string, string) {
	if display == "" || display == "direct" {
		return "", nil, ""
	}
	switch display {
	case "cage":
		if path, err := exec.LookPath("cage"); err == nil {
			wargs := append([]string{"--", app}, args...)
			return path, wargs, ""
		}
		return "", nil, "display_server=cage requested but cage not found"
	case "gamescope":
		if path, err := exec.LookPath("gamescope"); err == nil {
			wargs := append([]string{"--"}, append([]string{app}, args...)...)
			return path, wargs, ""
		}
		return "", nil, "display_server=gamescope requested but gamescope not found"
	case "weston":
		if path, err := exec.LookPath("weston"); err == nil {
			wargs := append([]string{"--"}, append([]string{app}, args...)...)
			return path, wargs, ""
		}
		return "", nil, "display_server=weston requested but weston not found"
	default:
		return "", nil, ""
	}
}

func cleanupEmulateTmp(base string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "gargoyle-emulate-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(base, name))
		}
	}
}
