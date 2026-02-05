package system

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"gargoyle/internal/config"
	"gargoyle/internal/paths"
	"gargoyle/internal/security"
)

type WipeMode int

const (
	WipeNormal WipeMode = iota
	WipeEmergency
)

func EnsureHome(cfg config.Config) (string, string, error) {
	homeDir, err := resolveHome(cfg)
	if err != nil {
		return "", "", err
	}
	if err := paths.EnsureDir(homeDir); err != nil {
		return "", "", err
	}

	for _, dir := range []string{
		filepath.Join(homeDir, "data"),
		filepath.Join(homeDir, "downloads"),
		filepath.Join(homeDir, "logs"),
		filepath.Join(homeDir, "keys"),
		filepath.Join(homeDir, "shared"),
	} {
		if err := paths.EnsureDir(dir); err != nil {
			return "", "", err
		}
	}

	identityPath := paths.ResolveInHome(homeDir, cfg.Security.IdentityKeyPath)
	if _, err := security.EnsureIdentityKey(identityPath, cfg.Security.IdentityLength, cfg.Security.IdentityGroup); err != nil {
		return "", "", err
	}

	return homeDir, identityPath, nil
}

func resolveHome(cfg config.Config) (string, error) {
	if v := os.Getenv(paths.EnvHome); v != "" {
		return v, nil
	}
	if cfg.Storage.RAMOnly && runtime.GOOS == "linux" {
		base := "/dev/shm"
		if info, err := os.Stat(base); err != nil || !info.IsDir() {
			base = os.TempDir()
		}
		dir, err := os.MkdirTemp(base, "gargoyle-")
		if err == nil {
			_ = os.Setenv(paths.EnvHome, dir)
			return dir, nil
		}
	}
	return paths.HomeDir()
}

func Wipe(homeDir string, identityPath string, mode WipeMode) error {
	if homeDir == "" {
		return errors.New("home directory is empty")
	}

	if mode == WipeNormal {
		for _, name := range []string{"data", "downloads", "logs", "shared"} {
			_ = os.RemoveAll(filepath.Join(homeDir, name))
		}
		return nil
	}

	entries, err := os.ReadDir(homeDir)
	if err != nil {
		return err
	}

	identityAbs := identityPath
	if !filepath.IsAbs(identityAbs) {
		identityAbs = filepath.Join(homeDir, identityAbs)
	}

	for _, entry := range entries {
		path := filepath.Join(homeDir, entry.Name())
		if entry.Name() == "keys" {
			_ = wipeKeys(path, identityAbs)
			continue
		}
		_ = os.RemoveAll(path)
	}

	return nil
}

func wipeKeys(keysDir string, identityAbs string) error {
	if err := paths.EnsureDir(keysDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(keysDir, entry.Name())
		if samePath(path, identityAbs) {
			continue
		}
		_ = os.RemoveAll(path)
	}
	return nil
}

func samePath(a, b string) bool {
	aAbs, _ := filepath.Abs(a)
	bAbs, _ := filepath.Abs(b)
	return aAbs == bAbs
}
