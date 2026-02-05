package paths

import (
	"errors"
	"os"
	"path/filepath"
)

const EnvHome = "GARGOYLE_HOME"

func HomeDir() (string, error) {
	if v := os.Getenv(EnvHome); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", errors.New("home directory not found")
	}
	return filepath.Join(home, ".gargoyle"), nil
}

func EnsureDir(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	return os.MkdirAll(path, 0700)
}

func RelayDir() (string, error) {
	base, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "relay"), nil
}

func KeysDir() (string, error) {
	base, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "keys"), nil
}

func ResolveInHome(homeDir, rel string) string {
	if rel == "" {
		return homeDir
	}
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(homeDir, rel)
}
