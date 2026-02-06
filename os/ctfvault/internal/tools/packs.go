package tools

import (
	"embed"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

//go:embed packs/*.yaml
var packFS embed.FS

func BuiltinPack(name string) (string, bool) {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return "", false
	}
	path := filepath.ToSlash(filepath.Join("packs", name+".yaml"))
	data, err := packFS.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func WritePackFile(path, content string) error {
	if path == "" {
		return errors.New("pack path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}
