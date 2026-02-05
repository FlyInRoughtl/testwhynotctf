package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

type UpdateOptions struct {
	URL    string
	SHA256 string
}

func UpdateBinary(opts UpdateOptions) (string, error) {
	if opts.URL == "" {
		return "", errors.New("update url is empty")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	tmpFile := filepath.Join(dir, "gargoyle.update.tmp")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	resp, err := http.Get(opts.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("update download failed: " + resp.Status)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), resp.Body); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if opts.SHA256 != "" && opts.SHA256 != sum {
		return "", errors.New("sha256 mismatch")
	}

	if runtime.GOOS == "windows" {
		target := exe + ".new.exe"
		_ = os.Remove(target)
		if err := os.Rename(tmpFile, target); err != nil {
			return "", err
		}
		return target, nil
	}

	backup := exe + ".bak"
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		return "", err
	}
	if err := os.Rename(tmpFile, exe); err != nil {
		_ = os.Rename(backup, exe)
		return "", err
	}
	return exe, nil
}
