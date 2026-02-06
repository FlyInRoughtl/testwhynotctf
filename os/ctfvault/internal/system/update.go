package system

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type UpdateOptions struct {
	URL       string
	SHA256    string
	Signature string
	PublicKey string
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

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, opts.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
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
	if opts.Signature != "" {
		if err := verifySignature(h.Sum(nil), opts.Signature, opts.PublicKey); err != nil {
			return "", err
		}
	}

	if runtime.GOOS == "windows" {
		target := exe + ".new.exe"
		_ = os.Remove(target)
		if err := os.Rename(tmpFile, target); err != nil {
			return "", err
		}
		base := filepath.Base(exe)
		script := filepath.Join(dir, "gargoyle.update.cmd")
		content := fmt.Sprintf(`@echo off
set EXE=%%~dp0%[1]s
set NEW=%%EXE%%.new.exe
:wait
tasklist /FI "IMAGENAME eq %[1]s" | find /I "%[1]s" >nul
if "%%ERRORLEVEL%%"=="0" (
  timeout /t 1 /nobreak >nul
  goto wait
)
del /f /q "%%EXE%%" >nul 2>&1
move /y "%%NEW%%" "%%EXE%%" >nul
start "" "%%EXE%%"
del "%%~f0"
`, base)
		if err := os.WriteFile(script, []byte(content), 0600); err != nil {
			return target, nil
		}
		_ = exec.Command("cmd", "/c", "start", "", script).Start()
		return script, nil
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

func verifySignature(hash []byte, sigText string, pubText string) error {
	if pubText == "" {
		return errors.New("signature provided but public key is empty")
	}
	sig, err := decodeBase64OrHex(sigText)
	if err != nil {
		return fmt.Errorf("signature decode: %w", err)
	}
	pub, err := decodeBase64OrHex(pubText)
	if err != nil {
		return fmt.Errorf("public key decode: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), hash, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func decodeBase64OrHex(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("empty value")
	}
	if data, err := base64.StdEncoding.DecodeString(text); err == nil {
		return data, nil
	}
	if data, err := hex.DecodeString(text); err == nil {
		return data, nil
	}
	return nil, errors.New("invalid base64/hex value")
}
