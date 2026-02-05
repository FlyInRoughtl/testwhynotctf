package system

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

func ReadClipboard() (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-Clipboard")
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	if runtime.GOOS == "linux" {
		if path, err := exec.LookPath("wl-paste"); err == nil {
			cmd := exec.Command(path, "--no-newline")
			out, err := cmd.Output()
			if err != nil {
				return "", err
			}
			return string(out), nil
		}
		if path, err := exec.LookPath("xclip"); err == nil {
			cmd := exec.Command(path, "-o", "-selection", "clipboard")
			out, err := cmd.Output()
			if err != nil {
				return "", err
			}
			return string(out), nil
		}
	}
	return "", errors.New("clipboard not supported")
}

func WriteClipboard(text string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Set-Clipboard", text)
		return cmd.Run()
	}
	if runtime.GOOS == "linux" {
		if path, err := exec.LookPath("wl-copy"); err == nil {
			cmd := exec.Command(path)
			cmd.Stdin = bytes.NewBufferString(text)
			return cmd.Run()
		}
		if path, err := exec.LookPath("xclip"); err == nil {
			cmd := exec.Command(path, "-selection", "clipboard")
			cmd.Stdin = bytes.NewBufferString(text)
			return cmd.Run()
		}
	}
	return errors.New("clipboard not supported")
}
