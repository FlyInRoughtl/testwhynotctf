package system

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
)

func RunShellCommand(cmdline string) (string, error) {
	if cmdline == "" {
		return "", errors.New("empty command")
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", cmdline)
	} else {
		cmd = exec.Command("sh", "-c", cmdline)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}
