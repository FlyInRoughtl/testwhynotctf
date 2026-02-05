package proxy

import (
	"errors"
	"os"
	"os/exec"
)

func Start(engine, configPath string) (*exec.Cmd, func() error, error) {
	if engine == "" {
		return nil, nil, errors.New("proxy engine is empty")
	}
	if configPath == "" {
		return nil, nil, errors.New("proxy config path is empty")
	}
	var cmd *exec.Cmd
	switch engine {
	case "sing-box":
		if _, err := exec.LookPath("sing-box"); err != nil {
			return nil, nil, errors.New("sing-box not installed")
		}
		cmd = exec.Command("sing-box", "run", "-c", configPath)
	case "xray":
		if _, err := exec.LookPath("xray"); err != nil {
			return nil, nil, errors.New("xray not installed")
		}
		cmd = exec.Command("xray", "run", "-config", configPath)
	case "hiddify":
		hiddify, err := exec.LookPath("hiddify")
		if err != nil {
			hiddify, err = exec.LookPath("hiddify-cli")
			if err != nil {
				return nil, nil, errors.New("hiddify not installed")
			}
		}
		cmd = exec.Command(hiddify, "run", "-c", configPath)
	default:
		return nil, nil, errors.New("unsupported proxy engine: " + engine)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	stop := func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return cmd, stop, nil
}
