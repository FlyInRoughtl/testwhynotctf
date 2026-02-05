package tools

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Pack struct {
	Pack  string      `yaml:"pack"`
	Tools []ToolEntry `yaml:"tools"`
}

type ToolEntry struct {
	Name    string `yaml:"name"`
	Install string `yaml:"install"`
	Check   string `yaml:"check"`
}

func (t *ToolEntry) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		t.Name = value.Value
		return nil
	case yaml.MappingNode:
		type raw ToolEntry
		var out raw
		if err := value.Decode(&out); err != nil {
			return err
		}
		*t = ToolEntry(out)
		return nil
	default:
		return errors.New("unsupported tool entry")
	}
}

func Load(path string) (Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Pack{}, err
	}
	var pack Pack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

func EnsureDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content := `pack: default
tools:
  - name: nmap
    install: "apt:nmap"
  - name: sqlmap
    install: "apt:sqlmap"
  - name: ffuf
    install: "apt:ffuf"
  - name: gobuster
    install: "apt:gobuster"
  - name: gdb
    install: "apt:gdb"
  - name: radare2
    install: "apt:radare2"
  - name: wireshark-cli
    install: "apt:tshark"
`
	return os.WriteFile(path, []byte(content), 0600)
}

func InstallAll(pack Pack) ([]string, error) {
	var logs []string
	for _, tool := range pack.Tools {
		if tool.Name == "" {
			continue
		}
		install := tool.Install
		if install == "" {
			install = "apt:" + tool.Name
		}
		logs = append(logs, fmt.Sprintf("install %s (%s)", tool.Name, install))
		if err := runInstall(install); err != nil {
			logs = append(logs, fmt.Sprintf("error: %v", err))
		}
	}
	return logs, nil
}

func runInstall(install string) error {
	switch {
	case strings.HasPrefix(install, "apt:"):
		pkg := strings.TrimPrefix(install, "apt:")
		return exec.Command("apt-get", "install", "-y", pkg).Run()
	case strings.HasPrefix(install, "go:"):
		pkg := strings.TrimPrefix(install, "go:")
		return exec.Command("go", "install", pkg).Run()
	case strings.HasPrefix(install, "pip:"):
		pkg := strings.TrimPrefix(install, "pip:")
		return exec.Command("python", "-m", "pip", "install", pkg).Run()
	case strings.HasPrefix(install, "cmd:"):
		cmdline := strings.TrimPrefix(install, "cmd:")
		parts := strings.Fields(cmdline)
		if len(parts) == 0 {
			return errors.New("empty cmd")
		}
		return exec.Command(parts[0], parts[1:]...).Run()
	default:
		return errors.New("unknown install prefix")
	}
}
