package mail

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func StoreMeshMessage(dataDir, path string) error {
	if dataDir == "" {
		dataDir = "."
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	from := ""
	to := ""
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "FROM:"):
			from = strings.TrimSpace(line[5:])
		case strings.HasPrefix(upper, "TO:"):
			to = strings.TrimSpace(line[3:])
		}
	}
	if to == "" {
		to = "unknown"
	}
	if from == "" {
		from = "unknown"
	}

	ts := time.Now().UTC().Format("20060102-150405.000000000")
	dir := filepath.Join(dataDir, "mail", "inbox", cleanAddr(to))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	outPath := filepath.Join(dir, ts+".eml")
	return os.WriteFile(outPath, raw, 0600)
}
