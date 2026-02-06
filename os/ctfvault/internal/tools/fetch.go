package tools

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func FetchPack(repoURL, name, destPath string) error {
	if repoURL == "" {
		return errors.New("tools repository is empty")
	}
	if !validPackName(name) {
		return errors.New("invalid pack name")
	}
	base := strings.TrimRight(repoURL, "/")
	url := fmt.Sprintf("%s/%s.yaml", base, name)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pack fetch failed: %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, 1<<20)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	return WritePackFile(destPath, string(data))
}

func validPackName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
