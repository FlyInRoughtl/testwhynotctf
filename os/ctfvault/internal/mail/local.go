package mail

import (
	"errors"
	"os/exec"
	"strings"
)

func StartLocal() error {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("systemctl not found")
	}
	_ = exec.Command(systemctl, "start", "postfix").Run()
	_ = exec.Command(systemctl, "start", "dovecot").Run()
	return nil
}

func StopLocal() error {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("systemctl not found")
	}
	_ = exec.Command(systemctl, "stop", "postfix").Run()
	_ = exec.Command(systemctl, "stop", "dovecot").Run()
	return nil
}

func LocalStatus() (bool, bool, error) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return false, false, errors.New("systemctl not found")
	}
	postfix := isActive(systemctl, "postfix")
	dovecot := isActive(systemctl, "dovecot")
	return postfix, dovecot, nil
}

func isActive(systemctl, svc string) bool {
	out, err := exec.Command(systemctl, "is-active", svc).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
