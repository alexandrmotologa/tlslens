//go:build linux

package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	debianCADir = "/usr/local/share/ca-certificates"
	rhelCADir   = "/etc/pki/ca-trust/source/anchors"
)

// InstallRootCA installs the root certificate into the Linux system trust store.
func InstallRootCA(certPath string) error {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert file %s: %w", certPath, err)
	}

	if _, err := os.Stat(debianCADir); err == nil {
		target := filepath.Join(debianCADir, "tlslens-root.crt")
		if err := os.WriteFile(target, certData, 0644); err != nil {
			return fmt.Errorf("failed to write cert to %s: %w", target, err)
		}
		cmd := exec.Command("update-ca-certificates")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-certificates failed: %s (%w)", string(out), err)
		}
		return nil
	}

	if _, err := os.Stat(rhelCADir); err == nil {
		target := filepath.Join(rhelCADir, "tlslens-root.crt")
		if err := os.WriteFile(target, certData, 0644); err != nil {
			return fmt.Errorf("failed to write cert to %s: %w", target, err)
		}
		cmd := exec.Command("update-ca-trust", "extract")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-trust failed: %s (%w)", string(out), err)
		}
		return nil
	}

	return fmt.Errorf("unrecognized Linux distribution: neither %s nor %s found", debianCADir, rhelCADir)
}

// UninstallRootCA removes the root certificate from the Linux system trust store.
func UninstallRootCA(certPathOrName string) error {
	debianTarget := filepath.Join(debianCADir, "tlslens-root.crt")
	if _, err := os.Stat(debianTarget); err == nil {
		_ = os.Remove(debianTarget)
		cmd := exec.Command("update-ca-certificates", "--fresh")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-certificates --fresh failed: %s (%w)", string(out), err)
		}
		return nil
	}

	rhelTarget := filepath.Join(rhelCADir, "tlslens-root.crt")
	if _, err := os.Stat(rhelTarget); err == nil {
		_ = os.Remove(rhelTarget)
		cmd := exec.Command("update-ca-trust", "extract")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-trust failed: %s (%w)", string(out), err)
		}
		return nil
	}

	return nil
}

// CheckRootCATrusted checks if the certificate exists in the Linux anchors.
func CheckRootCATrusted(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(debianCADir, "tlslens-root.crt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(rhelCADir, "tlslens-root.crt")); err == nil {
		return true
	}
	return false
}
