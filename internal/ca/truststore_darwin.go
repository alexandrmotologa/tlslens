//go:build darwin

package ca

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
)

// InstallRootCA installs the root certificate into macOS System Keychain.
func InstallRootCA(certPath string) error {
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add root CA to macOS keychain: %s (%w)", string(output), err)
	}
	return nil
}

// UninstallRootCA removes the root certificate from macOS System Keychain.
func UninstallRootCA(certPathOrName string) error {
	cmd := exec.Command("security", "remove-trusted-cert", "-d", certPathOrName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove root CA from macOS keychain: %s (%w)", string(output), err)
	}
	return nil
}

// CheckRootCATrusted checks if the certificate exists in the macOS Keychain.
func CheckRootCATrusted(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	cmd := exec.Command("security", "find-certificate", "-c", cert.Subject.CommonName, "/Library/Keychains/System.keychain")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return true
	}
	return false
}
