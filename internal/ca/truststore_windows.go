//go:build windows

package ca

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

// InstallRootCA installs the root certificate into the Windows Root certification store.
func InstallRootCA(certPath string) error {
	cmd := exec.Command("certutil.exe", "-addstore", "-f", "ROOT", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add root CA to Windows store: %s (%w)", string(output), err)
	}
	return nil
}

// UninstallRootCA removes the root certificate from the Windows Root store using its thumbprint or serial.
func UninstallRootCA(thumbprintOrSerial string) error {
	cmd := exec.Command("certutil.exe", "-delstore", "ROOT", thumbprintOrSerial)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete root CA from Windows store: %s (%w)", string(output), err)
	}
	return nil
}

// CheckRootCATrusted checks if the certificate exists in the Windows ROOT store.
func CheckRootCATrusted(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	sha1Sum := sha1.Sum(cert.Raw)
	thumbprint := hex.EncodeToString(sha1Sum[:])

	cmd := exec.Command("certutil.exe", "-verifystore", "ROOT", thumbprint)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}

	// Secondary check: look for serial number or CN
	serial := cert.SerialNumber.Text(16)
	cmd2 := exec.Command("certutil.exe", "-store", "ROOT", serial)
	output2, err2 := cmd2.CombinedOutput()
	if err2 == nil && strings.Contains(strings.ToLower(string(output2)), strings.ToLower(cert.Subject.CommonName)) {
		return true
	}

	_ = output
	return false
}
