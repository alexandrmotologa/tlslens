//go:build !windows && !darwin && !linux

package ca

import (
	"crypto/x509"
	"fmt"
)

func InstallRootCA(certPath string) error {
	return fmt.Errorf("automatic OS trust store installation is not supported on this platform")
}

func UninstallRootCA(thumbprintOrSerial string) error {
	return fmt.Errorf("automatic OS trust store uninstallation is not supported on this platform")
}

func CheckRootCATrusted(cert *x509.Certificate) bool {
	return false
}
