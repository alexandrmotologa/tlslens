package k8s

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ManifestOptions specifies customization settings for Kubernetes YAML output.
type ManifestOptions struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	CertPEM     []byte   `json:"certPem"`
	KeyPEM      []byte   `json:"keyPem"`
	CAPEM       []byte   `json:"caPem"`
	Domains     []string `json:"domains"`
	ServiceName string   `json:"serviceName"`
	ServicePort int      `json:"servicePort"`
}

// ManifestBundle holds all generated Kubernetes resource YAMLs.
type ManifestBundle struct {
	TLSSecret         string `json:"tlsSecret"`
	CAConfigMap       string `json:"caConfigMap"`
	CertManagerIssuer string `json:"certManagerIssuer"`
	Ingress           string `json:"ingress"`
	AllInOne          string `json:"allInOne"`
	KubectlCommand    string `json:"kubectlCommand"`
}

// GenerateManifests constructs production-grade Kubernetes YAML manifests.
func GenerateManifests(opts ManifestOptions) ManifestBundle {
	if opts.Name == "" {
		opts.Name = "tlslens-app"
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.ServiceName == "" {
		opts.ServiceName = opts.Name
	}
	if opts.ServicePort <= 0 {
		opts.ServicePort = 80
	}
	if len(opts.Domains) == 0 {
		opts.Domains = []string{"localhost"}
	}

	secretName := fmt.Sprintf("%s-tls", opts.Name)
	caConfigMapName := fmt.Sprintf("%s-ca", opts.Name)

	b64Cert := base64.StdEncoding.EncodeToString(opts.CertPEM)
	b64Key := base64.StdEncoding.EncodeToString(opts.KeyPEM)

	// 1. kubernetes.io/tls Secret
	tlsSecret := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/managed-by: tlslens
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, secretName, opts.Namespace, opts.Name, b64Cert, b64Key)

	// 2. CA Bundle ConfigMap
	caContent := string(opts.CAPEM)
	if caContent == "" {
		caContent = "# CA Certificate PEM (populate from local CA or cert-manager)\n"
	}
	indentedCA := indent(strings.TrimSpace(caContent), "    ")

	caConfigMap := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/managed-by: tlslens
data:
  ca.crt: |
%s
`, caConfigMapName, opts.Namespace, opts.Name, indentedCA)

	// 3. cert-manager ClusterIssuer & Issuer
	certManagerIssuer := fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: tlslens-local-ca
spec:
  ca:
    secretName: %s
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %s
  namespace: %s
spec:
  secretName: %s
  duration: 2160h # 90d
  renewBefore: 360h # 15d
  commonName: %s
  dnsNames:
%s
  issuerRef:
    name: tlslens-local-ca
    kind: ClusterIssuer
`, secretName, opts.Name, opts.Namespace, secretName, opts.Domains[0], formatDNSList(opts.Domains, "  - "))

	// 4. Ingress with TLS Termination
	ingress := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %s
  namespace: %s
  annotations:
    ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
%s
      secretName: %s
  rules:
%s
`, opts.Name, opts.Namespace, formatDNSList(opts.Domains, "        - "), secretName, formatIngressRules(opts.Domains, opts.ServiceName, opts.ServicePort))

	allInOne := fmt.Sprintf("%s---\n%s---\n%s---\n%s", tlsSecret, caConfigMap, certManagerIssuer, ingress)
	kubectlCmd := fmt.Sprintf("kubectl apply -n %s -f tls-bundle.yaml", opts.Namespace)

	return ManifestBundle{
		TLSSecret:         tlsSecret,
		CAConfigMap:       caConfigMap,
		CertManagerIssuer: certManagerIssuer,
		Ingress:           ingress,
		AllInOne:          allInOne,
		KubectlCommand:    kubectlCmd,
	}
}

func indent(str, prefix string) string {
	lines := strings.Split(str, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

func formatDNSList(domains []string, prefix string) string {
	var out []string
	for _, d := range domains {
		out = append(out, prefix+d)
	}
	return strings.Join(out, "\n")
}

func formatIngressRules(domains []string, svcName string, port int) string {
	var rules []string
	for _, d := range domains {
		rule := fmt.Sprintf(`    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %s
                port:
                  number: %d`, d, svcName, port)
		rules = append(rules, rule)
	}
	return strings.Join(rules, "\n")
}
