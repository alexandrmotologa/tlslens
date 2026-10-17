package watcher

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// WatchStatus denotes the operational and cryptographic health of a monitored domain.
type WatchStatus string

const (
	StatusHealthy      WatchStatus = "healthy"
	StatusExpiringSoon WatchStatus = "expiring_soon"
	StatusExpired      WatchStatus = "expired"
	StatusUnreachable  WatchStatus = "unreachable"
)

// MonitoredDomain holds tracking information and latest probe state.
type MonitoredDomain struct {
	ID                string      `json:"id"`
	Target            string      `json:"target"`
	Host              string      `json:"host"`
	Port              string      `json:"port"`
	IntervalSeconds   int         `json:"intervalSeconds"`
	Status            WatchStatus `json:"status"`
	CommonName        string      `json:"commonName"`
	Issuer            string      `json:"issuer"`
	DaysRemaining     int         `json:"daysRemaining"`
	ExpiresAt         string      `json:"expiresAt"`
	FingerprintSHA256 string      `json:"fingerprintSHA256"`
	TLSVersion        string      `json:"tlsVersion"`
	CipherSuite       string      `json:"cipherSuite"`
	LatencyMs         float64     `json:"latencyMs"`
	LastChecked       time.Time   `json:"lastChecked"`
	LastError         string      `json:"lastError,omitempty"`
	AddedAt           time.Time   `json:"addedAt"`
}

// AlertCallback is triggered whenever a certificate status degrades or changes.
type AlertCallback func(domain MonitoredDomain, changeType string)

// DomainWatcher manages scheduled domain checks in the background.
type DomainWatcher struct {
	mu         sync.RWMutex
	domains    map[string]*MonitoredDomain
	rootPool   *x509.CertPool
	onAlert    AlertCallback
	stopChan   chan struct{}
	running    bool
	tickerDone chan struct{}
}

// NewDomainWatcher creates a domain watcher instance.
func NewDomainWatcher(rootPool *x509.CertPool, onAlert AlertCallback) *DomainWatcher {
	return &DomainWatcher{
		domains:  make(map[string]*MonitoredDomain),
		rootPool: rootPool,
		onAlert:  onAlert,
		stopChan: make(chan struct{}),
	}
}

// Start begins background monitoring loop.
func (w *DomainWatcher) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.stopChan = make(chan struct{})
	w.tickerDone = make(chan struct{})
	w.mu.Unlock()

	go func() {
		defer close(w.tickerDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-w.stopChan:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.checkScheduled(ctx)
			}
		}
	}()
}

// Stop shuts down background ticker.
func (w *DomainWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}
	w.running = false
	close(w.stopChan)
}

// Add adds a new target to monitor and immediately runs a check.
func (w *DomainWatcher) Add(ctx context.Context, target string, intervalSeconds int) (*MonitoredDomain, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	if intervalSeconds <= 0 {
		intervalSeconds = 300 // default 5 minutes
	}

	id := fmt.Sprintf("watch_%d", time.Now().UnixNano())
	item := &MonitoredDomain{
		ID:              id,
		Target:          target,
		IntervalSeconds: intervalSeconds,
		Status:          StatusHealthy,
		AddedAt:         time.Now().UTC(),
	}

	w.probeDomain(ctx, item)

	w.mu.Lock()
	w.domains[id] = item
	w.mu.Unlock()

	return item, nil
}

// Remove deletes a monitored target by ID.
func (w *DomainWatcher) Remove(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.domains[id]; exists {
		delete(w.domains, id)
		return true
	}
	return false
}

// List returns all currently monitored domains.
func (w *DomainWatcher) List() []MonitoredDomain {
	w.mu.RLock()
	defer w.mu.RUnlock()

	res := make([]MonitoredDomain, 0, len(w.domains))
	for _, d := range w.domains {
		res = append(res, *d)
	}
	return res
}

// Check triggers an immediate probe for a specific monitored domain.
func (w *DomainWatcher) Check(ctx context.Context, id string) (*MonitoredDomain, error) {
	w.mu.RLock()
	item, exists := w.domains[id]
	w.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("monitored domain %s not found", id)
	}

	w.probeDomain(ctx, item)
	return item, nil
}

func (w *DomainWatcher) checkScheduled(ctx context.Context) {
	w.mu.RLock()
	var targets []*MonitoredDomain
	now := time.Now()
	for _, d := range w.domains {
		if now.Sub(d.LastChecked) >= time.Duration(d.IntervalSeconds)*time.Second {
			targets = append(targets, d)
		}
	}
	w.mu.RUnlock()

	for _, t := range targets {
		w.probeDomain(ctx, t)
	}
}

func (w *DomainWatcher) probeDomain(ctx context.Context, item *MonitoredDomain) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	opts := handshake.ProbeOptions{
		RootCAs:            w.rootPool,
		InsecureSkipVerify: true,
	}

	oldStatus := item.Status
	result, err := handshake.ProbeEndpoint(probeCtx, item.Target, opts)

	item.LastChecked = time.Now().UTC()
	if err != nil || result == nil || len(result.PeerCertificates) == 0 {
		item.Status = StatusUnreachable
		if err != nil {
			item.LastError = err.Error()
		} else {
			item.LastError = "No certificates presented"
		}
		if w.onAlert != nil && oldStatus != StatusUnreachable {
			w.onAlert(*item, "domain_unreachable")
		}
		return
	}

	item.Host = result.Host
	item.Port = result.Port
	item.TLSVersion = result.TLSVersion
	item.CipherSuite = result.Cipher.Name
	item.LatencyMs = result.TotalDurationMs
	item.LastError = ""

	leaf := result.PeerCertificates[0]
	item.CommonName = leaf.CommonName
	item.Issuer = leaf.Issuer
	item.DaysRemaining = leaf.DaysRemaining
	item.ExpiresAt = leaf.NotAfter.Format(time.RFC3339)
	item.FingerprintSHA256 = leaf.FingerprintSHA256

	if leaf.IsExpired {
		item.Status = StatusExpired
		if w.onAlert != nil && oldStatus != StatusExpired {
			w.onAlert(*item, "certificate_expired")
		}
	} else if leaf.DaysRemaining <= 14 {
		item.Status = StatusExpiringSoon
		if w.onAlert != nil && oldStatus != StatusExpiringSoon {
			w.onAlert(*item, "expiring_soon")
		}
	} else {
		item.Status = StatusHealthy
	}
}
