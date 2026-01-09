// network-liveness-monitor is a minimal reproducer for the cloud network liveness
// monitors (aws/gcp/azure). It continuously polls an HTTP health endpoint and prints
// disruption rates measured over 5-minute intervals.
//
// This monitor tracks:
//   - TCP connection establishment time (dial latency)
//   - TLS handshake time
//   - Time to first response byte
//   - Total request time
//   - Success/failure rates with error categorization
//
// Usage:
//
//	go run cmd/network-liveness-monitor/main.go [flags] <target>
//
// Where <target> can be:
//   - "aws"   - AWS test endpoint
//   - "gcp"   - GCP test endpoint
//   - "azure" - Azure test endpoint
//   - Any URL - Custom endpoint (e.g., http://localhost:8080/health)
//
// Examples:
//
//	# Monitor GCP network liveness endpoint
//	go run cmd/network-liveness-monitor/main.go gcp
//
//	# Monitor AWS network liveness endpoint with JSONL output
//	go run cmd/network-liveness-monitor/main.go --output jsonl aws
//
//	# Monitor with faster reporting interval
//	go run cmd/network-liveness-monitor/main.go --report 30s gcp
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// Cloud provider endpoints - same URLs used by the actual monitors
var cloudEndpoints = map[string]string{
	"aws":   "http://trt-openshift-tests-endpoint-lb-1161093811.us-east-1.elb.amazonaws.com/health",
	"gcp":   "http://35.212.33.188/health",
	"azure": "http://20.127.186.25/health",
}

const (
	// Sampling interval - same as the actual monitor
	defaultSampleInterval = 1 * time.Second

	// Report interval for disruption statistics
	defaultReportInterval = 5 * time.Minute

	// Timeout for individual requests - same as actual monitor
	requestTimeout = 20 * time.Second
)

// ErrorCategory categorizes the type of failure
type ErrorCategory string

const (
	ErrNone       ErrorCategory = ""
	ErrDNS        ErrorCategory = "dns"
	ErrConnect    ErrorCategory = "connect"
	ErrTLS        ErrorCategory = "tls"
	ErrTimeout    ErrorCategory = "timeout"
	ErrHTTPStatus ErrorCategory = "http_status"
	ErrReadBody   ErrorCategory = "read_body"
	ErrOther      ErrorCategory = "other"
)

// SampleResult is the JSONL output format for each sample
type SampleResult struct {
	Timestamp      string  `json:"timestamp"`
	Success        bool    `json:"success"`
	ErrorCategory  string  `json:"error_category,omitempty"`
	ErrorMessage   string  `json:"error_message,omitempty"`
	DNSMs          float64 `json:"dns_ms,omitempty"`
	ConnectMs      float64 `json:"connect_ms,omitempty"`
	TLSMs          float64 `json:"tls_ms,omitempty"`
	TTFBMs         float64 `json:"ttfb_ms,omitempty"`
	TotalMs        float64 `json:"total_ms,omitempty"`
	ConsecutiveFail int64  `json:"consecutive_fail,omitempty"`
}

// TimingInfo captures latency at each phase of the request
type TimingInfo struct {
	DNSStart     time.Time
	DNSDone      time.Time
	ConnectStart time.Time
	ConnectDone  time.Time
	TLSStart     time.Time
	TLSDone      time.Time
	FirstByte    time.Time
	RequestStart time.Time
	RequestDone  time.Time
}

func (t *TimingInfo) DNSLatency() time.Duration {
	if t.DNSDone.IsZero() || t.DNSStart.IsZero() {
		return 0
	}
	return t.DNSDone.Sub(t.DNSStart)
}

func (t *TimingInfo) ConnectLatency() time.Duration {
	if t.ConnectDone.IsZero() || t.ConnectStart.IsZero() {
		return 0
	}
	return t.ConnectDone.Sub(t.ConnectStart)
}

func (t *TimingInfo) TLSLatency() time.Duration {
	if t.TLSDone.IsZero() || t.TLSStart.IsZero() {
		return 0
	}
	return t.TLSDone.Sub(t.TLSStart)
}

func (t *TimingInfo) TimeToFirstByte() time.Duration {
	if t.FirstByte.IsZero() || t.RequestStart.IsZero() {
		return 0
	}
	return t.FirstByte.Sub(t.RequestStart)
}

func (t *TimingInfo) TotalLatency() time.Duration {
	if t.RequestDone.IsZero() || t.RequestStart.IsZero() {
		return 0
	}
	return t.RequestDone.Sub(t.RequestStart)
}

// Stats tracks the success/failure counts and latencies for a time window
type Stats struct {
	mu              sync.Mutex
	totalRequests   int64
	failedRequests  int64
	windowStart     time.Time
	consecutiveFail int64
	lastError       string
	lastErrorCat    ErrorCategory

	// Error counts by category
	errorCounts map[ErrorCategory]int64

	// Latency tracking (in microseconds for precision)
	connectLatencies []int64 // TCP connect times
	tlsLatencies     []int64 // TLS handshake times
	ttfbLatencies    []int64 // Time to first byte
	totalLatencies   []int64 // Total request times
}

func newStats() *Stats {
	return &Stats{
		windowStart: time.Now(),
		errorCounts: make(map[ErrorCategory]int64),
	}
}

// Config holds the monitor configuration
type Config struct {
	URL            string
	Provider       string // "aws", "gcp", "azure", or "custom"
	SampleInterval time.Duration
	ReportInterval time.Duration
	OutputFormat   string // "text" or "jsonl"
}

func main() {
	// Parse command line flags
	sampleInterval := flag.Duration("sample", defaultSampleInterval, "sampling interval")
	reportInterval := flag.Duration("report", defaultReportInterval, "report interval for statistics")
	outputFormat := flag.String("output", "text", "output format: text or jsonl")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <target>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Target can be:\n")
		fmt.Fprintf(os.Stderr, "  aws    - AWS test endpoint (%s)\n", cloudEndpoints["aws"])
		fmt.Fprintf(os.Stderr, "  gcp    - GCP test endpoint (%s)\n", cloudEndpoints["gcp"])
		fmt.Fprintf(os.Stderr, "  azure  - Azure test endpoint (%s)\n", cloudEndpoints["azure"])
		fmt.Fprintf(os.Stderr, "  <URL>  - Custom endpoint (e.g., http://localhost:8080/health)\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Validate output format
	*outputFormat = strings.ToLower(*outputFormat)
	if *outputFormat != "text" && *outputFormat != "jsonl" {
		fmt.Fprintf(os.Stderr, "Error: invalid output format %q, must be 'text' or 'jsonl'\n", *outputFormat)
		os.Exit(1)
	}

	// Resolve the target to a URL
	target := flag.Arg(0)
	targetURL, provider := resolveTarget(target)

	config := Config{
		URL:            targetURL,
		Provider:       provider,
		SampleInterval: *sampleInterval,
		ReportInterval: *reportInterval,
		OutputFormat:   *outputFormat,
	}

	// Only print header for text mode
	if config.OutputFormat == "text" {
		fmt.Println("Network Liveness Monitor - New Connections")
		fmt.Println("===========================================")
		fmt.Printf("Provider: %s\n", config.Provider)
		fmt.Printf("Target URL: %s\n", config.URL)
		fmt.Printf("Sample Interval: %v\n", config.SampleInterval)
		fmt.Printf("Report Interval: %v\n", config.ReportInterval)
		fmt.Printf("Request Timeout: %v\n", requestTimeout)
		fmt.Println()
		fmt.Println("Tracking: DNS lookup, TCP connect, TLS handshake, time-to-first-byte")
		fmt.Println()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if config.OutputFormat == "text" {
			fmt.Println("\nShutting down...")
		}
		cancel()
	}()

	stats := newStats()

	// Start the reporter goroutine (only for text mode)
	if config.OutputFormat == "text" {
		go reportStats(ctx, stats, config)
	}

	// Run the monitor
	runMonitor(ctx, stats, config)

	// Final report (only for text mode)
	if config.OutputFormat == "text" {
		printStats(stats, "Final", config.SampleInterval)
	}
}

// resolveTarget converts a target string to a URL and provider name
func resolveTarget(target string) (url, provider string) {
	targetLower := strings.ToLower(target)

	// Check if it's a known cloud provider
	if endpoint, ok := cloudEndpoints[targetLower]; ok {
		return endpoint, strings.ToUpper(targetLower)
	}

	// Otherwise treat it as a URL
	return target, "custom"
}

// createNewConnectionClient creates an HTTP client that does NOT reuse connections.
// This mimics the behavior of monitorapi.NewConnectionType.
func createNewConnectionClient() *http.Client {
	timeoutForPartOfRequest := requestTimeout * 4 / 5

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeoutForPartOfRequest,
			KeepAlive: -1, // disable keep-alive
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true, // disable connection reuse - NEW connection each time
		TLSHandshakeTimeout:   timeoutForPartOfRequest,
		IdleConnTimeout:       timeoutForPartOfRequest,
		ResponseHeaderTimeout: timeoutForPartOfRequest,
		ExpectContinueTimeout: timeoutForPartOfRequest,
		Proxy:                 http.ProxyFromEnvironment,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
}

func runMonitor(ctx context.Context, stats *Stats, config Config) {
	client := createNewConnectionClient()
	ticker := time.NewTicker(config.SampleInterval)
	defer ticker.Stop()

	if config.OutputFormat == "text" {
		fmt.Printf("[%s] Starting monitoring...\n", time.Now().Format(time.RFC3339))
	}

	var consecutiveFails int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			timing, errCat, err := checkConnectionWithTiming(ctx, client, config.URL)

			stats.mu.Lock()
			stats.totalRequests++

			// Record latencies for successful connections (even if HTTP failed)
			if timing.ConnectLatency() > 0 {
				stats.connectLatencies = append(stats.connectLatencies, timing.ConnectLatency().Microseconds())
			}
			if timing.TLSLatency() > 0 {
				stats.tlsLatencies = append(stats.tlsLatencies, timing.TLSLatency().Microseconds())
			}
			if timing.TimeToFirstByte() > 0 {
				stats.ttfbLatencies = append(stats.ttfbLatencies, timing.TimeToFirstByte().Microseconds())
			}
			if timing.TotalLatency() > 0 {
				stats.totalLatencies = append(stats.totalLatencies, timing.TotalLatency().Microseconds())
			}

			if err != nil {
				stats.failedRequests++
				consecutiveFails++
				stats.consecutiveFail = consecutiveFails
				stats.lastError = err.Error()
				stats.lastErrorCat = errCat
				stats.errorCounts[errCat]++

				if config.OutputFormat == "jsonl" {
					outputJSONL(timing, errCat, err, consecutiveFails)
				} else {
					// Log the failure with timing info
					timingStr := formatTiming(timing)
					fmt.Printf("[%s] FAILURE #%d [%s] (consecutive: %d): %v %s\n",
						time.Now().Format(time.RFC3339),
						stats.failedRequests,
						errCat,
						consecutiveFails,
						err,
						timingStr)
				}
			} else {
				if config.OutputFormat == "jsonl" {
					outputJSONL(timing, ErrNone, nil, 0)
				} else {
					if consecutiveFails > 0 {
						fmt.Printf("[%s] RECOVERED after %d consecutive failures (connect: %v, ttfb: %v)\n",
							time.Now().Format(time.RFC3339),
							consecutiveFails,
							timing.ConnectLatency().Round(time.Millisecond),
							timing.TimeToFirstByte().Round(time.Millisecond))
					}
				}
				consecutiveFails = 0
				stats.consecutiveFail = 0
				stats.lastError = ""
				stats.lastErrorCat = ErrNone
			}
			stats.mu.Unlock()
		}
	}
}

func outputJSONL(timing TimingInfo, errCat ErrorCategory, err error, consecutiveFail int64) {
	result := SampleResult{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Success:   err == nil,
	}

	if err != nil {
		result.ErrorCategory = string(errCat)
		result.ErrorMessage = err.Error()
		result.ConsecutiveFail = consecutiveFail
	}

	if timing.DNSLatency() > 0 {
		result.DNSMs = float64(timing.DNSLatency().Microseconds()) / 1000.0
	}
	if timing.ConnectLatency() > 0 {
		result.ConnectMs = float64(timing.ConnectLatency().Microseconds()) / 1000.0
	}
	if timing.TLSLatency() > 0 {
		result.TLSMs = float64(timing.TLSLatency().Microseconds()) / 1000.0
	}
	if timing.TimeToFirstByte() > 0 {
		result.TTFBMs = float64(timing.TimeToFirstByte().Microseconds()) / 1000.0
	}
	if timing.TotalLatency() > 0 {
		result.TotalMs = float64(timing.TotalLatency().Microseconds()) / 1000.0
	}

	jsonBytes, _ := json.Marshal(result)
	fmt.Println(string(jsonBytes))
}

func formatTiming(t TimingInfo) string {
	var parts []string
	if t.DNSLatency() > 0 {
		parts = append(parts, fmt.Sprintf("dns=%v", t.DNSLatency().Round(time.Millisecond)))
	}
	if t.ConnectLatency() > 0 {
		parts = append(parts, fmt.Sprintf("connect=%v", t.ConnectLatency().Round(time.Millisecond)))
	}
	if t.TLSLatency() > 0 {
		parts = append(parts, fmt.Sprintf("tls=%v", t.TLSLatency().Round(time.Millisecond)))
	}
	if t.TimeToFirstByte() > 0 {
		parts = append(parts, fmt.Sprintf("ttfb=%v", t.TimeToFirstByte().Round(time.Millisecond)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// checkConnectionWithTiming performs the request and captures timing at each phase
func checkConnectionWithTiming(ctx context.Context, client *http.Client, url string) (TimingInfo, ErrorCategory, error) {
	var timing TimingInfo
	timing.RequestStart = time.Now()

	// Create request with timeout
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout*3/2)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		timing.RequestDone = time.Now()
		return timing, ErrOther, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Audit-ID header - required by the cloud test endpoints
	// This matches what the original monitor does in disruption_backend_sampler.go
	auditID := uuid.New().String()
	req.Header.Set("Audit-ID", auditID)

	// Add tracing to capture connection timing
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			timing.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			timing.DNSDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			timing.ConnectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			timing.ConnectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			timing.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			timing.TLSDone = time.Now()
		},
		GotFirstResponseByte: func() {
			timing.FirstByte = time.Now()
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, trace))

	resp, err := client.Do(req)
	timing.RequestDone = time.Now()

	if err != nil {
		errCat := categorizeError(err, timing)
		return timing, errCat, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read and discard body
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return timing, ErrReadBody, fmt.Errorf("failed to read body: %w", err)
	}

	// Check for successful status code (2xx or 3xx)
	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return timing, ErrHTTPStatus, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	return timing, ErrNone, nil
}

// categorizeError determines what type of failure occurred based on error and timing
func categorizeError(err error, timing TimingInfo) ErrorCategory {
	errStr := err.Error()

	// Check timing to understand where we failed
	switch {
	case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup"):
		return ErrDNS
	case strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable"):
		return ErrConnect
	case strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "x509:"):
		return ErrTLS
	case strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "context canceled"):
		// Determine which phase timed out based on timing
		if timing.ConnectDone.IsZero() {
			return ErrConnect // Timed out during connect
		}
		if timing.TLSDone.IsZero() && timing.TLSStart.After(time.Time{}) {
			return ErrTLS // Timed out during TLS
		}
		return ErrTimeout
	default:
		return ErrOther
	}
}

func reportStats(ctx context.Context, stats *Stats, config Config) {
	ticker := time.NewTicker(config.ReportInterval)
	defer ticker.Stop()

	windowNum := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			windowNum++
			printStats(stats, fmt.Sprintf("Window #%d", windowNum), config.SampleInterval)

			// Reset window stats
			stats.mu.Lock()
			stats.totalRequests = 0
			stats.failedRequests = 0
			stats.windowStart = time.Now()
			stats.errorCounts = make(map[ErrorCategory]int64)
			stats.connectLatencies = nil
			stats.tlsLatencies = nil
			stats.ttfbLatencies = nil
			stats.totalLatencies = nil
			stats.mu.Unlock()
		}
	}
}

func printStats(stats *Stats, label string, sampleInterval time.Duration) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	elapsed := time.Since(stats.windowStart)
	disruptionRate := float64(0)
	if stats.totalRequests > 0 {
		disruptionRate = float64(stats.failedRequests) / float64(stats.totalRequests) * 100
	}

	// Calculate disruption in seconds
	disruptionSeconds := float64(stats.failedRequests) * sampleInterval.Seconds()

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 %s Report (%v elapsed)\n", label, elapsed.Round(time.Second))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Println()
	fmt.Println("REQUEST STATISTICS:")
	fmt.Printf("  Total Requests:     %d\n", stats.totalRequests)
	fmt.Printf("  Successful:         %d\n", stats.totalRequests-stats.failedRequests)
	fmt.Printf("  Failed:             %d\n", stats.failedRequests)
	fmt.Printf("  Disruption Rate:    %.2f%%\n", disruptionRate)
	fmt.Printf("  Disruption Time:    %.1fs\n", disruptionSeconds)

	// Error breakdown
	if stats.failedRequests > 0 {
		fmt.Println()
		fmt.Println("FAILURE BREAKDOWN:")
		for cat, count := range stats.errorCounts {
			pct := float64(count) / float64(stats.failedRequests) * 100
			fmt.Printf("  %-12s %5d (%.1f%%)\n", cat+":", count, pct)
		}
		if stats.consecutiveFail > 0 {
			fmt.Printf("\n  Current Outage:     %d consecutive failures\n", stats.consecutiveFail)
			fmt.Printf("  Last Error [%s]:    %s\n", stats.lastErrorCat, stats.lastError)
		}
	}

	// Latency statistics
	fmt.Println()
	fmt.Println("CONNECTION LATENCY (successful connections only):")
	printLatencyStats("  TCP Connect:", stats.connectLatencies)
	printLatencyStats("  TLS Handshake:", stats.tlsLatencies)
	printLatencyStats("  Time to First Byte:", stats.ttfbLatencies)
	printLatencyStats("  Total Request:", stats.totalLatencies)

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

func printLatencyStats(label string, latencies []int64) {
	if len(latencies) == 0 {
		fmt.Printf("%s n/a\n", label)
		return
	}

	// Sort for percentile calculation
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	min := time.Duration(sorted[0]) * time.Microsecond
	max := time.Duration(sorted[len(sorted)-1]) * time.Microsecond
	p50 := time.Duration(sorted[len(sorted)/2]) * time.Microsecond
	p99Idx := int(float64(len(sorted)) * 0.99)
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}
	p99 := time.Duration(sorted[p99Idx]) * time.Microsecond

	var sum int64
	for _, v := range sorted {
		sum += v
	}
	avg := time.Duration(sum/int64(len(sorted))) * time.Microsecond

	fmt.Printf("%s min=%v avg=%v p50=%v p99=%v max=%v (n=%d)\n",
		label,
		min.Round(time.Millisecond),
		avg.Round(time.Millisecond),
		p50.Round(time.Millisecond),
		p99.Round(time.Millisecond),
		max.Round(time.Millisecond),
		len(sorted))
}
