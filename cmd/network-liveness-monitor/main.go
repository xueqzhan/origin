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
//   - ICMP ping to intermediate network nodes (discovered via traceroute)
//   - Optional traceroute diagnostics during disruptions
//
// At startup, the monitor runs traceroute to discover intermediate network nodes,
// then continuously pings these nodes along with the endpoint and local host to
// identify where network issues occur (application vs intermediate hops vs endpoint).
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
//	# Monitor GCP network liveness endpoint (auto-discovers intermediate nodes)
//	go run cmd/network-liveness-monitor/main.go gcp
//
//	# Monitor AWS network liveness endpoint with JSONL output
//	go run cmd/network-liveness-monitor/main.go --output jsonl aws
//
//	# Monitor with faster reporting interval
//	go run cmd/network-liveness-monitor/main.go --report 30s gcp
//
//	# Monitor with traceroute enabled (runs after 3 consecutive failures)
//	go run cmd/network-liveness-monitor/main.go --traceroute --traceroute-threshold 3 gcp
//
//	# Monitor with traceroute and custom minimum interval between traces
//	go run cmd/network-liveness-monitor/main.go --traceroute --traceroute-interval 10m gcp
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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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

// PingResult represents the result of a single ping check
type PingResult struct {
	Target      string  `json:"target"`
	Success     bool    `json:"success"`
	LatencyMs   float64 `json:"latency_ms,omitempty"`
	ErrorMsg    string  `json:"error,omitempty"`
	PacketLoss  float64 `json:"packet_loss,omitempty"`
}

// SampleResult is the JSONL output format for each sample
type SampleResult struct {
	Timestamp       string       `json:"timestamp"`
	Success         bool         `json:"success"`
	ErrorCategory   string       `json:"error_category,omitempty"`
	ErrorMessage    string       `json:"error_message,omitempty"`
	DNSMs           float64      `json:"dns_ms,omitempty"`
	ConnectMs       float64      `json:"connect_ms,omitempty"`
	TLSMs           float64      `json:"tls_ms,omitempty"`
	TTFBMs          float64      `json:"ttfb_ms,omitempty"`
	TotalMs         float64      `json:"total_ms,omitempty"`
	ConsecutiveFail int64        `json:"consecutive_fail,omitempty"`
	TracerouteRun   bool         `json:"traceroute_run,omitempty"`
	TracerouteOut   string       `json:"traceroute_output,omitempty"`
	PingResults     []PingResult `json:"ping_results,omitempty"`
}

// TracerouteState tracks when traceroute was last run to avoid excessive executions
type TracerouteState struct {
	mu               sync.Mutex
	lastRun          time.Time
	minInterval      time.Duration
	failureThreshold int64
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

// PingStats tracks ping statistics for a single target
type PingStats struct {
	totalPings   int64
	failedPings  int64
	latencies    []int64 // in microseconds
	lastError    string
	consecutiveFail int64
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

	// Ping statistics per target
	pingStats map[string]*PingStats
}

func newStats() *Stats {
	return &Stats{
		windowStart: time.Now(),
		errorCounts: make(map[ErrorCategory]int64),
		pingStats:   make(map[string]*PingStats),
	}
}

// Config holds the monitor configuration
type Config struct {
	URL                     string
	Provider                string // "aws", "gcp", "azure", or "custom"
	SampleInterval          time.Duration
	ReportInterval          time.Duration
	OutputFormat            string // "text" or "jsonl"
	EnableTraceroute        bool
	TracerouteInterval      time.Duration
	TracerouteFailThreshold int64
	PingTargets             []string // Additional targets to ping
}

func main() {
	// Parse command line flags
	sampleInterval := flag.Duration("sample", defaultSampleInterval, "sampling interval")
	reportInterval := flag.Duration("report", defaultReportInterval, "report interval for statistics")
	outputFormat := flag.String("output", "text", "output format: text or jsonl")
	enableTraceroute := flag.Bool("traceroute", false, "enable traceroute on disruptions")
	tracerouteInterval := flag.Duration("traceroute-interval", 5*time.Minute, "minimum interval between traceroute runs")
	tracerouteFailThreshold := flag.Int64("traceroute-threshold", 3, "number of consecutive failures before triggering traceroute")

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
		URL:                     targetURL,
		Provider:                provider,
		SampleInterval:          *sampleInterval,
		ReportInterval:          *reportInterval,
		OutputFormat:            *outputFormat,
		EnableTraceroute:        *enableTraceroute,
		TracerouteInterval:      *tracerouteInterval,
		TracerouteFailThreshold: *tracerouteFailThreshold,
		PingTargets:             nil, // Will be populated after discovery
	}

	// Only print initial header for text mode
	if config.OutputFormat == "text" {
		fmt.Println("Network Liveness Monitor - New Connections")
		fmt.Println("===========================================")
		fmt.Printf("Provider: %s\n", config.Provider)
		fmt.Printf("Target URL: %s\n", config.URL)
		fmt.Printf("Sample Interval: %v\n", config.SampleInterval)
		fmt.Printf("Report Interval: %v\n", config.ReportInterval)
		fmt.Printf("Request Timeout: %v\n", requestTimeout)
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

	// Discover ping targets dynamically via traceroute
	config.PingTargets = discoverPingTargets(ctx, config.URL, config.OutputFormat)

	// Print tracking info after discovery
	if config.OutputFormat == "text" {
		fmt.Println("Tracking: DNS lookup, TCP connect, TLS handshake, time-to-first-byte")
		if len(config.PingTargets) > 0 {
			fmt.Printf("Ping Targets (%d total): %s\n", len(config.PingTargets), strings.Join(config.PingTargets, ", "))
		}
		fmt.Println()
	}

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

	// Initialize traceroute state
	var traceState *TracerouteState
	if config.EnableTraceroute {
		traceState = &TracerouteState{
			minInterval:      config.TracerouteInterval,
			failureThreshold: config.TracerouteFailThreshold,
		}
		if config.OutputFormat == "text" {
			fmt.Printf("[%s] Traceroute enabled (threshold: %d failures, min interval: %v)\n",
				time.Now().Format(time.RFC3339),
				config.TracerouteFailThreshold,
				config.TracerouteInterval)
		}
	}

	if config.OutputFormat == "text" {
		fmt.Printf("[%s] Starting monitoring...\n", time.Now().Format(time.RFC3339))
	}

	var consecutiveFails int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Run HTTP check and pings in parallel
			var timing TimingInfo
			var errCat ErrorCategory
			var err error
			var pingResults []PingResult

			var wg sync.WaitGroup

			// HTTP check
			wg.Add(1)
			go func() {
				defer wg.Done()
				timing, errCat, err = checkConnectionWithTiming(ctx, client, config.URL)
			}()

			// Ping checks (if configured)
			if len(config.PingTargets) > 0 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					pingResults = runPingsParallel(ctx, config.PingTargets)
				}()
			}

			wg.Wait()

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

			// Record ping statistics
			for _, pingResult := range pingResults {
				if stats.pingStats[pingResult.Target] == nil {
					stats.pingStats[pingResult.Target] = &PingStats{}
				}
				pstat := stats.pingStats[pingResult.Target]
				pstat.totalPings++

				if pingResult.Success {
					pstat.latencies = append(pstat.latencies, int64(pingResult.LatencyMs*1000)) // Convert to microseconds
					pstat.consecutiveFail = 0
				} else {
					pstat.failedPings++
					pstat.consecutiveFail++
					pstat.lastError = pingResult.ErrorMsg
				}
			}

			var tracerouteOutput string
			var tracerouteRun bool

			if err != nil {
				stats.failedRequests++
				consecutiveFails++
				stats.consecutiveFail = consecutiveFails
				stats.lastError = err.Error()
				stats.lastErrorCat = errCat
				stats.errorCounts[errCat]++

				// Run traceroute if enabled and conditions are met
				if config.EnableTraceroute && traceState.shouldRunTraceroute(consecutiveFails) {
					tracerouteRun = true
					if config.OutputFormat == "text" {
						fmt.Printf("[%s] Running traceroute (consecutive failures: %d)...\n",
							time.Now().Format(time.RFC3339),
							consecutiveFails)
					}

					// Run traceroute in background to avoid blocking
					trOutput, trErr := runTraceroute(ctx, config.URL)
					if trErr != nil {
						tracerouteOutput = fmt.Sprintf("Traceroute error: %v\nPartial output:\n%s", trErr, trOutput)
					} else {
						tracerouteOutput = trOutput
					}
					tracerouteOutput = cleanTracerouteOutput(tracerouteOutput)
				}

				if config.OutputFormat == "jsonl" {
					outputJSONL(timing, errCat, err, consecutiveFails, tracerouteRun, tracerouteOutput, pingResults)
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

					// Print ping results
					if len(pingResults) > 0 {
						printPingResults(pingResults)
					}

					// Print traceroute output if available
					if tracerouteRun && tracerouteOutput != "" {
						fmt.Println("--- Traceroute Output ---")
						fmt.Println(tracerouteOutput)
						fmt.Println("--- End Traceroute ---")
					}
				}
			} else {
				if config.OutputFormat == "jsonl" {
					outputJSONL(timing, ErrNone, nil, 0, false, "", pingResults)
				} else {
					if consecutiveFails > 0 {
						fmt.Printf("[%s] RECOVERED after %d consecutive failures (connect: %v, ttfb: %v)\n",
							time.Now().Format(time.RFC3339),
							consecutiveFails,
							timing.ConnectLatency().Round(time.Millisecond),
							timing.TimeToFirstByte().Round(time.Millisecond))
					}
					// Print ping results on success too
					if len(pingResults) > 0 {
						printPingResults(pingResults)
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

func outputJSONL(timing TimingInfo, errCat ErrorCategory, err error, consecutiveFail int64, tracerouteRun bool, tracerouteOutput string, pingResults []PingResult) {
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

	if tracerouteRun {
		result.TracerouteRun = true
		result.TracerouteOut = tracerouteOutput
	}

	if len(pingResults) > 0 {
		result.PingResults = pingResults
	}

	jsonBytes, _ := json.Marshal(result)
	fmt.Println(string(jsonBytes))
}

// printPingResults prints ping results in text format
func printPingResults(results []PingResult) {
	fmt.Print("  Pings: ")
	for i, result := range results {
		if i > 0 {
			fmt.Print(", ")
		}
		if result.Success {
			fmt.Printf("%s=%.1fms", result.Target, result.LatencyMs)
		} else {
			fmt.Printf("%s=FAIL", result.Target)
		}
	}
	fmt.Println()
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

// extractHostname extracts the hostname or IP from a URL
func extractHostname(targetURL string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// Get the hostname without port
	host := parsedURL.Hostname()
	if host == "" {
		return "", fmt.Errorf("no hostname found in URL: %s", targetURL)
	}

	return host, nil
}

// runTraceroute executes traceroute to the target and returns the output
func runTraceroute(ctx context.Context, targetURL string) (string, error) {
	hostname, err := extractHostname(targetURL)
	if err != nil {
		return "", err
	}

	// Create a timeout context for traceroute (30 seconds max)
	traceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Determine the traceroute command based on OS
	// On Linux: traceroute, On macOS: traceroute, On Windows: tracert
	var cmd *exec.Cmd
	if _, err := exec.LookPath("traceroute"); err == nil {
		// Unix-like systems (Linux, macOS)
		// Use -m 15 to limit max hops, -w 2 for 2 second timeout per hop
		cmd = exec.CommandContext(traceCtx, "traceroute", "-m", "15", "-w", "2", hostname)
	} else if _, err := exec.LookPath("tracert"); err == nil {
		// Windows
		cmd = exec.CommandContext(traceCtx, "tracert", "-h", "15", "-w", "2000", hostname)
	} else {
		return "", fmt.Errorf("traceroute command not found (tried traceroute and tracert)")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Include partial output even on error
		return string(output), fmt.Errorf("traceroute failed: %w", err)
	}

	return string(output), nil
}

// parseTracerouteForIPs extracts IP addresses from traceroute output
// Returns a list of unique IP addresses of intermediate hops that responded
func parseTracerouteForIPs(tracerouteOutput string) []string {
	var ips []string
	seen := make(map[string]bool)

	// IP address regex - matches IPv4 addresses
	// Pattern: xxx.xxx.xxx.xxx where xxx is 1-3 digits
	ipRegex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

	lines := strings.Split(tracerouteOutput, "\n")
	for _, line := range lines {
		// Skip lines with no response (containing "* * *")
		if strings.Contains(line, "* * *") {
			continue
		}

		// Skip the header line
		if strings.Contains(line, "traceroute to") || strings.Contains(line, "Tracing route") {
			continue
		}

		// Extract all IP addresses from the line
		matches := ipRegex.FindAllString(line, -1)
		for _, ip := range matches {
			// Skip invalid IPs and duplicates
			if !seen[ip] && isValidIP(ip) {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// isValidIP validates if an IP address is valid and not a special address
func isValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Skip localhost
	if ip.IsLoopback() {
		return false
	}

	// Skip multicast
	if ip.IsMulticast() {
		return false
	}

	// Skip unspecified (0.0.0.0)
	if ip.IsUnspecified() {
		return false
	}

	return true
}

// discoverPingTargets runs traceroute and discovers intermediate nodes to ping
func discoverPingTargets(ctx context.Context, targetURL string, outputFormat string) []string {
	if outputFormat == "text" {
		fmt.Println("Discovering intermediate network nodes via traceroute...")
	}

	// Run traceroute to discover the path
	// Even if it fails/times out, we'll get partial output with some intermediate nodes
	traceOutput, traceErr := runTraceroute(ctx, targetURL)

	// Parse traceroute output to find intermediate hops (even if traceroute failed)
	intermediateNodes := parseTracerouteForIPs(traceOutput)

	if outputFormat == "text" {
		if traceErr != nil {
			fmt.Printf("Note: traceroute did not complete (%v), using partial results\n", traceErr)
		}
		fmt.Printf("Discovered %d intermediate nodes from traceroute\n", len(intermediateNodes))
		fmt.Println("Testing which nodes are pingable...")
	}

	// Test each intermediate node to see if it responds to ping
	// Only include pingable nodes in the final list
	var pingableNodes []string
	maxNodesToTest := 20 // Test up to 20 nodes to avoid too long startup
	testCount := len(intermediateNodes)
	if testCount > maxNodesToTest {
		testCount = maxNodesToTest
	}

	// Test nodes in parallel for faster discovery
	type testResult struct {
		node    string
		success bool
	}
	resultsChan := make(chan testResult, testCount)

	for i := 0; i < testCount; i++ {
		node := intermediateNodes[i]
		go func(n string) {
			result := runPing(ctx, n)
			resultsChan <- testResult{node: n, success: result.Success}
		}(node)
	}

	// Blocklist of unreliable nodes to exclude
	blocklist := map[string]bool{
		"242.10.91.181": true, // Consistently unreliable node on worker2
	}

	// Collect results
	for i := 0; i < testCount; i++ {
		result := <-resultsChan
		if result.success && !blocklist[result.node] {
			pingableNodes = append(pingableNodes, result.node)
		}
	}

	// Get endpoint hostname
	endpointHost, _ := extractHostname(targetURL)

	// Build target list: pingable intermediate nodes + endpoint + local hostname
	var targets []string

	// Add pingable intermediate nodes (limit to reasonable number, e.g., 10)
	maxPingableNodes := 10
	for i, node := range pingableNodes {
		if i >= maxPingableNodes {
			break
		}
		targets = append(targets, node)
	}

	// Add endpoint host if not already included (test it first)
	if endpointHost != "" {
		found := false
		for _, t := range targets {
			if t == endpointHost {
				found = true
				break
			}
		}
		if !found {
			// Test if endpoint is pingable
			endpointPing := runPing(ctx, endpointHost)
			if endpointPing.Success {
				targets = append(targets, endpointHost)
			} else if outputFormat == "text" {
				fmt.Printf("Note: endpoint %s is not responding to ping\n", endpointHost)
			}
		}
	}

	// Add local hostname if it's pingable
	localHost, err := os.Hostname()
	if err == nil && localHost != "" {
		localPing := runPing(ctx, localHost)
		if localPing.Success {
			targets = append(targets, localHost)
		}
	}

	if outputFormat == "text" {
		fmt.Printf("Found %d pingable nodes out of %d tested, total %d ping targets\n",
			len(pingableNodes), testCount, len(targets))
		if len(pingableNodes) > 0 {
			// Show which nodes are pingable
			displayNodes := pingableNodes
			if len(displayNodes) > 15 {
				displayNodes = displayNodes[:15]
			}
			fmt.Printf("Pingable intermediate nodes: %s", strings.Join(displayNodes, ", "))
			if len(pingableNodes) > 15 {
				fmt.Printf(" ... and %d more", len(pingableNodes)-15)
			}
			fmt.Println()
		} else {
			fmt.Println("Warning: No pingable intermediate nodes found")
		}
		fmt.Println()
	}

	return targets
}

// shouldRunTraceroute determines if traceroute should be executed based on state
func (ts *TracerouteState) shouldRunTraceroute(consecutiveFails int64) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Check if we've hit the failure threshold
	if consecutiveFails < ts.failureThreshold {
		return false
	}

	// Check if enough time has passed since last run
	if time.Since(ts.lastRun) < ts.minInterval {
		return false
	}

	// Update last run time
	ts.lastRun = time.Now()
	return true
}

// cleanTracerouteOutput removes ANSI escape codes and limits output size
func cleanTracerouteOutput(output string) string {
	// Remove ANSI escape codes
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	cleaned := ansiRegex.ReplaceAllString(output, "")

	// Limit output to 2000 characters to avoid excessive logging
	if len(cleaned) > 2000 {
		cleaned = cleaned[:2000] + "... (truncated)"
	}

	return cleaned
}

// runPing executes a single ping to the target and returns the result
func runPing(ctx context.Context, target string) PingResult {
	result := PingResult{
		Target: target,
	}

	// Create a timeout context for ping (5 seconds max)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	var pingCount string = "1" // Single ping for minimal overhead

	// Determine the ping command based on OS
	if _, err := exec.LookPath("ping"); err == nil {
		// Check if we're on Linux or macOS based on ping flags
		// Linux uses -c, macOS uses -c, Windows uses -n
		testCmd := exec.Command("ping", "-c", "1", "-W", "1", target)
		if testCmd.Run() == nil || strings.Contains(runtime.GOOS, "linux") || strings.Contains(runtime.GOOS, "darwin") {
			// Unix-like (Linux/macOS): -c count -W timeout
			cmd = exec.CommandContext(pingCtx, "ping", "-c", pingCount, "-W", "2", target)
		} else {
			// Windows: -n count -w timeout_ms
			cmd = exec.CommandContext(pingCtx, "ping", "-n", pingCount, "-w", "2000", target)
		}
	} else {
		result.Success = false
		result.ErrorMsg = "ping command not found"
		return result
	}

	start := time.Now()
	output, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("ping failed: %v", err)
		return result
	}

	// Parse the output to extract latency
	// Look for patterns like "time=X.XXX ms" (Linux/macOS) or "time=XXXms" (Windows)
	outputStr := string(output)

	// Try to extract latency from output
	latencyRegex := regexp.MustCompile(`time[=<](\d+\.?\d*)\s*ms`)
	matches := latencyRegex.FindStringSubmatch(outputStr)

	if len(matches) > 1 {
		if latency, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.LatencyMs = latency
			result.Success = true
		} else {
			// Fallback to elapsed time if parsing fails
			result.LatencyMs = float64(elapsed.Microseconds()) / 1000.0
			result.Success = true
		}
	} else {
		// If we can't parse latency, use elapsed time
		result.LatencyMs = float64(elapsed.Microseconds()) / 1000.0
		// Check if ping was actually successful
		if strings.Contains(outputStr, "1 received") ||
		   strings.Contains(outputStr, "1 packets received") ||
		   strings.Contains(outputStr, "Received = 1") {
			result.Success = true
		} else {
			result.Success = false
			result.ErrorMsg = "no response received"
		}
	}

	return result
}

// runPingsParallel runs pings to multiple targets in parallel
func runPingsParallel(ctx context.Context, targets []string) []PingResult {
	results := make([]PingResult, len(targets))
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt string) {
			defer wg.Done()
			results[idx] = runPing(ctx, tgt)
		}(i, target)
	}

	wg.Wait()
	return results
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
			stats.pingStats = make(map[string]*PingStats)
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

	// Ping statistics
	if len(stats.pingStats) > 0 {
		fmt.Println()
		fmt.Println("PING STATISTICS:")

		// Sort targets for consistent output
		targets := make([]string, 0, len(stats.pingStats))
		for target := range stats.pingStats {
			targets = append(targets, target)
		}
		sort.Strings(targets)

		for _, target := range targets {
			pstat := stats.pingStats[target]
			pingDisruptionRate := float64(0)
			if pstat.totalPings > 0 {
				pingDisruptionRate = float64(pstat.failedPings) / float64(pstat.totalPings) * 100
			}

			fmt.Printf("  %s:\n", target)
			fmt.Printf("    Total: %d, Failed: %d (%.2f%%)", pstat.totalPings, pstat.failedPings, pingDisruptionRate)
			if pstat.consecutiveFail > 0 {
				fmt.Printf(", Consecutive Fails: %d", pstat.consecutiveFail)
			}
			fmt.Println()

			if len(pstat.latencies) > 0 {
				printLatencyStats("    Latency:", pstat.latencies)
			} else {
				fmt.Println("    Latency: n/a")
			}

			if pstat.lastError != "" {
				fmt.Printf("    Last Error: %s\n", pstat.lastError)
			}
		}
	}

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
