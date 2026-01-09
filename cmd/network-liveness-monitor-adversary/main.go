// network-liveness-monitor-adversary is a CPU stress tool designed to create
// adversarial conditions for testing network liveness monitors.
//
// It pins goroutines to specific CPU cores and runs busy loops to fully
// consume those cores, simulating CPU contention scenarios.
//
// Usage:
//
//	go run cmd/network-liveness-monitor-adversary/main.go [--sleep N] <num_cores>
//
// Examples:
//
//	# Burn 4 CPU cores (cores 0-3)
//	go run cmd/network-liveness-monitor-adversary/main.go 4
//
//	# Wait 60 seconds then burn 4 cores
//	go run cmd/network-liveness-monitor-adversary/main.go --sleep 60 4
//
//	# Burn all available cores
//	go run cmd/network-liveness-monitor-adversary/main.go all
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	sleepSeconds := flag.Int("sleep", 0, "seconds to wait before starting to burn CPU")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <num_cores>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  <N>   - Burn N cores starting from CPU 0 (e.g., 4 burns cores 0-3)\n")
		fmt.Fprintf(os.Stderr, "  all   - Burn all available cores\n\n")
		fmt.Fprintf(os.Stderr, "Available cores on this system: %d\n\n", runtime.NumCPU())
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Parse the cores argument
	count, err := parseCoreCount(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	numCPU := runtime.NumCPU()
	if count > numCPU {
		fmt.Fprintf(os.Stderr, "Warning: requested %d cores but only %d available, using %d\n", count, numCPU, numCPU)
		count = numCPU
	}

	// Build list of cores to burn (0 to count-1)
	cores := make([]int, count)
	for i := 0; i < count; i++ {
		cores[i] = i
	}

	fmt.Println("Network Liveness Monitor Adversary - CPU Burner")
	fmt.Println("================================================")
	fmt.Printf("Available CPUs: %d\n", numCPU)
	fmt.Printf("Burning cores:  0-%d (%d cores)\n", count-1, count)
	if *sleepSeconds > 0 {
		fmt.Printf("Sleep before:   %d seconds\n", *sleepSeconds)
	}
	fmt.Printf("Started at:     %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Set GOMAXPROCS to ensure we have enough OS threads
	runtime.GOMAXPROCS(count + 2) // +2 for main thread and signal handler

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Sleep before starting if requested
	if *sleepSeconds > 0 {
		fmt.Printf("Sleeping for %d seconds before burning...\n", *sleepSeconds)
		select {
		case <-time.After(time.Duration(*sleepSeconds) * time.Second):
			fmt.Println("Sleep complete, starting CPU burn...")
		case <-sigChan:
			fmt.Println("\nInterrupted during sleep. Exiting.")
			return
		}
	}

	var wg sync.WaitGroup

	// Start burning each core
	for _, cpu := range cores {
		wg.Add(1)
		go burnCore(cpu, &wg, sigChan)
	}

	// Wait for signal
	<-sigChan
	fmt.Println("\nShutting down...")

	// Note: The burnCore goroutines will exit when the process terminates
	// We don't wait for them since they're in infinite loops
	fmt.Println("Stopped.")
}

// parseCoreCount parses the count argument (number or "all")
func parseCoreCount(spec string) (int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))

	// Handle "all"
	if spec == "all" {
		return runtime.NumCPU(), nil
	}

	// Parse as a number
	count, err := strconv.Atoi(spec)
	if err != nil {
		return 0, fmt.Errorf("invalid argument %q: expected number or 'all'", spec)
	}

	if count <= 0 {
		return 0, fmt.Errorf("core count must be positive, got %d", count)
	}

	return count, nil
}

// burnCore pins to a specific CPU and runs a busy loop to consume 100% of that core
func burnCore(cpu int, wg *sync.WaitGroup, stopCh <-chan os.Signal) {
	defer wg.Done()

	// Lock this goroutine to its OS thread so CPU affinity works
	runtime.LockOSThread()

	// Set CPU affinity to pin to the specific core
	var mask unix.CPUSet
	mask.Set(cpu)

	if err := unix.SchedSetaffinity(0, &mask); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to set affinity for CPU %d: %v\n", cpu, err)
		// Continue anyway - the goroutine will still consume CPU, just not pinned
	}

	fmt.Printf("[CPU %d] Burning started\n", cpu)

	// Busy loop - this will consume 100% of the CPU core
	// We use a simple operation that can't be optimized away
	counter := 0
	for {
		// Check for stop signal periodically (every ~1M iterations)
		// This adds negligible overhead but allows clean shutdown detection
		counter++
		if counter&0xFFFFF == 0 {
			select {
			case <-stopCh:
				fmt.Printf("[CPU %d] Burning stopped\n", cpu)
				return
			default:
				// Continue burning
			}
		}

		// Busy work - prevent compiler optimization
		_ = counter * counter
	}
}
