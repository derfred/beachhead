package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
)

const (
	metricsHistoryDuration    = 5 * time.Minute // Store 5 minutes of history
	metricsCollectionInterval = 5 * time.Second // Collect metrics every 5 seconds
)

// MetricsPoint represents a single point of collected metrics
type MetricsPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	CPUUsage     []float64 `json:"cpu_usage"`             // Percentage per CPU
	CPUAggregate float64   `json:"cpu_aggregate"`         // Aggregate CPU usage percentage
	MemoryUsage  float64   `json:"memory_usage"`          // Percentage
	DiskFree     float64   `json:"disk_free"`             // GB
	GPUCompute   []float64 `json:"gpu_compute,omitempty"` // Percentage per GPU
	GPUMemory    []float64 `json:"gpu_memory,omitempty"`  // Percentage per GPU
}

// MetricsCollector collects and stores system metrics
type MetricsCollector struct {
	history      []MetricsPoint
	historyMutex sync.RWMutex
	hasGPU       bool
	stopChan     chan struct{}
	registry     *prometheus.Registry

	// Prometheus metrics
	cpuUsagePerCPU    *prometheus.GaugeVec
	cpuUsageAggregate prometheus.Gauge
	memoryUsage       prometheus.Gauge
	diskFree          prometheus.Gauge
	gpuCompute        *prometheus.GaugeVec
	gpuMemory         *prometheus.GaugeVec
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	// Create Prometheus metrics
	cpuUsagePerCPU := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cpu_usage_percent",
		Help: "Current CPU usage percentage per CPU",
	}, []string{"cpu"})

	cpuUsageAggregate := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cpu_usage_aggregate_percent",
		Help: "Aggregate CPU usage percentage across all CPUs",
	})

	memoryUsage := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "memory_usage_percent",
		Help: "Current memory usage percentage",
	})

	diskFree := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "disk_free_gb",
		Help: "Free disk space in GB on root filesystem",
	})

	gpuCompute := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gpu_compute_percent",
		Help: "GPU compute usage percentage",
	}, []string{"gpu"})

	gpuMemory := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gpu_memory_percent",
		Help: "GPU memory usage percentage",
	}, []string{"gpu"})

	// Register metrics with Prometheus
	registry := prometheus.NewRegistry()
	registry.MustRegister(cpuUsagePerCPU)
	registry.MustRegister(cpuUsageAggregate)
	registry.MustRegister(memoryUsage)
	registry.MustRegister(diskFree)
	registry.MustRegister(gpuCompute)
	registry.MustRegister(gpuMemory)

	// Check if NVIDIA GPUs are available
	hasGPU := checkNvidiaGPU()

	return &MetricsCollector{
		history:           make([]MetricsPoint, 0, metricsHistoryDuration/metricsCollectionInterval),
		hasGPU:            hasGPU,
		stopChan:          make(chan struct{}),
		registry:          registry,
		cpuUsagePerCPU:    cpuUsagePerCPU,
		cpuUsageAggregate: cpuUsageAggregate,
		memoryUsage:       memoryUsage,
		diskFree:          diskFree,
		gpuCompute:        gpuCompute,
		gpuMemory:         gpuMemory,
	}
}

// Start begins collecting metrics at regular intervals
func (mc *MetricsCollector) Start() {
	go func() {
		ticker := time.NewTicker(metricsCollectionInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				metrics, err := mc.collectMetrics()
				if err != nil {
					log.Printf("Error collecting metrics: %v", err)
					continue
				}

				mc.updatePrometheusMetrics(metrics)
				mc.addToHistory(metrics)
			case <-mc.stopChan:
				return
			}
		}
	}()
}

// Stop halts metrics collection
func (mc *MetricsCollector) Stop() {
	close(mc.stopChan)
}

// collectMetrics gathers current system metrics
func (mc *MetricsCollector) collectMetrics() (MetricsPoint, error) {
	metrics := MetricsPoint{
		Timestamp: time.Now(),
	}

	// Collect CPU metrics
	cpuPercent, err := cpu.Percent(0, true) // true to get per-CPU metrics
	if err != nil {
		return metrics, fmt.Errorf("failed to get CPU usage: %v", err)
	}

	// Store per-CPU metrics
	metrics.CPUUsage = make([]float64, len(cpuPercent))
	copy(metrics.CPUUsage, cpuPercent)

	// Calculate aggregate CPU usage
	var total float64
	for _, usage := range cpuPercent {
		total += usage
	}
	metrics.CPUAggregate = total / float64(len(cpuPercent))

	// Collect memory metrics
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return metrics, fmt.Errorf("failed to get memory usage: %v", err)
	}
	metrics.MemoryUsage = memInfo.UsedPercent

	// Collect disk metrics
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return metrics, fmt.Errorf("failed to get disk usage: %v", err)
	}
	metrics.DiskFree = float64(diskInfo.Free) / 1024 / 1024 / 1024 // Convert to GB

	// Collect GPU metrics if available
	if mc.hasGPU {
		gpuMetrics, err := collectNvidiaGPUMetrics()
		if err != nil {
			log.Printf("Failed to collect GPU metrics: %v", err)
		} else {
			metrics.GPUCompute = gpuMetrics.compute
			metrics.GPUMemory = gpuMetrics.memory
		}
	}

	return metrics, nil
}

// updatePrometheusMetrics updates Prometheus metrics with current values
func (mc *MetricsCollector) updatePrometheusMetrics(metrics MetricsPoint) {
	// Update per-CPU metrics
	for i, usage := range metrics.CPUUsage {
		mc.cpuUsagePerCPU.WithLabelValues(fmt.Sprintf("%d", i)).Set(usage)
	}

	// Update aggregate CPU metric
	mc.cpuUsageAggregate.Set(metrics.CPUAggregate)

	mc.memoryUsage.Set(metrics.MemoryUsage)
	mc.diskFree.Set(metrics.DiskFree)

	// Update GPU metrics if available
	if mc.hasGPU && len(metrics.GPUCompute) > 0 {
		for i, compute := range metrics.GPUCompute {
			mc.gpuCompute.WithLabelValues(fmt.Sprintf("%d", i)).Set(compute)
		}

		for i, memory := range metrics.GPUMemory {
			mc.gpuMemory.WithLabelValues(fmt.Sprintf("%d", i)).Set(memory)
		}
	}
}

// addToHistory adds metrics to the history and removes old ones
func (mc *MetricsCollector) addToHistory(metrics MetricsPoint) {
	mc.historyMutex.Lock()
	defer mc.historyMutex.Unlock()

	// Add new metrics
	mc.history = append(mc.history, metrics)

	// Remove old metrics
	cutoffTime := time.Now().Add(-metricsHistoryDuration)
	newStartIndex := 0

	for i, point := range mc.history {
		if point.Timestamp.After(cutoffTime) {
			newStartIndex = i
			break
		}
	}

	if newStartIndex > 0 {
		mc.history = mc.history[newStartIndex:]
	}
}

// GetHistory returns historical metrics for the last 5 minutes
func (mc *MetricsCollector) GetHistory() []MetricsPoint {
	mc.historyMutex.RLock()
	defer mc.historyMutex.RUnlock()

	// Create a copy to avoid external modification
	history := make([]MetricsPoint, len(mc.history))
	copy(history, mc.history)

	return history
}

// PrometheusHandler returns an HTTP handler for Prometheus metrics
func (mc *MetricsCollector) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(mc.registry, promhttp.HandlerOpts{})
}

// MetricsHandler returns historical metrics as JSON
func (mc *MetricsCollector) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	history := mc.GetHistory()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(history); err != nil {
		http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
	}
}

type gpuMetricsInfo struct {
	compute []float64
	memory  []float64
}

// checkNvidiaGPU checks if NVIDIA GPUs are available
func checkNvidiaGPU() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("where", "nvidia-smi")
		if err := cmd.Run(); err != nil {
			return false
		}
		return true
	}

	// For Linux/macOS
	cmd := exec.Command("which", "nvidia-smi")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// collectNvidiaGPUMetrics collects GPU usage metrics using nvidia-smi
func collectNvidiaGPUMetrics() (gpuMetricsInfo, error) {
	var metrics gpuMetricsInfo

	// Run nvidia-smi to get GPU information
	cmd := exec.Command("nvidia-smi", "--query-gpu=utilization.gpu,utilization.memory", "--format=csv,noheader,nounits")
	output, err := cmd.Output()
	if err != nil {
		return metrics, fmt.Errorf("failed to execute nvidia-smi: %v", err)
	}

	// Parse the output
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	metrics.compute = make([]float64, len(lines))
	metrics.memory = make([]float64, len(lines))

	for i, line := range lines {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) != 2 {
			continue
		}

		compute := strings.TrimSpace(fields[0])
		memory := strings.TrimSpace(fields[1])

		if computeVal, err := parseFloat(compute); err == nil {
			metrics.compute[i] = computeVal
		}

		if memoryVal, err := parseFloat(memory); err == nil {
			metrics.memory[i] = memoryVal
		}
	}

	return metrics, nil
}

// parseFloat parses a string to float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}
