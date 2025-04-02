package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	HealthHandler(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "OK" {
		t.Errorf("Expected body 'OK', got %s", body)
	}
}

func TestVersionHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()
	VersionHandler(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), version) {
		t.Errorf("Expected version %s in response, got %s", version, body)
	}
}

func TestMetricsHandler(t *testing.T) {
	// Create a new metrics collector
	collector := NewMetricsCollector()

	// Start collecting metrics
	collector.Start()

	// Wait for at least one data point to be collected
	time.Sleep(metricsCollectionInterval + time.Second)

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "/metrics/history", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler := http.HandlerFunc(collector.MetricsHandler)
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, "application/json")
	}

	// Parse the response body
	var metricsPoints []MetricsPoint
	if err := json.Unmarshal(rr.Body.Bytes(), &metricsPoints); err != nil {
		t.Errorf("error parsing response body: %v", err)
	}

	// Verify we have at least one data point
	if len(metricsPoints) == 0 {
		t.Error("expected at least one metrics data point, got none")
	}

	// Check that the data point has the expected fields
	if len(metricsPoints) > 0 {
		point := metricsPoints[0]
		if point.Timestamp.IsZero() {
			t.Error("timestamp is zero")
		}

		// Check CPU metrics
		if len(point.CPUUsage) == 0 {
			t.Error("no CPU usage data points")
		}
		for i, usage := range point.CPUUsage {
			if usage < 0 || usage > 100 {
				t.Errorf("CPU %d usage out of range: %f", i, usage)
			}
		}
		if point.CPUAggregate < 0 || point.CPUAggregate > 100 {
			t.Errorf("CPU aggregate usage out of range: %f", point.CPUAggregate)
		}

		// Check other metrics
		if point.MemoryUsage < 0 || point.MemoryUsage > 100 {
			t.Errorf("Memory usage out of range: %f", point.MemoryUsage)
		}
		if point.DiskFree < 0 {
			t.Errorf("Disk free space negative: %f", point.DiskFree)
		}
	}

	// Stop the collector
	collector.Stop()
}

func TestPrometheusHandler(t *testing.T) {
	// Create a new metrics collector
	collector := NewMetricsCollector()

	// Start collecting metrics
	collector.Start()

	// Wait for at least one data point to be collected
	time.Sleep(metricsCollectionInterval + time.Second)

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler := collector.PrometheusHandler()
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the response contains expected metrics
	body := rr.Body.String()
	expectedMetrics := []string{
		"cpu_usage_percent",
		"cpu_usage_aggregate_percent",
		"memory_usage_percent",
		"disk_free_gb",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("response does not contain expected metric: %s", metric)
		}
	}

	// Stop the collector
	collector.Stop()
}
