package main

import (
	"testing"
)

func TestStoreContextLines_CompleteLines(t *testing.T) {
	p := &ProcessInfo{
		lastOutputLines: make([][]byte, 5),
	}

	// Store 3 complete lines
	p.storeContextLines([]byte("line1\nline2\nline3\n"))

	// Check that the lines were stored correctly
	expected := []string{"line1", "line2", "line3", "", ""}
	for i, exp := range expected {
		if exp == "" && len(p.lastOutputLines[i]) > 0 {
			t.Errorf("Expected empty line at index %d, got %s", i, string(p.lastOutputLines[i]))
		} else if exp != "" && string(p.lastOutputLines[i]) != exp {
			t.Errorf("Expected %s at index %d, got %s", exp, i, string(p.lastOutputLines[i]))
		}
	}

	if p.lastOutputIndex != 3 {
		t.Errorf("Expected lastOutputIndex to be 3, got %d", p.lastOutputIndex)
	}
}

func TestStoreContextLines_PartialLine(t *testing.T) {
	p := &ProcessInfo{
		lastOutputLines: make([][]byte, 5),
	}

	// Test with a partial line (no trailing newline)
	p.storeContextLines([]byte("partial line"))

	// The partial line should be stored at index 0
	if string(p.lastOutputLines[0]) != "partial line" {
		t.Errorf("Expected 'partial line' at index 0, got %s", string(p.lastOutputLines[0]))
	}

	if p.lastOutputIndex != 1 {
		t.Errorf("Expected lastOutputIndex to be 1, got %d", p.lastOutputIndex)
	}

	// Now simulate the rest of the line coming in
	p.storeContextLines([]byte(" continued\n"))

	// Now we should have the partial line at index 0 and the new line at index 1
	if string(p.lastOutputLines[1]) != " continued" {
		t.Errorf("Expected ' continued' at index 1, got %s", string(p.lastOutputLines[1]))
	}

	if p.lastOutputIndex != 2 {
		t.Errorf("Expected lastOutputIndex to be 2, got %d", p.lastOutputIndex)
	}
}

func TestStoreContextLines_CircularBuffer(t *testing.T) {
	p := &ProcessInfo{
		lastOutputLines: make([][]byte, 5),
	}

	// Store 7 lines to test circular behavior (more than buffer size)
	p.storeContextLines([]byte("line1\nline2\nline3\nline4\nline5\nline6\nline7\n"))

	// Check that only the last 5 lines are stored
	expected := []string{"line3", "line4", "line5", "line6", "line7"}
	for i := 0; i < 5; i++ {
		idx := (p.lastOutputIndex + i) % 5
		if string(p.lastOutputLines[idx]) != expected[i] {
			t.Errorf("Expected %s at index %d, got %s", expected[i], idx, string(p.lastOutputLines[idx]))
		}
	}
}

func TestStoreContextLines_EmptyData(t *testing.T) {
	p := &ProcessInfo{
		lastOutputLines: make([][]byte, 5),
	}

	// Test with empty data
	p.storeContextLines([]byte(""))

	// The index should not change and no data should be stored
	if p.lastOutputIndex != 0 {
		t.Errorf("Expected lastOutputIndex to remain 0, got %d", p.lastOutputIndex)
	}

	for i := 0; i < 5; i++ {
		if len(p.lastOutputLines[i]) != 0 {
			t.Errorf("Expected empty line at index %d, got %s", i, string(p.lastOutputLines[i]))
		}
	}
}

func TestStoreContextLines_MixedContent(t *testing.T) {
	p := &ProcessInfo{
		lastOutputLines: make([][]byte, 5),
	}

	// Store a mix of complete lines and a partial line
	p.storeContextLines([]byte("line1\nline2\n"))
	p.storeContextLines([]byte("partial"))
	p.storeContextLines([]byte(" continued\nline4\n"))

	// Expected result after all operations
	if string(p.lastOutputLines[0]) != "line1" {
		t.Errorf("Expected 'line1' at index 0, got %s", string(p.lastOutputLines[0]))
	}
	if string(p.lastOutputLines[1]) != "line2" {
		t.Errorf("Expected 'line2' at index 1, got %s", string(p.lastOutputLines[1]))
	}
	if string(p.lastOutputLines[2]) != "partial" {
		t.Errorf("Expected 'partial' at index 2, got %s", string(p.lastOutputLines[2]))
	}
	if string(p.lastOutputLines[3]) != " continued" {
		t.Errorf("Expected ' continued' at index 3, got %s", string(p.lastOutputLines[3]))
	}
	if string(p.lastOutputLines[4]) != "line4" {
		t.Errorf("Expected 'line4' at index 4, got %s", string(p.lastOutputLines[4]))
	}
}
