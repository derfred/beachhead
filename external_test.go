package main

import (
	"bytes"
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

func TestProcessRegistry_Execute(t *testing.T) {
	templates := map[string]ShellTemplate{
		"echo": {Template: "echo {{.text}}"},
		"root": {User: "root", Template: "whoami"},
	}

	registry := NewProcessRegistry(templates)

	tests := []struct {
		name    string
		cmd     string
		args    map[string]interface{}
		wantOut string
		wantErr bool
	}{
		{
			name:    "basic command",
			cmd:     "echo",
			args:    map[string]interface{}{"text": "hello"},
			wantOut: "hello\n",
		},
		{
			name:    "unknown command",
			cmd:     "unknown",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := registry.Execute("", tt.cmd, tt.args, &out)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Since the output is written asynchronously, we need to wait a bit
			time.Sleep(100 * time.Millisecond)

			if got := out.String(); !strings.Contains(got, tt.wantOut) {
				t.Errorf("output = %q, want to contain %q", got, tt.wantOut)
			}
		})
	}
}
