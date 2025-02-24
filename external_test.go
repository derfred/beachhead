package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	HealthHandler(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", res.StatusCode)
	}
	body, _ := ioutil.ReadAll(res.Body)
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
	body, _ := ioutil.ReadAll(res.Body)
	if !strings.Contains(string(body), version) {
		t.Errorf("Expected version %s in response, got %s", version, body)
	}
}

func TestCommandExecutor_Execute(t *testing.T) {
	templates := map[string]ShellTemplate{
		"echo": {Template: "echo {{.text}}"},
		"root": {User: "root", Template: "whoami"},
	}

	executor := NewCommandExecutor(templates)

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
			_, err := executor.Execute("", tt.cmd, tt.args, &out)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got := out.String(); got != tt.wantOut {
				t.Errorf("output = %q, want %q", got, tt.wantOut)
			}
		})
	}
}
