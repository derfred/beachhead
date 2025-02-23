package main

import (
	"os"
	"testing"
)

func TestParseShellFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantUser string
		wantTmpl string
		wantErr  bool
	}{
		{
			name:     "basic command",
			input:    "ls:ls -l",
			wantName: "ls",
			wantTmpl: "ls -l",
		},
		{
			name:     "with user",
			input:    "ps@root:ps aux",
			wantName: "ps",
			wantUser: "root",
			wantTmpl: "ps aux",
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, user, tmpl, err := parseShellFlag(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if name != tt.wantName {
				t.Errorf("name = %v, want %v", name, tt.wantName)
			}

			if user != tt.wantUser {
				t.Errorf("user = %v, want %v", user, tt.wantUser)
			}

			if tmpl != tt.wantTmpl {
				t.Errorf("template = %v, want %v", tmpl, tt.wantTmpl)
			}
		})
	}
}

func TestProcessShellEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want map[string]ShellTemplate
	}{
		{
			name: "basic command",
			env: map[string]string{
				"BEACHHEAD_SHELL_LS": "ls -l",
			},
			want: map[string]ShellTemplate{
				"ls": {Template: "ls -l"},
			},
		},
		{
			name: "with user",
			env: map[string]string{
				"BEACHHEAD_SHELL_PS": "root:ps aux",
			},
			want: map[string]ShellTemplate{
				"ps": {User: "root", Template: "ps aux"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			got := processShellEnv()

			if len(got) != len(tt.want) {
				t.Errorf("processShellEnv() got %v items, want %v", len(got), len(tt.want))
			}

			for k, v := range tt.want {
				if g, ok := got[k]; !ok {
					t.Errorf("missing key %v", k)
				} else if g != v {
					t.Errorf("for key %v, got %v, want %v", k, g, v)
				}
			}
		})
	}
}
