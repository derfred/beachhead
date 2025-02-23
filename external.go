package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"text/template"
)

type ExecRequest struct {
	Cmd  string `json:"cmd"`
	Args string `json:"args"`
}

var version = "1.0.0"

var (
	// Global variable to hold the WebSocket connection
	fileMap     = make(map[string]string)
	fileMapLock sync.Mutex
)

type CommandExecutor struct {
	shellTemplates map[string]ShellTemplate
}

func NewCommandExecutor(templates map[string]ShellTemplate) *CommandExecutor {
	return &CommandExecutor{
		shellTemplates: templates,
	}
}

func (e *CommandExecutor) Execute(cmd, args string, w io.Writer) (int, error) {
	shellTmpl, exists := e.shellTemplates[cmd]
	if !exists {
		return 0, fmt.Errorf("command not found: %s", cmd)
	}

	tmpl, err := template.New("cmd").Parse(shellTmpl.Template)
	if err != nil {
		return 0, fmt.Errorf("template parse error: %v", err)
	}

	var cmdStr bytes.Buffer
	err = tmpl.Execute(&cmdStr, map[string]string{"Args": args})
	if err != nil {
		return 0, fmt.Errorf("template execution error: %v", err)
	}

	finalCmd := cmdStr.String()
	if shellTmpl.User != "" {
		finalCmd = "sudo -u " + shellTmpl.User + " " + finalCmd
	}

	shellcmd := exec.Command("sh", "-c", finalCmd)
	stdout, err := shellcmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("failed to get stdout: %v", err)
	}
	stderr, err := shellcmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("failed to get stderr: %v", err)
	}

	if err := shellcmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start command: %v", err)
	}

	reader := io.MultiReader(stdout, stderr)
	if _, err := io.Copy(w, reader); err != nil {
		return 0, fmt.Errorf("failed to copy output: %v", err)
	}

	err = shellcmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

// HealthHandler responds with 200 OK.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// VersionHandler returns the current version.
func VersionHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(version))
}

// Replace ExecHandler with MakeExecHandler that uses a passed-in shellTemplates
func MakeExecHandler(shellTemplates map[string]ShellTemplate) http.HandlerFunc {
	executor := NewCommandExecutor(shellTemplates)
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON request: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Cmd == "" {
			http.Error(w, "cmd field is required", http.StatusBadRequest)
			return
		}

		w.Header().Set("Trailer", "X-Exit-Code")
		w.Header().Set("Content-Type", "text/plain")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		exitCode, err := executor.Execute(req.Cmd, req.Args, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Exit-Code", strconv.Itoa(exitCode))
	}
}

func generateRandomID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// UploadHandler accepts a file upload and saves it to a temporary file.
// It returns the ID of the file.
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	id := generateRandomID()
	filePath := filepath.Join(os.TempDir(), id)

	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fileMapLock.Lock()
	fileMap[id] = filePath
	fileMapLock.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(id))
}

// DownloadHandler serves a file for download given its ID.
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id query parameter missing", http.StatusBadRequest)
		return
	}

	fileMapLock.Lock()
	filePath, exists := fileMap[id]
	fileMapLock.Unlock()

	if !exists {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Failed to open file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+id)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Failed to send file: "+err.Error(), http.StatusInternalServerError)
	}
}
