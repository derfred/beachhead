package main

import (
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

var version = "1.0.0"

var (
	// Global variable to hold the WebSocket connection
	fileMap     = make(map[string]string)
	fileMapLock sync.Mutex
)

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

// ExecHandler executes a shell command provided via query parameter "cmd".
// It streams stdout/stderr in a chunked response and returns the exit code as a trailer.
func ExecHandler(w http.ResponseWriter, r *http.Request) {
	cmdStr := r.URL.Query().Get("cmd")
	if cmdStr == "" {
		http.Error(w, "cmd query parameter missing", http.StatusBadRequest)
		return
	}

	// Create the command.
	cmd := exec.Command("sh", "-c", cmdStr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "Failed to get stdout: "+err.Error(), http.StatusInternalServerError)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, "Failed to get stderr: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Start the command.
	if err := cmd.Start(); err != nil {
		http.Error(w, "Failed to start command: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set trailer header for exit code.
	w.Header().Set("Trailer", "X-Exit-Code")
	w.Header().Set("Content-Type", "text/plain")
	// Flush headers.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Stream stdout and stderr.
	// Here we simply merge the two streams.
	reader := io.MultiReader(stdout, stderr)
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if err != nil {
			break
		}
	}

	// Wait for command to finish.
	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	// Set the trailer exit code.
	w.Header().Set("X-Exit-Code", strconv.Itoa(exitCode))
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
