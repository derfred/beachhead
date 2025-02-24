package main

import (
	"archive/zip"
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
	"strings"
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

// WorkspaceHandler extracts a zip file from the request into a temp directory.
func MakeWorkspaceHandler(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form with a reasonable max memory.
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Get the file
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Failed to get file from form: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		buf, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Failed to read file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rdr := bytes.NewReader(buf)
		zipReader, err := zip.NewReader(rdr, int64(len(buf)))
		if err != nil {
			http.Error(w, "Failed to open zip file: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new temporary directory inside the workspace base.
		tmpDir, err := os.MkdirTemp(server.workspaceBase, "workspace_*")
		if err != nil {
			http.Error(w, "Failed to create temp dir: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Extract zip contents.
		for _, f := range zipReader.File {
			fpath := filepath.Join(tmpDir, f.Name)
			// Prevent ZipSlip vulnerability.
			if !strings.HasPrefix(fpath, filepath.Clean(tmpDir)+string(os.PathSeparator)) {
				http.Error(w, "Illegal file path", http.StatusBadRequest)
				return
			}

			if f.FileInfo().IsDir() {
				os.MkdirAll(fpath, os.ModePerm)
				continue
			}

			// Make sure directory exists.
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				http.Error(w, "Failed to create directories: "+err.Error(), http.StatusInternalServerError)
				return
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				http.Error(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
				return
			}

			rc, err := f.Open()
			if err != nil {
				outFile.Close()
				http.Error(w, "Failed to open zipped file: "+err.Error(), http.StatusInternalServerError)
				return
			}

			_, err = io.Copy(outFile, rc)
			outFile.Close()
			rc.Close()
			if err != nil {
				http.Error(w, "Failed to extract file: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// For future operations, the new workspace base is now tmpDir.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Workspace set to: " + tmpDir))
	}
}
