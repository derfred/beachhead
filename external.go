package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

type ExecRequest struct {
	Args  string          `json:"args"`
	Files map[string]bool `json:"files"` // map of variable names that will be supplied as files
}

var version = "1.0.0"

type CommandExecutor struct {
	shellTemplates map[string]ShellTemplate
}

func NewCommandExecutor(templates map[string]ShellTemplate) *CommandExecutor {
	return &CommandExecutor{
		shellTemplates: templates,
	}
}

func (e *CommandExecutor) Execute(cwd string, cmd string, args map[string]interface{}, w io.Writer) (int, error) {
	shellTmpl, exists := e.shellTemplates[cmd]
	if !exists {
		return 0, fmt.Errorf("command not found: %s", cmd)
	}

	tmpl, err := template.New("cmd").Parse(shellTmpl.Template)
	if err != nil {
		return 0, fmt.Errorf("template parse error: %v", err)
	}

	var cmdStr bytes.Buffer
	err = tmpl.Execute(&cmdStr, args)
	if err != nil {
		return 0, fmt.Errorf("template execution error: %v", err)
	}

	finalCmd := cmdStr.String()
	if shellTmpl.User != "" {
		finalCmd = "sudo -u " + shellTmpl.User + " " + finalCmd
	}

	shellcmd := exec.Cmd{
		Path: "/bin/sh",
		Args: []string{"sh", "-c", finalCmd},
		Dir:  cwd,
	}

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
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading output: %v", err)
			}
			break
		}
		if _, err := w.Write(buf[:n]); err != nil {
			log.Printf("error writing output: %v", err)
			break
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
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

func isMultipartFormRequest(contentType string) bool {
	return len(contentType) >= 19 && contentType[:19] == "multipart/form-data"
}

func createTempFile(originalName string) (*os.File, error) {
	// Create a temporary directory if it doesn't exist
	tempDir := filepath.Join(os.TempDir(), "uploads")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, err
	}

	// Create a temporary file with the original filename pattern
	ext := filepath.Ext(originalName)
	prefix := originalName[:len(originalName)-len(ext)]

	return os.CreateTemp(tempDir, prefix+"_*"+ext)
}

func extractCmdArgs(r *http.Request, workspaceBase string) (map[string]interface{}, error, int) {
	var requestData map[string]interface{}

	// Check the content type of the request
	contentType := r.Header.Get("Content-Type")

	// Handle JSON request
	if contentType == "application/json" {
		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err, http.StatusInternalServerError
		}
		defer r.Body.Close()

		// Unmarshal the JSON into a nested map
		err = json.Unmarshal(body, &requestData)
		if err != nil {
			return nil, err, http.StatusBadRequest
		}
		return requestData, nil, http.StatusOK
	} else if isMultipartFormRequest(contentType) {
		// Handle multipart form request
		// Parse the multipart form with a reasonable max memory
		err := r.ParseMultipartForm(10 << 20) // 10 MB max memory
		if err != nil {
			return nil, err, http.StatusBadRequest
		}

		// Initialize the request data map
		requestData = make(map[string]interface{})
		requestData["workspace"] = workspaceBase

		// Parse the JSON data
		jsonData := r.FormValue("json")
		if jsonData != "" {
			err = json.Unmarshal([]byte(jsonData), &requestData)
			if err != nil {
				return nil, err, http.StatusBadRequest
			}
		}

		// Process any additional file uploads
		for fileName, fileHeaders := range r.MultipartForm.File {
			for _, fileHeader := range fileHeaders {
				// Open the uploaded file
				file, err := fileHeader.Open()
				if err != nil {
					return nil, err, http.StatusInternalServerError
				}
				defer file.Close()

				// Create a temporary file to store the upload
				tempFile, err := createTempFile(fileHeader.Filename)
				if err != nil {
					return nil, err, http.StatusInternalServerError
				}
				defer tempFile.Close()

				// Copy the uploaded file to the temporary file
				_, err = io.Copy(tempFile, file)
				if err != nil {
					return nil, err, http.StatusInternalServerError
				}

				// Add the file location to the request data map
				requestData[fileName] = tempFile.Name()
			}
		}
		return requestData, nil, http.StatusOK
	} else {
		return nil, fmt.Errorf("unsupported content type. Use application/json or multipart/form-data"), http.StatusUnsupportedMediaType
	}
}

// Replace ExecHandler with MakeExecHandler that uses a passed-in shellTemplates
func MakeExecHandler(shellTemplates map[string]ShellTemplate, server *Server) http.HandlerFunc {
	executor := NewCommandExecutor(shellTemplates)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cmd := strings.TrimPrefix(r.URL.Path, "/exec/")
		if cmd == "" {
			http.Error(w, "command name is required", http.StatusBadRequest)
			return
		}

		if _, exists := shellTemplates[cmd]; !exists {
			http.Error(w, fmt.Sprintf("command not found: %s", cmd), http.StatusNotFound)
			return
		}

		args, err, status := extractCmdArgs(r, server.workspaceBase)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		w.Header().Set("Trailer", "X-Exit-Code")
		w.Header().Set("Content-Type", "text/plain")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		exitCode, err := executor.Execute(server.workspaceCurrent, cmd, args, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Exit-Code", strconv.Itoa(exitCode))
	}
}

// WorkspaceHandler extracts a zip file from the request into a temp directory.
func MakeWorkspaceHandler(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
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

			// now set the workspaceCurrent to the new workspace
			server.workspaceCurrent = tmpDir
		}

		// For future operations, the new workspace base is now tmpDir.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Workspace set to: " + tmpDir))
	}
}

func MakeWorkspaceUploadHandler(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if server.workspaceCurrent == "" {
			http.Error(w, "No workspace set", http.StatusBadRequest)
			return
		}

		filename := strings.TrimPrefix(r.URL.Path, "/workspace/upload/")
		if filename == "" {
			http.Error(w, "Filename required", http.StatusBadRequest)
			return
		}

		targetPath := filepath.Join(server.workspaceCurrent, filename)
		// Prevent path traversal
		if !strings.HasPrefix(targetPath, server.workspaceCurrent) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			http.Error(w, "Failed to create directories", http.StatusInternalServerError)
			return
		}

		file, err := os.Create(targetPath)
		if err != nil {
			http.Error(w, "Failed to create file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		if _, err := io.Copy(file, r.Body); err != nil {
			http.Error(w, "Failed to save file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("File uploaded successfully"))
	}
}

func MakeWorkspaceDownloadHandler(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if server.workspaceCurrent == "" {
			http.Error(w, "No workspace set", http.StatusBadRequest)
			return
		}

		filename := strings.TrimPrefix(r.URL.Path, "/workspace/download/")
		if filename == "" {
			http.Error(w, "Filename required", http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(server.workspaceCurrent, filename)
		// Prevent path traversal
		if !strings.HasPrefix(filePath, server.workspaceCurrent) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		file, err := os.Open(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				http.Error(w, "Failed to open file: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Failed to get file info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
		w.WriteHeader(http.StatusOK)

		if _, err := io.Copy(w, file); err != nil {
			log.Printf("Error while sending file: %v", err)
		}
	}
}
