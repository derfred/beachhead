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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var version = "0.3"

// HealthHandler responds with 200 OK.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("Error writing health response: %v", err)
	}
}

// VersionHandler returns the current version.
func VersionHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(version)); err != nil {
		log.Printf("Error writing version response: %v", err)
	}
}

type WorkspaceHandler struct {
	base            string
	current         string
	processRegistry *ProcessRegistry
}

func NewWorkspaceHandler(workspaceBase string, shellTemplates map[string]ShellTemplate) *WorkspaceHandler {
	return &WorkspaceHandler{
		base:            workspaceBase,
		processRegistry: NewProcessRegistry(shellTemplates),
	}
}

type ExecRequest struct {
	Args  string          `json:"args"`
	Files map[string]bool `json:"files"` // map of variable names that will be supplied as files
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

func extractCmdArgs(r *http.Request, workspaceBase string) (map[string]interface{}, int, error) {
	var requestData map[string]interface{}

	// Check the content type of the request
	contentType := r.Header.Get("Content-Type")

	// Handle JSON request
	if contentType == "application/json" {
		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		defer r.Body.Close()

		// Unmarshal the JSON into a nested map
		err = json.Unmarshal(body, &requestData)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		return requestData, http.StatusOK, nil
	} else if isMultipartFormRequest(contentType) {
		// Handle multipart form request
		// Parse the multipart form with a reasonable max memory
		err := r.ParseMultipartForm(10 << 20) // 10 MB max memory
		if err != nil {
			return nil, http.StatusBadRequest, err
		}

		// Initialize the request data map
		requestData = make(map[string]interface{})
		requestData["workspace"] = workspaceBase

		// Parse the JSON data
		jsonData := r.FormValue("json")
		if jsonData != "" {
			err = json.Unmarshal([]byte(jsonData), &requestData)
			if err != nil {
				return nil, http.StatusBadRequest, err
			}
		}

		// Process any additional file uploads
		for fileName, fileHeaders := range r.MultipartForm.File {
			for _, fileHeader := range fileHeaders {
				// Open the uploaded file
				file, err := fileHeader.Open()
				if err != nil {
					return nil, http.StatusInternalServerError, err
				}
				defer file.Close()

				// Create a temporary file to store the upload
				tempFile, err := createTempFile(fileHeader.Filename)
				if err != nil {
					return nil, http.StatusInternalServerError, err
				}
				defer tempFile.Close()

				// Copy the uploaded file to the temporary file
				_, err = io.Copy(tempFile, file)
				if err != nil {
					return nil, http.StatusInternalServerError, err
				}

				// Add the file location to the request data map
				requestData[fileName] = tempFile.Name()
			}
		}
		return requestData, http.StatusOK, nil
	} else {
		return nil, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content type. Use application/json or multipart/form-data")
	}
}

// WorkspaceHandler extracts a zip file from the request into a temp directory.
func (workspace *WorkspaceHandler) CreateWorkspaceHandler() http.HandlerFunc {
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

		// Create a new temporary directory inside the workspace base with timestamp suffix.
		timestamp := time.Now().Format("20060102_150405")
		tmpDir := filepath.Join(workspace.base, "workspace_"+timestamp)
		err = os.MkdirAll(tmpDir, os.ModePerm)
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
				if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
					http.Error(w, "Failed to create directory: "+err.Error(), http.StatusInternalServerError)
					return
				}
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
			workspace.current = tmpDir
		}

		// For future operations, the new workspace base is now tmpDir.
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Workspace set to: " + tmpDir)); err != nil {
			log.Printf("Error writing workspace response: %v", err)
		}
	}
}

func (workspace *WorkspaceHandler) MakeWorkspaceUploadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if workspace.current == "" {
			http.Error(w, "No workspace set", http.StatusBadRequest)
			return
		}

		filename := strings.TrimPrefix(r.URL.Path, "/workspace/upload/")
		if filename == "" {
			http.Error(w, "Filename required", http.StatusBadRequest)
			return
		}

		targetPath := filepath.Join(workspace.current, filename)
		// Prevent path traversal
		if !strings.HasPrefix(targetPath, workspace.current) {
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
		if _, err := w.Write([]byte("File uploaded successfully")); err != nil {
			log.Printf("Error writing upload success response: %v", err)
		}
	}
}

func (workspace *WorkspaceHandler) MakeWorkspaceDownloadHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if workspace.current == "" {
			http.Error(w, "No workspace set", http.StatusBadRequest)
			return
		}

		filename := strings.TrimPrefix(r.URL.Path, "/workspace/download/")
		if filename == "" {
			http.Error(w, "Filename required", http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(workspace.current, filename)
		// Prevent path traversal
		if !strings.HasPrefix(filePath, workspace.current) {
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

// MakeExecHandler creates an HTTP handler for executing commands
func (workspace *WorkspaceHandler) MakeExecHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if workspace.current == "" {
			http.Error(w, "No workspace set", http.StatusBadRequest)
			return
		}

		cmd := strings.TrimPrefix(r.URL.Path, "/workspace/exec/")
		if cmd == "" {
			http.Error(w, "command name is required", http.StatusBadRequest)
			return
		}

		if !workspace.processRegistry.HasShellTemplate(cmd) {
			http.Error(w, fmt.Sprintf("command not found: %s", cmd), http.StatusNotFound)
			return
		}

		args, status, err := extractCmdArgs(r, workspace.base)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		// Get follow parameter from query string instead of request body
		followOutput := true
		followParam := r.URL.Query().Get("follow")
		if followParam != "" {
			followOutput = followParam != "false" && followParam != "0"
		}

		// Setup output writer based on followOutput flag
		var outputListener *ProcessListener
		if followOutput {
			outputListener = workspace.startResponse(w, r)
		}

		// Execute the command
		process, err := workspace.processRegistry.Execute(workspace.current, cmd, args, outputListener)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set Location header pointing to the process endpoint
		w.Header().Set("Location", fmt.Sprintf("/workspace/process/%s", process.ID))

		if followOutput {
			defer process.RemoveListener(outputListener)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

			outputListener.Write(w)

			exitCode := process.Wait()
			outputListener.Close(w, exitCode)
			w.Header().Set("X-Exit-Code", strconv.Itoa(exitCode))
		} else {
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

// MakeProcessListHandler creates an HTTP handler to list all processes
func (workspace *WorkspaceHandler) MakeProcessListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		processes := workspace.processRegistry.ListProcesses()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(processes); err != nil {
			http.Error(w, "Failed to encode process list", http.StatusInternalServerError)
		}
	}
}

// MakeProcessDetailsHandler creates an HTTP handler to get details about a specific process
func (workspace *WorkspaceHandler) ProcessDetailsHandler(w http.ResponseWriter, process *ProcessInfo) {
	// Build the response data
	process.Lock.Lock()
	resp := map[string]interface{}{
		"id":           process.ID,
		"command":      process.Command,
		"pid":          process.PID,
		"start_time":   process.StartTime,
		"running_time": time.Since(process.StartTime).String(),
		"exit_code":    process.Exit.Get(),
	}
	process.Lock.Unlock()

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode process details", http.StatusInternalServerError)
	}
}

// MakeProcessTerminateHandler creates an HTTP handler for terminating a process
func (workspace *WorkspaceHandler) ProcessTerminateHandler(w http.ResponseWriter, process *ProcessInfo) {
	// Call the ProcessRegistry to terminate the process
	if err := workspace.processRegistry.TerminateProcess(process.ID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to terminate process: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{"status": "terminated", "id": process.ID}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding termination response: %v", err)
	}
}

// ProcessOutputHandler creates an HTTP handler for streaming process output
func (workspace *WorkspaceHandler) ProcessOutputHandler(w http.ResponseWriter, r *http.Request, process *ProcessInfo) {
	// Start the response and get the appropriate writer
	listener := workspace.startResponse(w, r)
	defer process.RemoveListener(listener)

	if !process.Exit.IsSet() {
		// Add the writer to the process's list of writers
		if err := workspace.processRegistry.AttachListener(process.ID, listener); err != nil {
			http.Error(w, fmt.Sprintf("Failed to attach to process output: %v", err), http.StatusInternalServerError)
			return
		}
		listener.Write(w)

		// Wait for the process to complete
		process.Wait()
	}

	// Close the writer (no-op if not in markup mode)
	listener.Close(w, process.Exit.Wait())

	// Set the exit code in the trailer
	w.Header().Set("X-Exit-Code", strconv.Itoa(process.Exit.Wait()))
}

// startResponse is a helper function that sets up the response headers and creates the appropriate writer
func (workspace *WorkspaceHandler) startResponse(w http.ResponseWriter, r *http.Request) *ProcessListener {
	// Check if the client accepts the processml format
	acceptHeader := r.Header.Get("Accept")
	useMarkup := strings.Contains(acceptHeader, "application/processml")
	if useMarkup {
		w.Header().Set("Content-Type", "application/processml")
	} else {
		// Set content type to plaintext for regular output
		w.Header().Set("Content-Type", "text/plain")
	}

	w.Header().Set("Trailer", "X-Exit-Code")

	// Create the writer with markup mode based on the Accept header
	return NewProcessListener(useMarkup)
}
