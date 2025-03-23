package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"text/template"
	"time"
)

// MarkupWriter provides a thread-safe writer with optional markup capabilities
type MarkupWriter struct {
	Process       *ProcessInfo
	writer        io.Writer
	mutex         sync.Mutex
	markupMode    bool
	isOutputOpen  bool
	lastWriteTime time.Time
	stopChan      chan struct{}
}

// NewMarkupWriter creates a new MarkupWriter
func NewMarkupWriter(w io.Writer, useMarkup bool) *MarkupWriter {
	mw := &MarkupWriter{
		Process:       nil,
		writer:        w,
		markupMode:    useMarkup,
		isOutputOpen:  false,
		lastWriteTime: time.Now(),
		stopChan:      make(chan struct{}),
	}

	// Start the keepalive goroutine if using markup mode
	if useMarkup {
		go mw.keepaliveMonitor()
	}

	return mw
}

// Write implements the io.Writer interface with optional markup
func (w *MarkupWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Update the last write time
	w.lastWriteTime = time.Now()

	w.openSegment()

	// Write the actual data
	n, err = w.writer.Write(p)

	// Flush the output
	w.Flush()

	return n, err
}

// Flush flushes the underlying writer
func (w *MarkupWriter) Flush() {
	if f, ok := w.writer.(http.Flusher); ok {
		f.Flush()
	}
}

// Close closes any open output segment and stops the keepalive monitor if in markup mode
func (w *MarkupWriter) Close(exitCode int) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if !w.markupMode {
		return
	}

	// Send the stop signal to the keepalive goroutine
	close(w.stopChan)

	// Close any open output segment
	w.closeSegment()

	if exitCode != -1 {
		if _, err := w.writer.Write([]byte("<exitcode>" + strconv.Itoa(exitCode) + "</exitcode>\n")); err != nil {
			log.Printf("Error writing exitcode: %v", err)
		}
	}

	w.Flush()
}

func (w *MarkupWriter) openSegment() {
	if w.markupMode && !w.isOutputOpen {
		infix := ""
		if w.Process != nil {
			infix = " lines=\"" + strconv.Itoa(w.Process.Lines) + "\""
		}
		if _, err := w.writer.Write([]byte("<output" + infix + ">\n")); err != nil {
			log.Printf("Error writing opening output tag: %v", err)
		}
		w.isOutputOpen = true
	}
}

func (w *MarkupWriter) closeSegment() {
	if w.markupMode && w.isOutputOpen {
		infix := ""
		if w.Process != nil {
			infix = " lines=\"" + strconv.Itoa(w.Process.Lines) + "\""
		}
		if _, err := w.writer.Write([]byte("</output" + infix + ">\n")); err != nil {
			log.Printf("Error writing closing output tag: %v", err)
		}
		w.isOutputOpen = false
	}
}

// keepaliveMonitor runs in a separate goroutine to monitor for inactivity and send keepalives
func (w *MarkupWriter) keepaliveMonitor() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.mutex.Lock()
			if time.Since(w.lastWriteTime) > 15*time.Second {
				w.closeSegment()
				if _, err := w.writer.Write([]byte("<keepalive/>\n")); err != nil {
					log.Printf("Error writing keepalive: %v", err)
				}
				w.Flush()
			}
			w.mutex.Unlock()
		}
	}
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	ID        string    // Unique identifier for the process
	Command   string    // The command that was executed
	PID       int       // Process ID
	StartTime time.Time // When the process was started
	Cmd       *exec.Cmd // The actual command object
	ExitCode  int       // The exit code of the process
	Lines     int
	Writers   []io.Writer
	Lock      sync.Mutex // Lock for thread safety
	Done      *sync.Cond // Cond for thread safety
}

// WriteToAllProcessWriters writes to all writers in a process
func (p *ProcessInfo) WriteToAllProcessWriters(data []byte) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	for _, writer := range p.Writers {
		if _, err := writer.Write(data); err != nil {
			log.Printf("Error writing to output: %v", err)
			continue
		}

		// Try to flush if it's a MarkupWriter
		if mw, ok := writer.(*MarkupWriter); ok {
			mw.Flush()
		}
	}
	p.Lines += bytes.Count(data, []byte("\n"))
}

// Wait blocks until the process is done and returns its exit code
func (p *ProcessInfo) Wait() int {
	p.Done.L.Lock()
	defer p.Done.L.Unlock()
	p.Done.Wait()
	return p.ExitCode
}

// ProcessRegistry manages running processes
type ProcessRegistry struct {
	shellTemplates map[string]ShellTemplate
	processes      map[string]*ProcessInfo
	mutex          sync.RWMutex
}

// NewProcessRegistry creates a new process registry
func NewProcessRegistry(templates map[string]ShellTemplate) *ProcessRegistry {
	return &ProcessRegistry{
		shellTemplates: templates,
		processes:      make(map[string]*ProcessInfo),
	}
}

// HasShellTemplate checks if a shell template exists for a given command
func (r *ProcessRegistry) HasShellTemplate(cmd string) bool {
	_, exists := r.shellTemplates[cmd]
	return exists
}

// AddWriterToProcess adds a writer to a process's Writers list
func (r *ProcessRegistry) AddWriterToProcess(processID string, writer io.Writer) error {
	process, exists := r.GetProcess(processID)
	if !exists {
		return fmt.Errorf("process with ID %s not found", processID)
	}

	process.Lock.Lock()
	defer process.Lock.Unlock()

	if mw, ok := writer.(*MarkupWriter); ok {
		mw.Process = process
	}

	// Add the writer directly without wrapping (the caller is responsible for thread safety)
	process.Writers = append(process.Writers, writer)
	return nil
}

// RegisterProcess adds a process to the registry
func (r *ProcessRegistry) RegisterProcess(cmd string, command *exec.Cmd, w io.Writer) *ProcessInfo {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Generate a unique ID for the process
	processID := fmt.Sprintf("%s-%d", cmd, time.Now().UnixNano())

	process := &ProcessInfo{
		ID:        processID,
		Command:   cmd,
		PID:       -1,
		StartTime: time.Now(),
		Cmd:       command,
		Lines:     0,
		ExitCode:  -1,
		Writers:   make([]io.Writer, 0),
		Done:      sync.NewCond(new(sync.Mutex)),
	}
	r.processes[processID] = process

	// Add the writer if provided
	if w != nil {
		if mw, ok := w.(*MarkupWriter); ok {
			mw.Process = process
		}

		// Add the writer directly without wrapping (the caller is responsible for thread safety)
		process.Writers = append(process.Writers, w)
	}

	return process
}

// GetProcess retrieves a process by ID
func (r *ProcessRegistry) GetProcess(id string) (*ProcessInfo, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	process, exists := r.processes[id]
	return process, exists
}

// ListProcesses returns a list of all running processes
func (r *ProcessRegistry) ListProcesses() []map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make([]map[string]interface{}, 0, len(r.processes))

	for _, process := range r.processes {
		process.Lock.Lock()
		info := map[string]interface{}{
			"id":           process.ID,
			"command":      process.Command,
			"pid":          process.PID,
			"start_time":   process.StartTime,
			"running_time": time.Since(process.StartTime).String(),
		}
		process.Lock.Unlock()
		result = append(result, info)
	}

	return result
}

// TerminateProcess sends a signal to terminate a process
func (r *ProcessRegistry) TerminateProcess(id string) error {
	process, exists := r.GetProcess(id)
	if !exists {
		return fmt.Errorf("process with ID %s not found", id)
	}

	process.Lock.Lock()
	defer process.Lock.Unlock()

	// Try to kill the process gracefully first (SIGTERM)
	if err := process.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// If SIGTERM fails, force kill with SIGKILL
		if killErr := process.Cmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("failed to kill process: %v", killErr)
		}
	}

	return nil
}

// Execute runs a command and returns its exit code
func (r *ProcessRegistry) Execute(cwd string, cmd string, args map[string]interface{}, w io.Writer) (*ProcessInfo, error) {
	shellTmpl, exists := r.shellTemplates[cmd]
	if !exists {
		return nil, fmt.Errorf("command not found: %s", cmd)
	}

	tmpl, err := template.New("cmd").Parse(shellTmpl.Template)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %v", err)
	}

	var cmdStr bytes.Buffer
	err = tmpl.Execute(&cmdStr, args)
	if err != nil {
		return nil, fmt.Errorf("template execution error: %v", err)
	}

	finalCmd := cmdStr.String()
	if shellTmpl.User != "" {
		finalCmd = "sudo -u " + shellTmpl.User + " " + finalCmd
	}

	shellcmd := exec.Command("sh", "-c", finalCmd)
	shellcmd.Dir = cwd

	stdout, err := shellcmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout: %v", err)
	}
	stderr, err := shellcmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stderr: %v", err)
	}

	// Register the process
	processInfo := r.RegisterProcess(cmd, shellcmd, w)

	// Start the process
	if err := shellcmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}

	processInfo.PID = shellcmd.Process.Pid

	// Start a goroutine to read output and write to all writers
	go func() {
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

			// Write to all attached writers
			processInfo.WriteToAllProcessWriters(buf[:n])
		}

		// Wait for the command to finish
		err = shellcmd.Wait()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
				processInfo.Lock.Lock()
				processInfo.ExitCode = exitCode
				processInfo.Lock.Unlock()
			}
		} else {
			processInfo.Lock.Lock()
			processInfo.ExitCode = 0
			processInfo.Lock.Unlock()
		}
		processInfo.Done.L.Lock()
		processInfo.Done.Broadcast()
		processInfo.Done.L.Unlock()
	}()

	return processInfo, nil
}
