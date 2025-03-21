package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"syscall"
	"text/template"
	"time"
)

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	ID        string    // Unique identifier for the process
	Command   string    // The command that was executed
	PID       int       // Process ID
	StartTime time.Time // When the process was started
	Cmd       *exec.Cmd // The actual command object
	ExitCode  int       // The exit code of the process
	Writers   []io.Writer
	Lock      sync.Mutex // Lock for thread safety
	Done      *sync.Cond // Cond for thread safety
}

// WriteToAllProcessWriters writes to all writers in a process
func (p *ProcessInfo) WriteToAllProcessWriters(data []byte) {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	for _, writer := range p.Writers {
		writer.Write(data)

		// Flush if the writer supports it
		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}
	}
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

	process.Writers = append(process.Writers, writer)
	return nil
}

// RegisterProcess adds a process to the registry
func (r *ProcessRegistry) RegisterProcess(id string, cmd string, command *exec.Cmd) *ProcessInfo {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	info := &ProcessInfo{
		ID:        id,
		Command:   cmd,
		PID:       command.Process.Pid,
		StartTime: time.Now(),
		Cmd:       command,
		Writers:   make([]io.Writer, 0),
		Done:      sync.NewCond(new(sync.Mutex)),
	}

	r.processes[id] = info
	return info
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

	if err := shellcmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}

	// Generate a unique ID for the process
	processID := fmt.Sprintf("%s-%d", cmd, time.Now().UnixNano())

	// Register the process
	processInfo := r.RegisterProcess(processID, finalCmd, shellcmd)

	// Add the writer if provided
	if w != nil {
		processInfo.Lock.Lock()
		processInfo.Writers = append(processInfo.Writers, w)
		processInfo.Lock.Unlock()
	}

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
