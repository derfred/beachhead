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

	"github.com/google/uuid"
)

// ProcessListener provides a thread-safe writer with optional markup capabilities
type ProcessListener struct {
	ID            string
	Process       *ProcessInfo
	mutex         sync.Mutex
	markupMode    bool
	isOutputOpen  bool
	lastWriteTime time.Time
	writeChan     chan []byte
	stopChan      chan struct{}
}

// NewProcessListener creates a new ProcessListener
func NewProcessListener(useMarkup bool) *ProcessListener {
	return &ProcessListener{
		ID:            uuid.New().String(),
		Process:       nil,
		markupMode:    useMarkup,
		isOutputOpen:  false,
		lastWriteTime: time.Now(),
		writeChan:     make(chan []byte, 100),
		stopChan:      make(chan struct{}),
	}
}

// Forward forwards data to the process listener
func (w *ProcessListener) Forward(p []byte) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.writeChan == nil {
		return false
	}

	// Make a copy of the data to avoid race conditions
	dataCopy := make([]byte, len(p))
	copy(dataCopy, p)

	select {
	case w.writeChan <- dataCopy:
		return true
	case <-time.After(100 * time.Millisecond):
		return true
	default:
		return true
	}
}

// Write implements the io.Writer interface with optional markup
func (w *ProcessListener) Write(rw http.ResponseWriter) error {
	for {
		select {
		case p := <-w.writeChan:
			w.openSegment(rw)
			if _, err := rw.Write(p); err != nil {
				return err
			}
			if f, ok := rw.(http.Flusher); ok {
				f.Flush()
			}
		case <-time.After(10 * time.Second):
			w.closeSegment(rw)
			if _, err := rw.Write([]byte("<keepalive/>\n")); err != nil {
				return err
			}
			if f, ok := rw.(http.Flusher); ok {
				f.Flush()
			}
		case <-w.stopChan:
			return nil
		}
	}
}

// Close closes any open output segment and stops the keepalive monitor if in markup mode
func (w *ProcessListener) Close(rw http.ResponseWriter, exitCode int) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// close the write channel
	if w.writeChan != nil {
		close(w.writeChan)
	}

	if !w.markupMode {
		return
	}

	// Close any open output segment
	w.closeSegment(rw)

	if exitCode != -1 {
		if _, err := rw.Write([]byte("<exitcode>" + strconv.Itoa(exitCode) + "</exitcode>\n")); err != nil {
			log.Printf("Error writing exitcode: %v", err)
		}
	}

	if f, ok := rw.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *ProcessListener) openSegment(rw http.ResponseWriter) {
	if w.markupMode && !w.isOutputOpen {
		infix := ""
		if w.Process != nil {
			w.Process.Lock.Lock()
			infix = " lines=\"" + strconv.Itoa(w.Process.Lines) + "\""
			w.Process.Lock.Unlock()
		}
		if _, err := rw.Write([]byte("<output" + infix + ">\n")); err != nil {
			log.Printf("Error writing opening output tag: %v", err)
		}
		w.isOutputOpen = true
	}
}

func (w *ProcessListener) closeSegment(rw http.ResponseWriter) {
	if w.markupMode && w.isOutputOpen {
		infix := ""
		if w.Process != nil {
			w.Process.Lock.Lock()
			infix = " lines=\"" + strconv.Itoa(w.Process.Lines) + "\""
			w.Process.Lock.Unlock()
		}
		if _, err := rw.Write([]byte("</output" + infix + ">\n")); err != nil {
			log.Printf("Error writing closing output tag: %v", err)
		}
		w.isOutputOpen = false
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
	Listeners map[string]*ProcessListener
	Lock      sync.Mutex // Lock for thread safety
	Done      *sync.Cond // Cond for thread safety
}

func (p *ProcessInfo) Copy(r io.Reader) {
	buf := make([]byte, 1024)

	for {
		n, err := r.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading output: %v", err)
			}
			break
		}

		// Write to all attached listeners
		p.Lock.Lock()
		for _, listener := range p.Listeners {
			if !listener.Forward(buf[:n]) {
				p.removeListener(listener)
			}
		}
		p.Lines += bytes.Count(buf[:n], []byte("\n"))
		p.Lock.Unlock()
	}
}

// Wait blocks until the process is done and returns its exit code
func (p *ProcessInfo) Wait() int {
	p.Lock.Lock()
	exitCode := p.ExitCode
	p.Lock.Unlock()

	if exitCode != -1 {
		return exitCode
	}

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
func (r *ProcessRegistry) AttachListener(processID string, listener *ProcessListener) error {
	process, exists := r.GetProcess(processID)
	if !exists {
		return fmt.Errorf("process with ID %s not found", processID)
	}

	process.Lock.Lock()
	defer process.Lock.Unlock()

	listener.Process = process
	process.Listeners[listener.ID] = listener

	return nil
}

// removeListener removes a listener from a process
func (p *ProcessInfo) removeListener(listener *ProcessListener) {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	delete(p.Listeners, listener.ID)
	close(listener.stopChan)
	close(listener.writeChan)
	listener.writeChan = nil
}

// registerProcess adds a process to the registry
func (r *ProcessRegistry) registerProcess(cmd string, command *exec.Cmd, listener *ProcessListener) *ProcessInfo {
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
		Listeners: make(map[string]*ProcessListener),
		Done:      sync.NewCond(new(sync.Mutex)),
	}
	r.processes[processID] = process

	// Add the writer if provided
	if listener != nil {
		listener.Process = process
		process.Listeners[listener.ID] = listener
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

	process.Cmd.Wait()

	return nil
}

// Execute runs a command and returns its exit code
func (r *ProcessRegistry) Execute(cwd string, cmd string, args map[string]interface{}, listener *ProcessListener) (*ProcessInfo, error) {
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
	processInfo := r.registerProcess(cmd, shellcmd, listener)

	// Start the process
	if err := shellcmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}

	processInfo.PID = shellcmd.Process.Pid

	// Start a goroutine to read output and write to all writers
	go processInfo.Copy(stdout)
	go processInfo.Copy(stderr)
	go func() {
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

		for _, listener := range processInfo.Listeners {
			processInfo.removeListener(listener)
		}
	}()

	return processInfo, nil
}
