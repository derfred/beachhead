package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/google/uuid"
)

// ProcessListener provides a thread-safe writer with optional markup capabilities
type ProcessListener struct {
	ID            string
	IsClosed      bool
	mutex         sync.Mutex
	markupMode    bool
	isOutputOpen  bool
	lastWriteTime time.Time
	writeChan     chan *ProcessMessage
	stopChan      chan struct{}
	lines         int
}

type ProcessMessage struct {
	Data  []byte
	Start int
	Lines int
}

// NewProcessListener creates a new ProcessListener
func NewProcessListener(useMarkup bool) *ProcessListener {
	return &ProcessListener{
		ID:            uuid.New().String(),
		IsClosed:      false,
		markupMode:    useMarkup,
		isOutputOpen:  false,
		lastWriteTime: time.Now(),
		writeChan:     make(chan *ProcessMessage, 100),
		stopChan:      make(chan struct{}),
	}
}

// Forward forwards data to the process listener
func (w *ProcessListener) Forward(p *ProcessMessage) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.IsClosed {
		return false
	}

	select {
	case w.writeChan <- p:
		return true
	case <-time.After(100 * time.Millisecond):
		return true
	default:
		return true
	}
}

// Write implements the io.Writer interface with optional markup
func (l *ProcessListener) Write(rw http.ResponseWriter) error {
	for {
		select {
		case p := <-l.writeChan:
			l.lines = p.Start
			l.openSegment(rw)
			if _, err := rw.Write(p.Data); err != nil {
				return err
			}
			l.lines += p.Lines
			if f, ok := rw.(http.Flusher); ok {
				f.Flush()
			}
		case <-time.After(10 * time.Second):
			l.closeSegment(rw)
			if _, err := rw.Write([]byte("<keepalive/>\n")); err != nil {
				return err
			}
			if f, ok := rw.(http.Flusher); ok {
				f.Flush()
			}
		case <-l.stopChan:
			return nil
		}
	}
}

// Shutdown closes the write channel
func (l *ProcessListener) Shutdown() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.IsClosed {
		return
	}

	l.IsClosed = true
	close(l.stopChan)
	close(l.writeChan)
}

// Close closes any open output segment and stops the keepalive monitor if in markup mode
func (l *ProcessListener) Close(rw http.ResponseWriter, exitCode int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.IsClosed {
		return
	}

	// Shutdown the listener without calling the Shutdown method to avoid deadlock
	l.IsClosed = true
	close(l.stopChan)
	close(l.writeChan)

	if !l.markupMode {
		return
	}

	// Close any open output segment
	l.closeSegment(rw)

	if exitCode != -1 {
		if _, err := rw.Write([]byte("<exitcode>" + strconv.Itoa(exitCode) + "</exitcode>\n")); err != nil {
			log.Printf("Error writing exitcode: %v", err)
		}
	}

	if f, ok := rw.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *ProcessListener) openSegment(rw http.ResponseWriter) {
	if l.markupMode && !l.isOutputOpen {
		infix := " lines=\"" + strconv.Itoa(l.lines) + "\""
		if _, err := rw.Write([]byte("<output" + infix + ">\n")); err != nil {
			log.Printf("Error writing opening output tag: %v", err)
		}
		l.isOutputOpen = true
	}
}

func (l *ProcessListener) closeSegment(rw http.ResponseWriter) {
	if l.markupMode && l.isOutputOpen {
		infix := " lines=\"" + strconv.Itoa(l.lines) + "\""
		if _, err := rw.Write([]byte("</output" + infix + ">\n")); err != nil {
			log.Printf("Error writing closing output tag: %v", err)
		}
		l.isOutputOpen = false
	}
}

// ProcessExit struct should use the same mutex for condition variable
type ProcessExit struct {
	ExitCode int
	mu       sync.Mutex
	cond     *sync.Cond
}

func NewProcessExit() *ProcessExit {
	pe := &ProcessExit{
		ExitCode: -1,
		mu:       sync.Mutex{},
	}
	pe.cond = sync.NewCond(&pe.mu) // Use the same mutex for the condition variable
	return pe
}

func (p *ProcessExit) Set(code int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ExitCode = code
	p.cond.Broadcast()
}

func (p *ProcessExit) Get() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ExitCode
}

func (p *ProcessExit) IsSet() bool {
	return p.Get() != -1
}

func (p *ProcessExit) Wait() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ExitCode != -1 {
		return p.ExitCode
	}

	p.cond.Wait()
	return p.ExitCode
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	ID              string       // Unique identifier for the process
	Command         string       // The command that was executed
	PID             int          // Process ID
	StartTime       time.Time    // When the process was started
	Cmd             *exec.Cmd    // The actual command object
	Exit            *ProcessExit // The exit code of the process
	Lines           int
	Listeners       map[string]*ProcessListener
	Lock            sync.Mutex // Lock for thread safety
	Done            *sync.Cond // Cond for thread safety
	lastOutputLines [][]byte
	lastOutputIndex int
}

func (p *ProcessInfo) copyMessage(data []byte) *ProcessMessage {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &ProcessMessage{
		Data:  dataCopy,
		Start: p.Lines,
		Lines: bytes.Count(data, []byte("\n")),
	}
}

func (p *ProcessInfo) storeContextLines(data []byte) {
	i := 0
	for i < len(data)-1 {
		j := bytes.Index(data[i:], []byte("\n"))
		if j == -1 {
			j = len(data)
		} else {
			j += i
		}
		p.lastOutputLines[p.lastOutputIndex] = append([]byte{}, data[i:j]...)
		p.lastOutputIndex = (p.lastOutputIndex + 1) % 5
		i = j + 1
		if i < len(data) {
			p.lastOutputLines[p.lastOutputIndex] = []byte{}
		}
	}
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
		p.storeContextLines(buf[:n])
		for _, listener := range p.Listeners {
			listener.Forward(p.copyMessage(buf[:n]))
		}
		p.Lines += bytes.Count(buf[:n], []byte("\n"))
		p.Lock.Unlock()
	}
}

// Wait blocks until the process is done and returns its exit code
func (p *ProcessInfo) Wait() int {
	p.Lock.Lock()
	exit := p.Exit
	p.Lock.Unlock()
	return exit.Wait()
}

// removeListener removes a listener from a process
func (p *ProcessInfo) RemoveListener(listener *ProcessListener) {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	listener.Shutdown()
	delete(p.Listeners, listener.ID)
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
func (r *ProcessRegistry) AttachListener(processID string, listener *ProcessListener, catchup bool) error {
	process, exists := r.GetProcess(processID)
	if !exists {
		return fmt.Errorf("process with ID %s not found", processID)
	}

	process.Lock.Lock()
	defer process.Lock.Unlock()

	// If we have previous output lines, send them first
	if process.lastOutputLines != nil && catchup {
		var contextLines [][]byte
		// Collect the last 5 lines in correct order
		for i := 0; i < 5; i++ {
			idx := (process.lastOutputIndex + i) % 5
			if process.lastOutputLines[idx] != nil && len(process.lastOutputLines[idx]) > 0 {
				contextLines = append(contextLines, process.lastOutputLines[idx])
			}
		}

		// If we have context lines, send them first
		if len(contextLines) > 0 {
			// Join the lines with newlines
			contextData := bytes.Join(contextLines, []byte("\n"))
			contextData = append(contextData, '\n') // Add final newline

			// Send the context as a separate message
			contextMsg := &ProcessMessage{
				Data:  contextData,
				Start: process.Lines - len(contextLines),
				Lines: len(contextLines),
			}
			listener.Forward(contextMsg)
		}
	}

	process.Listeners[listener.ID] = listener

	return nil
}

// registerProcess adds a process to the registry
func (r *ProcessRegistry) registerProcess(cmd string, command *exec.Cmd, listener *ProcessListener) *ProcessInfo {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Generate a unique ID for the process
	processID := fmt.Sprintf("%s-%d", cmd, time.Now().UnixNano())

	process := &ProcessInfo{
		ID:              processID,
		Command:         cmd,
		PID:             -1,
		StartTime:       time.Now(),
		Cmd:             command,
		Lines:           0,
		Exit:            NewProcessExit(),
		Listeners:       make(map[string]*ProcessListener),
		lastOutputLines: make([][]byte, 5),
		lastOutputIndex: 0,
	}
	process.lastOutputLines[0] = []byte{}
	r.processes[processID] = process

	// Add the writer if provided
	if listener != nil {
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
			"exited":       process.Exit.IsSet(),
		}
		process.Lock.Unlock()
		result = append(result, info)
	}

	return result
}

// findChildProcesses recursively finds all child processes of a given PID
func findChildProcesses(parentPID int) ([]int, error) {
	var allPIDs []int
	allPIDs = append(allPIDs, parentPID)

	// Use ps command to find child processes
	cmd := exec.Command("ps", "-eo", "pid,ppid", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		// If ps command fails, just return the parent PID
		log.Printf("Warning: ps command failed: %v", err)
		return allPIDs, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	pidMap := make(map[int][]int) // parent -> children mapping

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, err1 := strconv.Atoi(fields[0])
			ppid, err2 := strconv.Atoi(fields[1])
			if err1 == nil && err2 == nil {
				pidMap[ppid] = append(pidMap[ppid], pid)
			}
		}
	}

	// Recursively find all descendants
	var findDescendants func(int)
	findDescendants = func(parentPID int) {
		if children, exists := pidMap[parentPID]; exists {
			for _, childPID := range children {
				allPIDs = append(allPIDs, childPID)
				findDescendants(childPID) // Recursive call for grandchildren
			}
		}
	}

	findDescendants(parentPID)
	return allPIDs, nil
}

// isProcessAlive checks if a process with the given PID is still running
func isProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix systems, sending signal 0 checks if the process exists
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// signalProcess sends a signal to a process if it's still alive
func signalProcess(pid int, sig syscall.Signal) error {
	if !isProcessAlive(pid) {
		return nil // Process is already dead
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	return process.Signal(sig)
}

// TerminationStatus represents the status of a process termination
type TerminationStatus struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Completed bool   `json:"completed"`
	Remaining int    `json:"remaining,omitempty"`
	Message   string `json:"message,omitempty"`
}

// TerminateProcess sends a signal to terminate a process using a multi-step approach
// If statusCh is provided, it will receive a status update after 500ms
func (r *ProcessRegistry) TerminateProcess(id string, statusCh chan<- TerminationStatus) error {
	process, exists := r.GetProcess(id)
	if !exists {
		return fmt.Errorf("process with ID %s not found", id)
	}

	process.Lock.Lock()
	parentPID := process.PID
	if parentPID <= 0 {
		process.Lock.Unlock()
		return fmt.Errorf("invalid process PID: %d", parentPID)
	}
	process.Lock.Unlock()

	// Move termination logic to a goroutine
	go func() {
		process.Lock.Lock()
		defer process.Lock.Unlock()

		// Step 1: Recursively enumerate the process PID and all children
		allPIDs, err := findChildProcesses(parentPID)
		if err != nil {
			log.Printf("Warning: Failed to find child processes for PID %d: %v", parentPID, err)
			// Continue with just the parent PID
			allPIDs = []int{parentPID}
		}

		log.Printf("Found %d processes to terminate: %v", len(allPIDs), allPIDs)
		log.Printf("Sending SIGTERM to parent process %d", parentPID)

		// Step 2: Send graceful shutdown signal (SIGTERM) to parent process only
		if err := signalProcess(parentPID, syscall.SIGTERM); err != nil {
			log.Printf("Warning: Failed to send SIGTERM to parent process %d: %v", parentPID, err)
		}

		// Wait 500ms and check status if status channel is provided
		time.Sleep(500 * time.Millisecond)

		if statusCh != nil {
			// Count how many processes are still alive after 500ms
			var aliveCount int
			for _, pid := range allPIDs {
				if isProcessAlive(pid) {
					aliveCount++
				}
			}

			// Send status update
			if aliveCount == 0 {
				statusCh <- TerminationStatus{
					ID:        id,
					Status:    "terminated",
					Completed: true,
					Message:   "All processes terminated successfully",
				}
			} else {
				statusCh <- TerminationStatus{
					ID:        id,
					Status:    "terminating",
					Completed: false,
					Remaining: aliveCount,
					Message:   fmt.Sprintf("Termination in progress, %d processes still running", aliveCount),
				}
			}
		}

		// Continue with the rest of the termination process
		// Step 3: Wait additional time (1.5 seconds more to complete the original 2 seconds)
		time.Sleep(1500 * time.Millisecond)

		var stillRunningPIDs []int

		// Step 4: Send SIGKILL to all remaining processes
		for _, pid := range allPIDs {
			if isProcessAlive(pid) {
				stillRunningPIDs = append(stillRunningPIDs, pid)
			}
		}

		log.Printf("Still running processes (%d): %v", len(stillRunningPIDs), stillRunningPIDs)
		for _, pid := range stillRunningPIDs {
			if err := signalProcess(pid, syscall.SIGKILL); err != nil {
				log.Printf("Warning: Failed to send SIGKILL to process %d: %v", pid, err)
			}
		}

		// Step 5: Wait 2 seconds
		time.Sleep(2 * time.Second)

		var remainingPIDs []int

		// Step 6: Send final kill signal (SIGKILL) to all remaining processes
		for _, pid := range allPIDs {
			if isProcessAlive(pid) {
				remainingPIDs = append(remainingPIDs, pid)
			}
		}

		log.Printf("Remaining processes (%d): %v", len(remainingPIDs), remainingPIDs)
		for _, pid := range remainingPIDs {
			if err := signalProcess(pid, syscall.SIGKILL); err != nil {
				log.Printf("Warning: Failed to send SIGKILL to process %d: %v", pid, err)
			}
		}

		time.Sleep(2 * time.Second)
		log.Printf("Termination process completed for process %s", id)
	}()

	return nil
}

// Execute runs a command and returns its exit code
func (r *ProcessRegistry) Execute(cwd string, cmd string, args map[string]interface{}, listener *ProcessListener) (*ProcessInfo, error) {
	shellTmpl, exists := r.shellTemplates[cmd]
	if !exists {
		return nil, fmt.Errorf("command not found: %s", cmd)
	}

	// Parse & render the template
	tmpl, err := template.New("cmd").Option("missingkey=error").Parse(shellTmpl.Template)
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

	// Log the command
	if shellTmpl.User != "" {
		log.Printf("Executing command as user %s: %s (cwd: %s)", shellTmpl.User, finalCmd, cwd)
	} else {
		log.Printf("Executing command: %s (cwd: %s)", finalCmd, cwd)
	}

	// Execute the command
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
			}
		}

		processInfo.Exit.Set(exitCode)

		processInfo.Lock.Lock()
		defer processInfo.Lock.Unlock()
		for _, listener := range processInfo.Listeners {
			listener.Shutdown()
		}
	}()

	return processInfo, nil
}
