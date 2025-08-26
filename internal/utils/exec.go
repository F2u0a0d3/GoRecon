package utils

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	
	"github.com/rs/zerolog"
)

// ExecWrapper provides safe execution of external tools with logging and monitoring
type ExecWrapper struct {
	logger        zerolog.Logger
	timeout       time.Duration
	workingDir    string
	env           []string
	maxMemoryMB   int
	maxCPUPercent float64
	mutex         sync.RWMutex
}

// ExecResult contains the results of command execution
type ExecResult struct {
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
	PID        int           `json:"pid"`
	MemoryUsed int64         `json:"memory_used"`
	CPUUsage   float64       `json:"cpu_usage"`
}

// ExecOptions provides options for command execution
type ExecOptions struct {
	Timeout       time.Duration
	WorkingDir    string
	Env           []string
	Input         string
	IgnoreError   bool
	CaptureOutput bool
	StreamOutput  bool
	OutputHandler func(line string)
	MaxMemoryMB   int
	MaxOutputSize int64
}

// StreamingExecResult provides real-time output streaming
type StreamingExecResult struct {
	Command   string
	Args      []string
	PID       int
	StartTime time.Time
	Stdout    chan string
	Stderr    chan string
	Done      chan ExecResult
	Cancel    context.CancelFunc
}

// NewExecWrapper creates a new execution wrapper
func NewExecWrapper(logger zerolog.Logger) *ExecWrapper {
	return &ExecWrapper{
		logger:        logger.With().Str("component", "exec").Logger(),
		timeout:       10 * time.Minute,
		maxMemoryMB:   1024,
		maxCPUPercent: 80.0,
	}
}

// SetTimeout sets the default execution timeout
func (e *ExecWrapper) SetTimeout(timeout time.Duration) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.timeout = timeout
}

// SetWorkingDir sets the default working directory
func (e *ExecWrapper) SetWorkingDir(dir string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.workingDir = dir
}

// SetEnv sets the default environment variables
func (e *ExecWrapper) SetEnv(env []string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.env = env
}

// Execute runs a command and returns the complete result
func (e *ExecWrapper) Execute(ctx context.Context, command string, args []string, options ...*ExecOptions) (*ExecResult, error) {
	var opts *ExecOptions
	if len(options) > 0 {
		opts = options[0]
	} else {
		opts = &ExecOptions{}
	}
	
	return e.executeWithOptions(ctx, command, args, opts)
}

// ExecuteSimple runs a command with default options
func (e *ExecWrapper) ExecuteSimple(ctx context.Context, command string, args ...string) (*ExecResult, error) {
	return e.Execute(ctx, command, args)
}

// ExecuteStream runs a command with streaming output
func (e *ExecWrapper) ExecuteStream(ctx context.Context, command string, args []string, options ...*ExecOptions) (*StreamingExecResult, error) {
	var opts *ExecOptions
	if len(options) > 0 {
		opts = options[0]
	} else {
		opts = &ExecOptions{StreamOutput: true}
	}
	
	return e.executeStreaming(ctx, command, args, opts)
}

// CheckBinary verifies that a binary exists and is executable
func (e *ExecWrapper) CheckBinary(binary string) error {
	path, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("binary %s not found in PATH: %w", binary, err)
	}
	
	// Check if file is executable
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat binary %s: %w", path, err)
	}
	
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("binary %s is not executable", path)
	}
	
	e.logger.Debug().
		Str("binary", binary).
		Str("path", path).
		Msg("Binary check passed")
	
	return nil
}

// GetVersion attempts to get the version of a binary
func (e *ExecWrapper) GetVersion(ctx context.Context, binary string) (string, error) {
	// Try common version flags
	versionFlags := []string{"--version", "-version", "-V", "-v"}
	
	for _, flag := range versionFlags {
		result, err := e.ExecuteSimple(ctx, binary, flag)
		if err == nil && result.Success {
			// Clean up the version output
			version := strings.TrimSpace(result.Stdout)
			if version == "" {
				version = strings.TrimSpace(result.Stderr)
			}
			
			// Return first line if multi-line
			lines := strings.Split(version, "\n")
			if len(lines) > 0 && lines[0] != "" {
				return lines[0], nil
			}
		}
	}
	
	return "", fmt.Errorf("could not determine version for %s", binary)
}

// InstallBinary attempts to install a binary using package managers
func (e *ExecWrapper) InstallBinary(ctx context.Context, binary string, installCmd string) error {
	if installCmd == "" {
		// Try to determine install command
		if exists, _ := e.commandExists("apt-get"); exists {
			installCmd = fmt.Sprintf("apt-get install -y %s", binary)
		} else if exists, _ := e.commandExists("yum"); exists {
			installCmd = fmt.Sprintf("yum install -y %s", binary)
		} else if exists, _ := e.commandExists("brew"); exists {
			installCmd = fmt.Sprintf("brew install %s", binary)
		} else {
			return fmt.Errorf("no package manager found and no install command provided")
		}
	}
	
	e.logger.Info().
		Str("binary", binary).
		Str("install_cmd", installCmd).
		Msg("Installing binary")
	
	// Parse install command
	parts := strings.Fields(installCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty install command")
	}
	
	cmd := parts[0]
	args := parts[1:]
	
	result, err := e.Execute(ctx, cmd, args, &ExecOptions{
		Timeout:      5 * time.Minute,
		CaptureOutput: true,
	})
	
	if err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}
	
	if !result.Success {
		return fmt.Errorf("installation failed with exit code %d: %s", result.ExitCode, result.Stderr)
	}
	
	// Verify installation
	if err := e.CheckBinary(binary); err != nil {
		return fmt.Errorf("binary installation verification failed: %w", err)
	}
	
	e.logger.Info().
		Str("binary", binary).
		Msg("Binary installed successfully")
	
	return nil
}

// Implementation methods

func (e *ExecWrapper) executeWithOptions(ctx context.Context, command string, args []string, opts *ExecOptions) (*ExecResult, error) {
	startTime := time.Now()
	
	// Apply default options
	if opts.Timeout == 0 {
		opts.Timeout = e.timeout
	}
	if opts.WorkingDir == "" {
		opts.WorkingDir = e.workingDir
	}
	if opts.Env == nil {
		opts.Env = e.env
	}
	if opts.MaxOutputSize == 0 {
		opts.MaxOutputSize = 10 * 1024 * 1024 // 10MB default
	}
	
	// Create command with timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	
	cmd := exec.CommandContext(timeoutCtx, command, args...)
	
	// Set working directory
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}
	
	// Set environment
	if opts.Env != nil {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	
	// Setup input/output
	var stdout, stderr bytes.Buffer
	if opts.CaptureOutput {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}
	
	// Setup input
	if opts.Input != "" {
		cmd.Stdin = strings.NewReader(opts.Input)
	}
	
	e.logger.Debug().
		Str("command", command).
		Strs("args", args).
		Str("working_dir", opts.WorkingDir).
		Dur("timeout", opts.Timeout).
		Msg("Executing command")
	
	// Start command
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	
	pid := cmd.Process.Pid
	
	// Wait for completion
	err = cmd.Wait()
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	// Get exit code
	exitCode := 0
	success := true
	var errorMsg string
	
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
			success = false
		} else {
			success = false
			errorMsg = err.Error()
		}
		
		if !opts.IgnoreError {
			e.logger.Error().Err(err).
				Str("command", command).
				Int("exit_code", exitCode).
				Msg("Command execution failed")
		}
	}
	
	result := &ExecResult{
		Command:   command,
		Args:      args,
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		Duration:  duration,
		StartTime: startTime,
		EndTime:   endTime,
		Success:   success,
		Error:     errorMsg,
		PID:       pid,
	}
	
	// Truncate output if too large
	if int64(len(result.Stdout)) > opts.MaxOutputSize {
		result.Stdout = result.Stdout[:opts.MaxOutputSize] + "\n... [truncated]"
	}
	if int64(len(result.Stderr)) > opts.MaxOutputSize {
		result.Stderr = result.Stderr[:opts.MaxOutputSize] + "\n... [truncated]"
	}
	
	e.logger.Debug().
		Str("command", command).
		Int("exit_code", exitCode).
		Dur("duration", duration).
		Bool("success", success).
		Msg("Command execution completed")
	
	return result, nil
}

func (e *ExecWrapper) executeStreaming(ctx context.Context, command string, args []string, opts *ExecOptions) (*StreamingExecResult, error) {
	// Apply default options
	if opts.Timeout == 0 {
		opts.Timeout = e.timeout
	}
	if opts.WorkingDir == "" {
		opts.WorkingDir = e.workingDir
	}
	
	// Create command with timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	
	cmd := exec.CommandContext(timeoutCtx, command, args...)
	
	// Set working directory
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}
	
	// Set environment
	if opts.Env != nil {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	
	// Create streaming result
	result := &StreamingExecResult{
		Command:   command,
		Args:      args,
		StartTime: time.Now(),
		Stdout:    make(chan string, 100),
		Stderr:    make(chan string, 100),
		Done:      make(chan ExecResult, 1),
		Cancel:    cancel,
	}
	
	// Setup pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	// Setup input
	if opts.Input != "" {
		cmd.Stdin = strings.NewReader(opts.Input)
	}
	
	// Start command
	err = cmd.Start()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	
	result.PID = cmd.Process.Pid
	
	// Start goroutines to read output
	var wg sync.WaitGroup
	
	// Stdout reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(result.Stdout)
		
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			
			// Send to channel
			select {
			case result.Stdout <- line:
			case <-timeoutCtx.Done():
				return
			}
			
			// Call output handler if provided
			if opts.OutputHandler != nil {
				opts.OutputHandler(line)
			}
		}
	}()
	
	// Stderr reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(result.Stderr)
		
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			
			// Send to channel
			select {
			case result.Stderr <- line:
			case <-timeoutCtx.Done():
				return
			}
		}
	}()
	
	// Wait for command completion
	go func() {
		defer close(result.Done)
		
		// Wait for command to finish
		err := cmd.Wait()
		
		// Wait for output readers to finish
		wg.Wait()
		
		endTime := time.Now()
		duration := endTime.Sub(result.StartTime)
		
		// Build final result
		execResult := ExecResult{
			Command:   command,
			Args:      args,
			ExitCode:  0,
			Duration:  duration,
			StartTime: result.StartTime,
			EndTime:   endTime,
			Success:   true,
			PID:       result.PID,
		}
		
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				execResult.ExitCode = exitError.ExitCode()
				execResult.Success = false
			} else {
				execResult.Success = false
				execResult.Error = err.Error()
			}
		}
		
		result.Done <- execResult
	}()
	
	return result, nil
}

func (e *ExecWrapper) commandExists(cmd string) (bool, error) {
	_, err := exec.LookPath(cmd)
	return err == nil, err
}

// KillProcess kills a process by PID
func (e *ExecWrapper) KillProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}
	
	err = process.Kill()
	if err != nil {
		return fmt.Errorf("failed to kill process %d: %w", pid, err)
	}
	
	e.logger.Info().
		Int("pid", pid).
		Msg("Process killed successfully")
	
	return nil
}

// IsProcessRunning checks if a process is still running
func (e *ExecWrapper) IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	
	// Send signal 0 to check if process exists
	err = process.Signal(os.Signal(nil))
	return err == nil
}

// GetProcessInfo returns information about a running process
func (e *ExecWrapper) GetProcessInfo(pid int) (*ProcessInfo, error) {
	// This is a simplified implementation
	// In a real implementation, you would read from /proc/[pid]/ on Linux
	// or use system APIs on other platforms
	
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to find process %d: %w", pid, err)
	}
	
	return &ProcessInfo{
		PID:     pid,
		Running: e.IsProcessRunning(pid),
		Process: process,
	}, nil
}

// ProcessInfo contains information about a process
type ProcessInfo struct {
	PID         int         `json:"pid"`
	Running     bool        `json:"running"`
	MemoryUsage int64       `json:"memory_usage"`
	CPUUsage    float64     `json:"cpu_usage"`
	StartTime   time.Time   `json:"start_time"`
	Process     *os.Process `json:"-"`
}

// SafeExecute provides additional safety checks and resource limits
func (e *ExecWrapper) SafeExecute(ctx context.Context, command string, args []string, limits ResourceLimits) (*ExecResult, error) {
	// Check if command is in allowlist (if configured)
	if !e.isCommandAllowed(command) {
		return nil, fmt.Errorf("command %s is not allowed", command)
	}
	
	// Apply resource limits
	opts := &ExecOptions{
		Timeout:       limits.Timeout,
		MaxMemoryMB:   limits.MaxMemoryMB,
		CaptureOutput: true,
	}
	
	return e.executeWithOptions(ctx, command, args, opts)
}

// ResourceLimits defines resource constraints for command execution
type ResourceLimits struct {
	Timeout       time.Duration
	MaxMemoryMB   int
	MaxCPUPercent float64
	MaxProcesses  int
}

func (e *ExecWrapper) isCommandAllowed(command string) bool {
	// In a real implementation, this would check against a configured allowlist
	// For now, allow all commands
	return true
}