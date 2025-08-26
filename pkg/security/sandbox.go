package security

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sandbox provides secure execution environment for external tools
type Sandbox struct {
	config SandboxConfig
	jail   *ProcessJail
}

// SandboxConfig defines sandbox security parameters
type SandboxConfig struct {
	EnableSandbox     bool              `json:"enable_sandbox"`
	MaxExecutionTime  time.Duration     `json:"max_execution_time"`
	MaxMemoryMB       int64             `json:"max_memory_mb"`
	MaxFileSize       int64             `json:"max_file_size"`
	MaxProcesses      int               `json:"max_processes"`
	AllowedCommands   []string          `json:"allowed_commands"`
	BlockedCommands   []string          `json:"blocked_commands"`
	AllowNetworking   bool              `json:"allow_networking"`
	AllowFileSystem   bool              `json:"allow_filesystem"`
	TempDirectory     string            `json:"temp_directory"`
	WorkingDirectory  string            `json:"working_directory"`
	Environment       map[string]string `json:"environment"`
	DropCapabilities  []string          `json:"drop_capabilities"`
	ReadOnlyPaths     []string          `json:"readonly_paths"`
	BlockedPaths      []string          `json:"blocked_paths"`
}

// ProcessJail manages process isolation and resource limits
type ProcessJail struct {
	pid           int
	startTime     time.Time
	memoryLimit   int64
	cpuLimit      time.Duration
	networkAccess bool
	filesystemRW  bool
	tempDir       string
}

// ExecutionContext provides context for sandboxed execution
type ExecutionContext struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Environment map[string]string `json:"environment"`
	WorkingDir  string            `json:"working_dir"`
	Input       []byte            `json:"input"`
	Timeout     time.Duration     `json:"timeout"`
}

// ExecutionResult contains the result of sandboxed execution
type ExecutionResult struct {
	ExitCode     int           `json:"exit_code"`
	Stdout       []byte        `json:"stdout"`
	Stderr       []byte        `json:"stderr"`
	Duration     time.Duration `json:"duration"`
	MemoryUsed   int64         `json:"memory_used"`
	Killed       bool          `json:"killed"`
	KillReason   string        `json:"kill_reason,omitempty"`
	ResourceUsage ResourceUsage `json:"resource_usage"`
}

// ResourceUsage tracks resource consumption
type ResourceUsage struct {
	MaxMemory     int64         `json:"max_memory"`
	CPUTime       time.Duration `json:"cpu_time"`
	FileReads     int64         `json:"file_reads"`
	FileWrites    int64         `json:"file_writes"`
	NetworkConns  int           `json:"network_connections"`
	ProcessCount  int           `json:"process_count"`
}

// NewSandbox creates a new sandbox with the given configuration
func NewSandbox(config SandboxConfig) (*Sandbox, error) {
	// Set defaults
	if config.MaxExecutionTime == 0 {
		config.MaxExecutionTime = 5 * time.Minute
	}
	if config.MaxMemoryMB == 0 {
		config.MaxMemoryMB = 1024 // 1GB
	}
	if config.MaxProcesses == 0 {
		config.MaxProcesses = 10
	}
	if config.TempDirectory == "" {
		config.TempDirectory = "/tmp/gorecon-sandbox"
	}

	// Create temp directory
	if err := os.MkdirAll(config.TempDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	return &Sandbox{
		config: config,
	}, nil
}

// Execute runs a command in the sandbox
func (s *Sandbox) Execute(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	if !s.config.EnableSandbox {
		return s.executeUnsandboxed(ctx, execCtx)
	}

	// Validate command against whitelist/blacklist
	if err := s.validateCommand(execCtx.Command); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}

	// Create isolated execution environment
	jail, err := s.createJail()
	if err != nil {
		return nil, fmt.Errorf("failed to create process jail: %w", err)
	}
	defer jail.cleanup()

	// Set up execution context
	cmd := exec.CommandContext(ctx, execCtx.Command, execCtx.Args...)
	
	// Configure working directory
	workDir := execCtx.WorkingDir
	if workDir == "" {
		workDir = s.config.WorkingDirectory
	}
	if workDir == "" {
		workDir = jail.tempDir
	}
	cmd.Dir = workDir

	// Set environment variables
	env := os.Environ()
	for k, v := range s.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	for k, v := range execCtx.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Apply security restrictions
	if err := s.applySecurityRestrictions(cmd); err != nil {
		return nil, fmt.Errorf("failed to apply security restrictions: %w", err)
	}

	// Set up I/O
	if execCtx.Input != nil {
		cmd.Stdin = bytes.NewReader(execCtx.Input)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start execution with monitoring
	startTime := time.Now()
	
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	jail.pid = cmd.Process.Pid
	jail.startTime = startTime

	// Monitor execution
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Resource monitoring
	resourceMonitor := s.startResourceMonitoring(jail)
	defer close(resourceMonitor.stop)

	// Wait for completion or timeout
	timeout := execCtx.Timeout
	if timeout == 0 {
		timeout = s.config.MaxExecutionTime
	}

	var err error
	var killed bool
	var killReason string

	select {
	case err = <-done:
		// Process completed normally
	case <-time.After(timeout):
		// Timeout exceeded
		cmd.Process.Kill()
		killed = true
		killReason = "timeout"
		err = fmt.Errorf("execution timeout after %v", timeout)
	case reason := <-resourceMonitor.violations:
		// Resource limit exceeded
		cmd.Process.Kill()
		killed = true
		killReason = reason
		err = fmt.Errorf("resource limit exceeded: %s", reason)
	case <-ctx.Done():
		// Context cancelled
		cmd.Process.Kill()
		killed = true
		killReason = "cancelled"
		err = ctx.Err()
	}

	duration := time.Since(startTime)

	// Get final resource usage
	usage := <-resourceMonitor.final

	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if killed {
			exitCode = -1
		}
	}

	return &ExecutionResult{
		ExitCode:      exitCode,
		Stdout:        stdout.Bytes(),
		Stderr:        stderr.Bytes(),
		Duration:      duration,
		MemoryUsed:    usage.MaxMemory,
		Killed:        killed,
		KillReason:    killReason,
		ResourceUsage: usage,
	}, nil
}

// executeUnsandboxed runs a command without sandboxing (for testing/development)
func (s *Sandbox) executeUnsandboxed(ctx context.Context, execCtx ExecutionContext) (*ExecutionResult, error) {
	timeout := execCtx.Timeout
	if timeout == 0 {
		timeout = s.config.MaxExecutionTime
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, execCtx.Command, execCtx.Args...)
	
	if execCtx.WorkingDir != "" {
		cmd.Dir = execCtx.WorkingDir
	}

	if execCtx.Input != nil {
		cmd.Stdin = bytes.NewReader(execCtx.Input)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	exitCode := 0
	killed := false
	killReason := ""

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			exitCode = -1
			killed = true
			killReason = "timeout"
		}
	}

	return &ExecutionResult{
		ExitCode:   exitCode,
		Stdout:     stdout.Bytes(),
		Stderr:     stderr.Bytes(),
		Duration:   duration,
		Killed:     killed,
		KillReason: killReason,
	}, nil
}

// validateCommand checks if a command is allowed to execute
func (s *Sandbox) validateCommand(command string) error {
	cmdName := filepath.Base(command)

	// Check blacklist first
	for _, blocked := range s.config.BlockedCommands {
		if cmdName == blocked {
			return fmt.Errorf("command %s is blocked", cmdName)
		}
	}

	// Check whitelist if configured
	if len(s.config.AllowedCommands) > 0 {
		allowed := false
		for _, allowedCmd := range s.config.AllowedCommands {
			if cmdName == allowedCmd {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("command %s is not in allowed list", cmdName)
		}
	}

	return nil
}

// createJail sets up process isolation
func (s *Sandbox) createJail() (*ProcessJail, error) {
	// Create temporary directory for this execution
	tempDir := filepath.Join(s.config.TempDirectory, fmt.Sprintf("jail-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create jail directory: %w", err)
	}

	jail := &ProcessJail{
		tempDir:       tempDir,
		memoryLimit:   s.config.MaxMemoryMB * 1024 * 1024,
		networkAccess: s.config.AllowNetworking,
		filesystemRW:  s.config.AllowFileSystem,
	}

	return jail, nil
}

// applySecurityRestrictions applies OS-level security restrictions
func (s *Sandbox) applySecurityRestrictions(cmd *exec.Cmd) error {
	// Set process attributes for Linux
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Create new process group
		Setpgid: true,
		
		// Set resource limits
		// Note: In a production environment, you would implement more comprehensive
		// restrictions using technologies like:
		// - Linux namespaces (PID, network, mount, user, etc.)
		// - cgroups for resource limiting
		// - seccomp for syscall filtering
		// - capabilities dropping
		// - chroot/pivot_root for filesystem isolation
	}

	return nil
}

// ResourceMonitor tracks resource usage during execution
type ResourceMonitor struct {
	violations chan string
	final      chan ResourceUsage
	stop       chan struct{}
}

// startResourceMonitoring monitors process resource usage
func (s *Sandbox) startResourceMonitoring(jail *ProcessJail) *ResourceMonitor {
	monitor := &ResourceMonitor{
		violations: make(chan string, 1),
		final:      make(chan ResourceUsage, 1),
		stop:       make(chan struct{}),
	}

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var maxMemory int64
		var maxProcesses int

		for {
			select {
			case <-ticker.C:
				// Check memory usage
				if memory := s.getProcessMemory(jail.pid); memory > 0 {
					if memory > maxMemory {
						maxMemory = memory
					}
					if memory > jail.memoryLimit {
						select {
						case monitor.violations <- "memory_limit":
						default:
						}
						return
					}
				}

				// Check process count
				if procs := s.getProcessCount(jail.pid); procs > 0 {
					if procs > maxProcesses {
						maxProcesses = procs
					}
					if procs > s.config.MaxProcesses {
						select {
						case monitor.violations <- "process_limit":
						default:
						}
						return
					}
				}

			case <-monitor.stop:
				// Send final usage statistics
				monitor.final <- ResourceUsage{
					MaxMemory:    maxMemory,
					ProcessCount: maxProcesses,
					// Additional metrics would be collected here
				}
				return
			}
		}
	}()

	return monitor
}

// getProcessMemory returns memory usage for a process and its children
func (s *Sandbox) getProcessMemory(pid int) int64 {
	// Read from /proc/[pid]/status for memory information
	// This is a simplified implementation
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return 0
	}

	// Parse VmRSS (Resident Set Size) from status file
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if size, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return size * 1024 // Convert KB to bytes
				}
			}
		}
	}

	return 0
}

// getProcessCount returns the number of processes in the process group
func (s *Sandbox) getProcessCount(pid int) int {
	// This is a simplified implementation
	// In practice, you would walk the process tree
	return 1
}

// cleanup removes temporary files and directories
func (jail *ProcessJail) cleanup() {
	if jail.tempDir != "" {
		os.RemoveAll(jail.tempDir)
	}
}

// IsCommandAllowed checks if a command is allowed in the sandbox
func (s *Sandbox) IsCommandAllowed(command string) bool {
	return s.validateCommand(command) == nil
}

// GetConfig returns the sandbox configuration
func (s *Sandbox) GetConfig() SandboxConfig {
	return s.config
}

// UpdateConfig updates the sandbox configuration
func (s *Sandbox) UpdateConfig(config SandboxConfig) error {
	// Validate new configuration
	if config.MaxExecutionTime <= 0 {
		return fmt.Errorf("max_execution_time must be positive")
	}
	if config.MaxMemoryMB <= 0 {
		return fmt.Errorf("max_memory_mb must be positive")
	}
	if config.MaxProcesses <= 0 {
		return fmt.Errorf("max_processes must be positive")
	}

	s.config = config
	return nil
}

// Close cleans up sandbox resources
func (s *Sandbox) Close() error {
	// Clean up temporary directory
	return os.RemoveAll(s.config.TempDirectory)
}