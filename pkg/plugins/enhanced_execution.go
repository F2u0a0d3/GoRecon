package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/banner"
)

// EnhancedExecutor provides real-time tool output with GORECON styling
type EnhancedExecutor struct {
	mu       sync.RWMutex
	verbose  bool
	showLive bool
}

// StreamingOptions controls how tool output is displayed
type StreamingOptions struct {
	ShowCommand     bool
	ShowProgress    bool
	ShowRealTime    bool
	FilterKeywords  []string
	HighlightWords  []string
	SuppressEmpty   bool
}

// ToolExecution represents a single tool execution with streaming
type ToolExecution struct {
	Stage      string
	Tool       string
	Target     string
	StartTime  time.Time
	EndTime    *time.Time
	Output     []string
	Errors     []string
	ExitCode   int
	PID        int
	Status     string // running, completed, failed, killed
}

// NewEnhancedExecutor creates a new enhanced executor
func NewEnhancedExecutor(verbose, showLive bool) *EnhancedExecutor {
	return &EnhancedExecutor{
		verbose:  verbose,
		showLive: showLive,
	}
}

// ExecuteWithStreaming runs a tool with real-time output streaming
func (e *EnhancedExecutor) ExecuteWithStreaming(ctx context.Context, stage, tool string, args []string, opts *StreamingOptions) (*ToolExecution, error) {
	execution := &ToolExecution{
		Stage:     stage,
		Tool:      tool,
		Target:    "", // Will be extracted from args
		StartTime: time.Now(),
		Status:    "running",
		Output:    make([]string, 0),
		Errors:    make([]string, 0),
	}

	// Extract target from args if possible
	for i, arg := range args {
		if (arg == "--target" || arg == "-t" || arg == "--host") && i+1 < len(args) {
			execution.Target = args[i+1]
			break
		}
	}

	// Display execution header
	e.displayExecutionHeader(execution, args, opts)

	// Create command
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = append(cmd.Env, "FORCE_COLOR=1") // Enable colors in tools that support it
	
	execution.PID = cmd.Process.Pid if cmd.Process != nil

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return execution, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return execution, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start command
	if err := cmd.Start(); err != nil {
		execution.Status = "failed"
		execution.ExitCode = -1
		return execution, fmt.Errorf("failed to start command: %w", err)
	}

	// Stream output in real-time
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream stdout
	go func() {
		defer wg.Done()
		e.streamOutput(stdout, execution, "stdout", opts)
	}()

	// Stream stderr
	go func() {
		defer wg.Done()
		e.streamOutput(stderr, execution, "stderr", opts)
	}()

	// Wait for streams to complete
	wg.Wait()

	// Wait for command to complete
	err = cmd.Wait()
	endTime := time.Now()
	execution.EndTime = &endTime

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			execution.ExitCode = exitError.ExitCode()
		} else {
			execution.ExitCode = -1
		}
		execution.Status = "failed"
	} else {
		execution.ExitCode = 0
		execution.Status = "completed"
	}

	// Display execution footer
	e.displayExecutionFooter(execution)

	return execution, nil
}

func (e *EnhancedExecutor) displayExecutionHeader(exec *ToolExecution, args []string, opts *StreamingOptions) {
	banner.Section(fmt.Sprintf("%s EXECUTION", strings.ToUpper(exec.Tool)))
	
	banner.StatusLine("info", fmt.Sprintf("Stage: %s", exec.Stage))
	banner.StatusLine("info", fmt.Sprintf("Tool: %s", exec.Tool))
	if exec.Target != "" {
		banner.StatusLine("info", fmt.Sprintf("Target: %s", exec.Target))
	}
	banner.StatusLine("info", fmt.Sprintf("Started: %s", exec.StartTime.Format("15:04:05")))
	
	if opts.ShowCommand {
		cmdStr := exec.Tool + " " + strings.Join(args, " ")
		banner.StatusLine("debug", fmt.Sprintf("Command: %s", cmdStr))
	}
	
	fmt.Println()
	banner.StatusLine("info", "Streaming live output...")
	fmt.Printf("\n%s\n", color.New(color.FgCyan).Sprint(strings.Repeat("─", 80)))
}

func (e *EnhancedExecutor) streamOutput(reader io.Reader, exec *ToolExecution, streamType string, opts *StreamingOptions) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		
		if opts.SuppressEmpty && strings.TrimSpace(line) == "" {
			continue
		}

		// Store output
		e.mu.Lock()
		if streamType == "stdout" {
			exec.Output = append(exec.Output, line)
		} else {
			exec.Errors = append(exec.Errors, line)
		}
		e.mu.Unlock()

		// Display real-time output if enabled
		if opts.ShowRealTime {
			e.displayToolOutput(exec.Tool, line, streamType, opts)
		}
	}
}

func (e *EnhancedExecutor) displayToolOutput(tool, line, streamType string, opts *StreamingOptions) {
	// Parse and enhance tool-specific output
	switch strings.ToLower(tool) {
	case "subzy":
		e.displaySubzyOutput(line)
	case "nuclei":
		e.displayNucleiOutput(line)
	case "httpx":
		e.displayHTTPXOutput(line)
	case "hakcheckurl":
		e.displayHakCheckURLOutput(line)
	case "ffuf":
		e.displayFFUFOutput(line)
	case "hakrawler":
		e.displayHakrawlerOutput(line)
	case "jsluice":
		e.displayJSLuiceOutput(line)
	case "gau":
		e.displayGAUOutput(line)
	case "waybackurls":
		e.displayWaybackOutput(line)
	case "cloud_enum":
		e.displayCloudEnumOutput(line)
	default:
		e.displayGenericOutput(line, streamType)
	}
}

func (e *EnhancedExecutor) displaySubzyOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "VULNERABLE") && strings.Contains(line, " - "):
		// Extract domain and service
		parts := strings.Split(line, " - ")
		if len(parts) >= 2 {
			domain := extractDomainFromLine(parts[len(parts)-1])
			service := extractServiceFromLine(line)
			banner.StatusLine("error", fmt.Sprintf("🚨 TAKEOVER: %s (%s)", domain, service))
		} else {
			banner.StatusLine("error", fmt.Sprintf("🚨 VULNERABILITY: %s", line))
		}
	case strings.Contains(line, "EDGE CASE"):
		banner.StatusLine("warning", fmt.Sprintf("⚠️  EDGE CASE: %s", line))
	case strings.Contains(line, "Not Vulnerable") || strings.Contains(line, "NOT VULNERABLE"):
		if e.verbose {
			domain := extractDomainFromLine(line)
			banner.StatusLine("success", fmt.Sprintf("✓ Safe: %s", domain))
		}
	case strings.Contains(line, "Error") || strings.Contains(line, "ERROR"):
		banner.StatusLine("error", fmt.Sprintf("❌ Error: %s", line))
	case strings.Contains(line, "Checking") || strings.Contains(line, "Testing"):
		if e.verbose {
			banner.StatusLine("info", fmt.Sprintf("🔍 %s", line))
		}
	default:
		if e.verbose && line != "" {
			banner.StatusLine("debug", line)
		}
	}
}

func (e *EnhancedExecutor) displayNucleiOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "[critical]"):
		banner.StatusLine("error", fmt.Sprintf("🔴 CRITICAL: %s", line))
	case strings.Contains(line, "[high]"):
		banner.StatusLine("error", fmt.Sprintf("🟠 HIGH: %s", line))
	case strings.Contains(line, "[medium]"):
		banner.StatusLine("warning", fmt.Sprintf("🟡 MEDIUM: %s", line))
	case strings.Contains(line, "[low]"):
		banner.StatusLine("info", fmt.Sprintf("🔵 LOW: %s", line))
	case strings.Contains(line, "[info]"):
		if e.verbose {
			banner.StatusLine("info", fmt.Sprintf("ℹ️  INFO: %s", line))
		}
	case strings.Contains(line, "Templates loaded"):
		banner.StatusLine("info", fmt.Sprintf("📋 %s", line))
	case strings.Contains(line, "Scanning target"):
		banner.StatusLine("info", fmt.Sprintf("🎯 %s", line))
	default:
		if e.verbose && line != "" {
			banner.StatusLine("debug", line)
		}
	}
}

func (e *EnhancedExecutor) displayHTTPXOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.Contains(line, "http") {
		// Parse httpx output format: https://example.com [200] [title] [tech]
		parts := strings.Fields(line)
		if len(parts) > 0 {
			url := parts[0]
			status := "unknown"
			title := ""
			tech := ""
			
			// Extract status code
			for _, part := range parts {
				if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
					content := strings.Trim(part, "[]")
					if len(content) == 3 && strings.HasPrefix(content, "2") {
						status = "✅ " + content
					} else if len(content) == 3 && strings.HasPrefix(content, "3") {
						status = "🔄 " + content
					} else if len(content) == 3 && strings.HasPrefix(content, "4") {
						status = "⚠️  " + content
					} else if len(content) == 3 && strings.HasPrefix(content, "5") {
						status = "❌ " + content
					} else if !strings.Contains(content, "http") {
						if title == "" {
							title = content
						} else {
							tech = content
						}
					}
				}
			}
			
			output := fmt.Sprintf("%s %s", status, url)
			if title != "" {
				output += fmt.Sprintf(" [%s]", title)
			}
			if tech != "" {
				output += fmt.Sprintf(" [%s]", tech)
			}
			
			banner.StatusLine("success", output)
		}
	} else if e.verbose && line != "" {
		banner.StatusLine("debug", line)
	}
}

func (e *EnhancedExecutor) displayHakCheckURLOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.Contains(line, "http") && strings.Contains(line, " ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			url := parts[0]
			status := parts[1]
			
			statusIcon := "📊"
			statusColor := "info"
			
			switch status {
			case "200":
				statusIcon = "✅"
				statusColor = "success"
			case "301", "302", "307":
				statusIcon = "🔄"
				statusColor = "info"
			case "401":
				statusIcon = "🔐"
				statusColor = "warning"
			case "403":
				statusIcon = "🚫"
				statusColor = "warning"
			case "404":
				statusIcon = "❌"
				statusColor = "error"
			case "500", "502", "503":
				statusIcon = "💥"
				statusColor = "error"
			}
			
			banner.StatusLine(statusColor, fmt.Sprintf("%s [%s] %s", statusIcon, status, url))
		}
	} else if e.verbose && line != "" {
		banner.StatusLine("debug", line)
	}
}

func (e *EnhancedExecutor) displayFFUFOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "Status: 200"):
		banner.StatusLine("success", fmt.Sprintf("✅ FOUND: %s", line))
	case strings.Contains(line, "Status: 301") || strings.Contains(line, "Status: 302"):
		banner.StatusLine("info", fmt.Sprintf("🔄 REDIRECT: %s", line))
	case strings.Contains(line, "Status: 403"):
		banner.StatusLine("warning", fmt.Sprintf("🚫 FORBIDDEN: %s", line))
	case strings.Contains(line, "Status: 401"):
		banner.StatusLine("warning", fmt.Sprintf("🔐 AUTH REQUIRED: %s", line))
	case strings.Contains(line, ":: Progress"):
		if e.verbose {
			banner.StatusLine("info", fmt.Sprintf("⏳ %s", line))
		}
	case strings.Contains(line, "Calibrating"):
		banner.StatusLine("info", fmt.Sprintf("🎯 %s", line))
	default:
		if e.verbose && line != "" && !strings.HasPrefix(line, "[") {
			banner.StatusLine("debug", line)
		}
	}
}

func (e *EnhancedExecutor) displayHakrawlerOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.HasPrefix(line, "http") {
		banner.StatusLine("success", fmt.Sprintf("🔍 URL: %s", line))
	} else if strings.Contains(line, "Found") {
		banner.StatusLine("info", fmt.Sprintf("📦 %s", line))
	} else if e.verbose && line != "" {
		banner.StatusLine("debug", line)
	}
}

func (e *EnhancedExecutor) displayJSLuiceOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "endpoint"):
		banner.StatusLine("success", fmt.Sprintf("🔗 ENDPOINT: %s", line))
	case strings.Contains(line, "secret") || strings.Contains(line, "api_key"):
		banner.StatusLine("warning", fmt.Sprintf("🔑 SECRET: %s", line))
	case strings.Contains(line, "url"):
		banner.StatusLine("info", fmt.Sprintf("📎 URL: %s", line))
	default:
		if e.verbose && line != "" {
			banner.StatusLine("debug", line)
		}
	}
}

func (e *EnhancedExecutor) displayGAUOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.HasPrefix(line, "http") {
		// Count parameters in URL
		paramCount := strings.Count(line, "=")
		if paramCount > 0 {
			banner.StatusLine("success", fmt.Sprintf("🔗 URL (%d params): %s", paramCount, line))
		} else {
			banner.StatusLine("info", fmt.Sprintf("🔗 URL: %s", line))
		}
	} else if e.verbose && line != "" {
		banner.StatusLine("debug", line)
	}
}

func (e *EnhancedExecutor) displayWaybackOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.HasPrefix(line, "http") {
		banner.StatusLine("info", fmt.Sprintf("📜 WAYBACK: %s", line))
	} else if e.verbose && line != "" {
		banner.StatusLine("debug", line)
	}
}

func (e *EnhancedExecutor) displayCloudEnumOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "OPEN S3 BUCKET"):
		banner.StatusLine("error", fmt.Sprintf("☁️  %s", line))
	case strings.Contains(line, "Found"):
		banner.StatusLine("success", fmt.Sprintf("☁️  %s", line))
	case strings.Contains(line, "Checking"):
		if e.verbose {
			banner.StatusLine("info", fmt.Sprintf("🔍 %s", line))
		}
	default:
		if e.verbose && line != "" {
			banner.StatusLine("debug", line)
		}
	}
}

func (e *EnhancedExecutor) displayGenericOutput(line, streamType string) {
	line = strings.TrimSpace(line)
	
	if line == "" {
		return
	}
	
	if streamType == "stderr" {
		banner.StatusLine("error", fmt.Sprintf("STDERR: %s", line))
	} else if e.verbose {
		banner.StatusLine("info", line)
	}
}

func (e *EnhancedExecutor) displayExecutionFooter(exec *ToolExecution) {
	fmt.Printf("\n%s\n", color.New(color.FgCyan).Sprint(strings.Repeat("─", 80)))
	
	duration := time.Since(exec.StartTime)
	if exec.EndTime != nil {
		duration = exec.EndTime.Sub(exec.StartTime)
	}
	
	switch exec.Status {
	case "completed":
		banner.StatusLine("success", fmt.Sprintf("%s completed successfully", exec.Tool))
		banner.StatusLine("info", fmt.Sprintf("Duration: %v", duration))
		banner.StatusLine("info", fmt.Sprintf("Exit code: %d", exec.ExitCode))
		banner.StatusLine("info", fmt.Sprintf("Output lines: %d", len(exec.Output)))
		if len(exec.Errors) > 0 {
			banner.StatusLine("warning", fmt.Sprintf("Error lines: %d", len(exec.Errors)))
		}
	case "failed":
		banner.StatusLine("error", fmt.Sprintf("%s failed", exec.Tool))
		banner.StatusLine("error", fmt.Sprintf("Exit code: %d", exec.ExitCode))
		banner.StatusLine("info", fmt.Sprintf("Duration: %v", duration))
	case "killed":
		banner.StatusLine("warning", fmt.Sprintf("%s was killed", exec.Tool))
		banner.StatusLine("info", fmt.Sprintf("Duration: %v", duration))
	}
	
	fmt.Println()
}

// Helper functions
func extractDomainFromLine(line string) string {
	// Extract domain from various line formats
	line = strings.TrimSpace(line)
	
	// Remove ANSI color codes
	line = removeANSICodes(line)
	
	// Look for URLs
	if strings.Contains(line, "http") {
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "http") {
				return part
			}
		}
	}
	
	// Look for domains in brackets
	if strings.Contains(line, "[") && strings.Contains(line, "]") {
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if end > start {
			return line[start+1 : end]
		}
	}
	
	return line
}

func extractServiceFromLine(line string) string {
	// Common service patterns
	services := []string{"GitHub Pages", "Heroku", "Bitbucket", "AWS", "Azure", "DigitalOcean"}
	
	for _, service := range services {
		if strings.Contains(strings.ToLower(line), strings.ToLower(service)) {
			return service
		}
	}
	
	// Try to extract from brackets at end
	parts := strings.Fields(line)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			return strings.Trim(part, "[]")
		}
	}
	
	return "Unknown Service"
}

func removeANSICodes(text string) string {
	// Simple ANSI code removal (for more complex cases, use a library)
	result := text
	ansiCodes := []string{"\033[0m", "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[37m"}
	
	for _, code := range ansiCodes {
		result = strings.ReplaceAll(result, code, "")
	}
	
	return result
}