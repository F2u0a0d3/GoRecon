package banner

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Colors
var (
	colorRed     = color.New(color.FgRed).SprintFunc()
	colorGreen   = color.New(color.FgGreen).SprintFunc()
	colorYellow  = color.New(color.FgYellow).SprintFunc()
	colorBlue    = color.New(color.FgBlue).SprintFunc()
	colorMagenta = color.New(color.FgMagenta).SprintFunc()
	colorCyan    = color.New(color.FgCyan).SprintFunc()
	colorWhite   = color.New(color.FgWhite).SprintFunc()
	colorBold    = color.New(color.Bold).SprintFunc()
	colorDim     = color.New(color.Faint).SprintFunc()
)

// Status indicators
const (
	StatusInfo     = "[*]"
	StatusSuccess  = "[+]"
	StatusWarning  = "[!]"
	StatusError    = "[-]"
	StatusDebug    = "[?]"
)

// PrintBanner displays the GORECON ASCII banner with hacker-style formatting
func PrintBanner() {
	banner := `
   ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║  ███╗██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║   ██║██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚██████╔╝╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
`
	
	// Print banner in cyan
	fmt.Print(colorCyan(banner))
	
	// Print tagline
	fmt.Printf("           %s Intelligence-Driven Penetration Testing Framework %s\n", 
		colorDim("►"), colorDim("◄"))
	
	// Print version info
	fmt.Printf("                      %s v2.1.0 | Build: %s %s\n", 
		colorBold("GORECON"), 
		time.Now().Format("2006-01-02"), 
		colorDim("| @GoRecon"))
	
	fmt.Println()
}

// StatusLine prints a status line with colored indicator
func StatusLine(status, message string) {
	var indicator, text string
	
	switch status {
	case "info":
		indicator = colorBlue(StatusInfo)
		text = colorWhite(message)
	case "success":
		indicator = colorGreen(StatusSuccess)
		text = colorGreen(message)
	case "warning":
		indicator = colorYellow(StatusWarning)
		text = colorYellow(message)
	case "error":
		indicator = colorRed(StatusError)
		text = colorRed(message)
	case "debug":
		indicator = colorMagenta(StatusDebug)
		text = colorDim(message)
	default:
		indicator = colorBlue(StatusInfo)
		text = colorWhite(message)
	}
	
	fmt.Printf("%s %s %s\n", colorBold("[GORECON]"), indicator, text)
}

// ProgressBar prints a hacker-style progress bar
func ProgressBar(current, total int, message string) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * percentage / 100)
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	
	fmt.Printf("\r%s %s [%s] %3.0f%% (%d/%d) %s",
		colorBold("[GORECON]"),
		colorBlue(StatusInfo),
		colorCyan(bar),
		percentage,
		current,
		total,
		colorWhite(message))
	
	if current == total {
		fmt.Println() // New line when complete
	}
}

// Section prints a section header with decorative borders
func Section(title string) {
	width := 80
	titleLen := len(title) + 12 // "[GORECON] " + title + " "
	padding := (width - titleLen) / 2
	if padding < 0 {
		padding = 0
	}
	
	border := strings.Repeat("═", width)
	spacer := strings.Repeat(" ", padding)
	
	fmt.Printf("\n%s\n", colorCyan(border))
	fmt.Printf("%s%s %s %s\n", 
		spacer, 
		colorBold("[GORECON]"), 
		colorBold(colorCyan(title)),
		spacer)
	fmt.Printf("%s\n\n", colorCyan(border))
}

// Tree prints a tree-style hierarchical display
func Tree(items []string, level int) {
	for i, item := range items {
		prefix := strings.Repeat("  ", level)
		
		if i == len(items)-1 {
			// Last item
			fmt.Printf("%s%s %s\n", 
				prefix, 
				colorDim("└──"), 
				colorWhite(item))
		} else {
			// Other items
			fmt.Printf("%s%s %s\n", 
				prefix, 
				colorDim("├──"), 
				colorWhite(item))
		}
	}
}

// Vulnerability prints a vulnerability finding with exploit command
func Vulnerability(severity, title, target, exploitCmd string) {
	var indicator string
	var severityColor func(...interface{}) string
	
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		indicator = colorRed(StatusError)
		severityColor = colorRed
	case "HIGH":
		indicator = colorYellow(StatusWarning)
		severityColor = colorYellow
	case "MEDIUM":
		indicator = colorBlue(StatusInfo)
		severityColor = colorBlue
	case "LOW":
		indicator = colorGreen(StatusInfo)
		severityColor = colorGreen
	default:
		indicator = colorBlue(StatusInfo)
		severityColor = colorWhite
	}
	
	fmt.Printf("%s %s %s: %s\n", 
		colorBold("[GORECON]"), 
		indicator, 
		severityColor(severity), 
		colorBold(title))
	
	fmt.Printf("    %s Target: %s\n", 
		colorDim("├──"), 
		colorWhite(target))
	
	if exploitCmd != "" {
		fmt.Printf("    %s Exploit: %s\n", 
			colorDim("└──"), 
			colorCyan(exploitCmd))
	}
	fmt.Println()
}

// Summary prints a final summary with statistics
func Summary(duration time.Duration, findings map[string]int) {
	Section("SCAN COMPLETE")
	
	fmt.Printf("%s %s Total scan time: %s\n", 
		colorBold("[GORECON]"), 
		colorGreen(StatusSuccess), 
		colorBold(duration.String()))
	
	total := 0
	for _, count := range findings {
		total += count
	}
	
	fmt.Printf("%s %s Total findings: %s\n", 
		colorBold("[GORECON]"), 
		colorBlue(StatusInfo), 
		colorBold(fmt.Sprintf("%d", total)))
	
	if critical, ok := findings["critical"]; ok && critical > 0 {
		fmt.Printf("    %s Critical: %s\n", 
			colorDim("├──"), 
			colorRed(fmt.Sprintf("%d", critical)))
	}
	
	if high, ok := findings["high"]; ok && high > 0 {
		fmt.Printf("    %s High: %s\n", 
			colorDim("├──"), 
			colorYellow(fmt.Sprintf("%d", high)))
	}
	
	if medium, ok := findings["medium"]; ok && medium > 0 {
		fmt.Printf("    %s Medium: %s\n", 
			colorDim("├──"), 
			colorBlue(fmt.Sprintf("%d", medium)))
	}
	
	if low, ok := findings["low"]; ok && low > 0 {
		fmt.Printf("    %s Low: %s\n", 
			colorDim("└──"), 
			colorGreen(fmt.Sprintf("%d", low)))
	}
	
	fmt.Println()
	
	if total > 0 {
		fmt.Printf("%s %s Review findings and apply security patches immediately\n", 
			colorBold("[GORECON]"), 
			colorYellow(StatusWarning))
	} else {
		fmt.Printf("%s %s No vulnerabilities detected in scan scope\n", 
			colorBold("[GORECON]"), 
			colorGreen(StatusSuccess))
	}
	
	fmt.Println()
}