package helpstyle

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type cfg struct {
	ColorEnabled bool
	ManMode      bool
}

var (
	flagNoColor bool
	flagMan     bool
)

func Install(root *cobra.Command) {
	// Add persistent flags if they don't already exist
	if root.PersistentFlags().Lookup("no-color") == nil {
		root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable ANSI colors in output")
	}
	if root.PersistentFlags().Lookup("man") == nil {
		root.PersistentFlags().BoolVar(&flagMan, "man", false, "render manpage-style help (no color)")
	}

	// Attach a custom help func to root and all descendants
	apply := func(cmd *cobra.Command) {
		cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
			renderHelp(c, detectCfg(c))
		})
	}
	apply(root)
	for _, c := range root.Commands() {
		applyRec(c, apply)
	}
}

func applyRec(cmd *cobra.Command, f func(*cobra.Command)) {
	f(cmd)
	for _, c := range cmd.Commands() {
		applyRec(c, f)
	}
}

func detectCfg(cmd *cobra.Command) cfg {
	// Resolve flags on this command chain
	noColor := flagNoColor
	man := flagMan
	// Respect NO_COLOR env var
	if v := os.Getenv("NO_COLOR"); v != "" {
		noColor = true
	}
	// Cobra / CI non-TTY? Let user force colors off with --no-color/NO_COLOR.
	color.NoColor = noColor || man

	return cfg{
		ColorEnabled: !color.NoColor,
		ManMode:      man,
	}
}

func banner() string {
	return `   ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║  ███╗██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║   ██║██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚██████╔╝╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
           ► Intelligence-Driven Penetration Testing Framework ◄
                      GORECON v2.1.0 | Build: 2025-08-25 | @GoRecon

`
}

// Banner returns the GORECON ASCII banner for external use
func Banner() string {
	return banner()
}

func cBlue() func(a ...interface{}) string   { return color.New(color.FgCyan).SprintFunc() }
func cGreen() func(a ...interface{}) string  { return color.New(color.FgGreen).SprintFunc() }
func cYellow() func(a ...interface{}) string { return color.New(color.FgYellow).SprintFunc() }
func cRed() func(a ...interface{}) string    { return color.New(color.FgRed).SprintFunc() }
func cBold() func(a ...interface{}) string   { return color.New(color.Bold).SprintFunc() }

func renderHelp(cmd *cobra.Command, cfg cfg) {
	out := cmd.OutOrStdout()
	fmt.Fprint(out, banner())

	if isRoot(cmd) {
		// Root command gets the fancy stage-like styling
		renderRootHelpStyled(out, cmd)
	} else if cmd.Name() == "step" {
		renderStepCommands(out, cmd)
	} else {
		renderStandardCommands(out, cmd)
	}
}

func renderRootHelpStyled(out io.Writer, cmd *cobra.Command) {
	// Color functions
	bold := color.New(color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	// Decorative separator like in stage help
	separator := strings.Repeat("═", 80)
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	fmt.Fprintf(out, "                        %s                       \n", bold(cyan("[GORECON] TACTICAL RECONNAISSANCE FRAMEWORK")))
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	// Main sections with [GORECON] prefixes like stage help
	fmt.Fprintf(out, "%s %s Name: %s\n", bold("[GORECON]"), cyan("[*]"), white("Intelligence-driven penetration testing orchestrator"))
	fmt.Fprintf(out, "%s %s Description: %s\n", bold("[GORECON]"), cyan("[*]"), white(firstLine(nonEmpty(cmd.Long, "GoRecon coordinates 30+ external security tools while providing advanced correlation, anomaly detection, and attack path analysis."))))
	fmt.Fprintf(out, "%s %s Category: %s\n", bold("[GORECON]"), cyan("[*]"), white("reconnaissance"))
	fmt.Fprintf(out, "%s %s Type: %s\n\n", bold("[GORECON]"), cyan("[*]"), yellow("ENTERPRISE FRAMEWORK - Comprehensive reconnaissance platform"))

	// Technical details with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Plugins: %s\n", bold("[GORECON]"), cyan("[*]"), cyan("[30+ integrated security tools]"))
	fmt.Fprintf(out, "%s %s Timeout: %s\n", bold("[GORECON]"), cyan("[*]"), white("unlimited"))

	// Commands section with [GORECON] prefixes - formatted like flags
	fmt.Fprintf(out, "\n%s %s Available Commands:\n", bold("[GORECON]"), cyan("[*]"))
	for _, c := range visible(cmd.Commands()) {
		desc := firstLine(c.Short)
		if desc == "" {
			desc = "No description available"
		}
		// Format like flags: "command              description"
		formatted := fmt.Sprintf("%-20s %s", c.Name(), desc)
		fmt.Fprintf(out, "    %s\n", white(formatted))
	}
	fmt.Fprintln(out)

	// Usage examples with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Usage Examples:\n", bold("[GORECON]"), cyan("[*]"))
	if ex := strings.TrimSpace(cmd.Example); ex != "" {
		examples := strings.Split(strings.TrimSpace(ex), "\n")
		for _, example := range examples {
			if strings.TrimSpace(example) != "" && strings.HasPrefix(strings.TrimSpace(example), "gorecon") {
				fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white(strings.TrimSpace(example)))
			}
		}
	} else {
		fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon scan --target https://example.com"))
		fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon do-all --target example.com --confirm"))
		fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon step takeover --target example.com"))
	}
	fmt.Fprintln(out)

	// Tips & Notes with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Tips & Notes:\n", bold("[GORECON]"), cyan("[*]"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Use 'scan' for basic reconnaissance operations"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Use 'do-all' for comprehensive penetration testing"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Use 'step' to run individual reconnaissance stages"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Results are automatically correlated and analyzed"))
	fmt.Fprintf(out, "    %s %s\n\n", cyan("[*]"), white("All operations support custom profiles and configurations"))

	// Usage section with decorative separator like stage help
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	fmt.Fprintf(out, "                               %s                                \n", bold(cyan("[GORECON] USAGE")))
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	fmt.Fprintf(out, "%s %s Basic usage: %s\n", bold("[GORECON]"), cyan("[*]"), white("gorecon <command> [flags]"))
	fmt.Fprintf(out, "%s %s Available flags:\n", bold("[GORECON]"), cyan("[*]"))
	
	// Flags formatted like step takeover
	localFlags := strings.TrimSpace(cmd.LocalFlags().FlagUsages())
	inheritedFlags := strings.TrimSpace(cmd.InheritedFlags().FlagUsages())
	
	if localFlags != "" {
		for _, line := range strings.Split(localFlags, "\n") {
			if strings.TrimSpace(line) != "" {
				// Format like takeover: "    -t, --target string      Target URL or domain to scan"
				formatted := formatFlag(strings.TrimSpace(line))
				fmt.Fprintf(out, "    %s\n", white(formatted))
			}
		}
	}
	if inheritedFlags != "" {
		for _, line := range strings.Split(inheritedFlags, "\n") {
			if strings.TrimSpace(line) != "" {
				formatted := formatFlag(strings.TrimSpace(line))
				fmt.Fprintf(out, "    %s\n", white(formatted))
			}
		}
	}
	fmt.Fprintln(out)

	fmt.Fprintf(out, "Use %s for more information about a command.\n", cyan("'gorecon [command] --help'"))
}

func titleFor(cmd *cobra.Command) string {
	if isRoot(cmd) {
		return "Tactical Reconnaissance Framework v2.1.0"
	}
	if cmd.Name() == "step" {
		return "Pipeline Stages"
	}
	return strings.Title(cmd.Name()) + " Command"
}

func isRoot(cmd *cobra.Command) bool {
	return !cmd.HasParent()
}

func visible(cmds []*cobra.Command) []*cobra.Command {
	out := make([]*cobra.Command, 0, len(cmds))
	for _, c := range cmds {
		if !c.IsAvailableCommand() || c.Hidden {
			continue
		}
		out = append(out, c)
	}
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func nonEmpty(strs ...string) string {
	for _, s := range strs {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func normalizeBullets(s string) string {
	s = strings.ReplaceAll(s, "•", "-")
	s = strings.ReplaceAll(s, "·", "-")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		ln = strings.TrimRight(ln, " ")
		lines[i] = ln
	}
	return strings.Join(lines, "\n")
}

func stripBullets(s string) string {
	s = strings.TrimLeft(s, "-•· \t")
	return s
}

func indent(s, pad string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

func normalizeDescription(s string) string {
	// Remove emojis and normalize bullet points
	s = strings.ReplaceAll(s, "•", "")
	s = strings.ReplaceAll(s, "🔍", "")
	s = strings.ReplaceAll(s, "📋", "")
	s = strings.ReplaceAll(s, "🌐", "")
	s = strings.ReplaceAll(s, "⚡", "")
	s = strings.ReplaceAll(s, "🕷️", "")
	s = strings.ReplaceAll(s, "🔒", "")
	s = strings.ReplaceAll(s, "🚨", "")
	s = strings.ReplaceAll(s, "📊", "")
	s = strings.ReplaceAll(s, "⚙️", "")
	
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Features:") {
			continue // Skip features section as it's handled separately
		}
		if line != "" && !strings.Contains(line, "RECONNAISSANCE PIPELINE OVERVIEW") {
			result = append(result, line)
		}
	}
	
	desc := strings.Join(result, " ")
	if len(desc) > 200 {
		// Truncate at word boundary
		words := strings.Fields(desc)
		if len(words) > 25 {
			desc = strings.Join(words[:25], " ") + "..."
		}
	}
	
	return strings.TrimSpace(desc)
}

func renderRootCommands(out io.Writer, cmd *cobra.Command) {
	bold := color.New(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	
	fmt.Fprintln(out, bold("COMMANDS"))
	
	// Show all commands with colored markers
	for _, c := range visible(cmd.Commands()) {
		desc := firstLine(c.Short)
		if desc == "" {
			desc = "No description available"
		}
		fmt.Fprintf(out, "    %s %-12s %s\n", green("[*]"), c.Name(), desc)
	}
	fmt.Fprintln(out)
}

func renderRootCommandsStyled(out io.Writer, cmd *cobra.Command, green, yellow, red, cyan, bold func(a ...interface{}) string) {
	fmt.Fprintln(out, bold("COMMANDS"))
	
	// Categorize commands with colored markers
	commandCategories := []struct {
		name     string
		commands []string
		marker   func(a ...interface{}) string
		desc     string
	}{
		{
			name:     "Core Operations",
			commands: []string{"scan", "do-all", "step"},
			marker:   green,
			desc:     "Primary reconnaissance and scanning operations",
		},
		{
			name:     "Management & Analysis", 
			commands: []string{"list", "validate", "report", "info", "plugins"},
			marker:   cyan,
			desc:     "Configuration management and result analysis",
		},
		{
			name:     "Advanced Features",
			commands: []string{"serve", "api", "stream", "distributed", "intelligence"},
			marker:   yellow,
			desc:     "Web interface, APIs, and distributed operations",
		},
		{
			name:     "Utilities",
			commands: []string{"cache", "completion", "version"},
			marker:   cyan,
			desc:     "System utilities and shell integration",
		},
	}
	
	cmdMap := make(map[string]*cobra.Command)
	for _, c := range visible(cmd.Commands()) {
		cmdMap[c.Name()] = c
	}
	
	// Show categorized commands
	for _, category := range commandCategories {
		hasCommands := false
		for _, cmdName := range category.commands {
			if _, exists := cmdMap[cmdName]; exists {
				hasCommands = true
				break
			}
		}
		if !hasCommands {
			continue
		}
		
		fmt.Fprintf(out, "    %s %s\n", category.marker("[+]"), category.name)
		for _, cmdName := range category.commands {
			if c, exists := cmdMap[cmdName]; exists {
				desc := firstLine(c.Short)
				if desc == "" {
					desc = "No description available"
				}
				fmt.Fprintf(out, "        %-12s %s\n", cmdName, desc)
				delete(cmdMap, cmdName) // Remove from map to avoid duplicates
			}
		}
		fmt.Fprintln(out)
	}
	
	// Add any remaining commands not categorized
	if len(cmdMap) > 0 {
		fmt.Fprintf(out, "    %s Other Commands\n", cyan("[*]"))
		for _, c := range visible(cmd.Commands()) {
			if _, exists := cmdMap[c.Name()]; exists {
				desc := firstLine(c.Short)
				if desc == "" {
					desc = "No description available"
				}
				fmt.Fprintf(out, "        %-12s %s\n", c.Name(), desc)
			}
		}
		fmt.Fprintln(out)
	}
}

func renderStepCommands(out io.Writer, cmd *cobra.Command) {
	// Color functions
	bold := color.New(color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	// Decorative separator like in stage help
	separator := strings.Repeat("═", 80)
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	fmt.Fprintf(out, "                        %s                        \n", bold(cyan("[GORECON] AVAILABLE RECONNAISSANCE STAGES")))
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	// Main sections with [GORECON] prefixes like stage help
	fmt.Fprintf(out, "%s %s Name: %s\n", bold("[GORECON]"), cyan("[*]"), white("Pipeline Stages"))
	fmt.Fprintf(out, "%s %s Description: %s\n", bold("[GORECON]"), cyan("[*]"), white("Execute specific reconnaissance or security testing stages independently"))
	fmt.Fprintf(out, "%s %s Category: %s\n", bold("[GORECON]"), cyan("[*]"), white("pipeline"))
	fmt.Fprintf(out, "%s %s Type: %s\n\n", bold("[GORECON]"), cyan("[*]"), yellow("STAGE MANAGEMENT - Individual pipeline execution"))

	// Define stage categories with their stages and tools
	categories := []struct {
		name        string
		description string
		stages      []stageInfo
		requiresConfirm bool
	}{
		{
			name:        "RECONNAISSANCE (Passive)",
			description: "Passive information gathering - no alerts triggered",
			stages: []stageInfo{
				{"takeover", "Detects and verifies subdomain takeover vulnerabilities using subzy with JSON output", "[subzy]"},
				{"cloud", "Discovers cloud assets and services using cloud enumeration tools", "[cloud_enum, sni_scanner]"},
				{"wayback", "Collects historical URLs from web archives using gau and waybackurls", "[gau, waybackurls]"},
			},
		},
		{
			name:        "SCANNING (Active - Requires --confirm)",
			description: "Active scanning operations",
			requiresConfirm: true,
			stages: []stageInfo{
				{"portscan", "Scans for open ports and services using nmap, masscan, and other scanners", "[smap, nmap, naabu]"},
				{"httpprobe", "Probes HTTP services and detects technologies using httpx", "[httpx, meg]"},
				{"js", "Analyzes JavaScript files for endpoints, secrets, and vulnerabilities", "[jsluice, linkfinder]"},
				{"crawl", "Crawls web applications to discover additional endpoints and content", "[hakrawler, gospider]"},
			},
		},
		{
			name:        "DISCOVERY (Active)",
			description: "Content and parameter discovery",
			requiresConfirm: true,
			stages: []stageInfo{
				{"blc", "Checks for broken links and potential issues in web applications", "[blc]"},
				{"dirfuzz", "Fuzzes directories and files to discover hidden content", "[ffuf, dirb, gobuster]"},
				{"params", "Discovers URL parameters and additional endpoints", "[paramspider]"},
			},
		},
		{
			name:        "VULNERABILITY ASSESSMENT (Active - Requires --confirm)",
			description: "Security testing and vulnerability detection",
			requiresConfirm: true,
			stages: []stageInfo{
				{"vuln", "Scans for known vulnerabilities using nuclei and other tools", "[nuclei, xray]"},
			},
		},
	}

	fmt.Fprintf(out, "%s %s Available Stages:\n", bold("[GORECON]"), cyan("[*]"))
	for _, category := range categories {
		fmt.Fprintf(out, "\n%s %s %s:\n", bold("[GORECON]"), cyan("[*]"), yellow(category.name))
		for _, stage := range category.stages {
			// Format like flags: "stage                description [tools]"
			formatted := fmt.Sprintf("%-20s %s %s", stage.name, stage.description, stage.tools)
			fmt.Fprintf(out, "    %s\n", white(formatted))
		}
	}
	fmt.Fprintln(out)

	// Usage examples with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Usage Examples:\n", bold("[GORECON]"), cyan("[*]"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon step takeover --target https://example.com"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon step portscan --target example.com --confirm"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("gorecon step js --target example.com --timeout 30m"))
	fmt.Fprintln(out)

	// Tips & Notes with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Tips & Notes:\n", bold("[GORECON]"), cyan("[*]"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Passive stages require no confirmation and won't trigger alerts"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Active stages may require --confirm flag for safety"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Use individual stages for focused reconnaissance"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("Results are saved in ./work/<target>/<stage>/ directory"))
	fmt.Fprintln(out)

	// Usage section with decorative separator like stage help
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	fmt.Fprintf(out, "                               %s                                \n", bold(cyan("[GORECON] USAGE")))
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	fmt.Fprintf(out, "%s %s Basic usage: %s\n", bold("[GORECON]"), cyan("[*]"), white("gorecon step <stage> --target <target> [flags]"))
	fmt.Fprintf(out, "%s %s Available flags:\n", bold("[GORECON]"), cyan("[*]"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--target <url>     Target URL or domain to scan"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--verbose, -v      Enable verbose output"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--quiet, -q        Quiet mode (minimal output)"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--timeout <dur>    Override default timeout"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--output <file>    Save results to file"))
	fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white("--confirm          Enable active/intrusive scans"))
}

func renderStandardCommands(out io.Writer, cmd *cobra.Command) {
	// Color functions
	bold := color.New(color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	// Apply stage-like styling to individual commands
	separator := strings.Repeat("═", 80)
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	cmdTitle := fmt.Sprintf("[GORECON] %s", strings.ToUpper(cmd.Name()))
	padding := (80 - len(cmdTitle)) / 2
	if padding > 0 {
		fmt.Fprintf(out, "%s%s%s\n", strings.Repeat(" ", padding), bold(cyan(cmdTitle)), strings.Repeat(" ", 80-len(cmdTitle)-padding))
	} else {
		fmt.Fprintf(out, "%s\n", bold(cyan(cmdTitle)))
	}
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	// Main sections with [GORECON] prefixes
	fmt.Fprintf(out, "%s %s Name: %s\n", bold("[GORECON]"), cyan("[*]"), white(cmd.Name()))
	desc := firstLine(nonEmpty(cmd.Short, cmd.Long, "No description available"))
	fmt.Fprintf(out, "%s %s Description: %s\n", bold("[GORECON]"), cyan("[*]"), white(desc))
	fmt.Fprintf(out, "%s %s Category: %s\n", bold("[GORECON]"), cyan("[*]"), white(cmd.Name()))
	fmt.Fprintf(out, "%s %s Type: %s\n\n", bold("[GORECON]"), cyan("[*]"), yellow("COMMAND - GoRecon subcommand"))

	// Show subcommands if any
	if len(cmd.Commands()) > 0 {
		fmt.Fprintf(out, "%s %s Available Subcommands:\n", bold("[GORECON]"), cyan("[*]"))
		subs := visible(cmd.Commands())
		sort.Slice(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		for _, c := range subs {
			subDesc := firstLine(c.Short)
			if subDesc == "" {
				subDesc = "No description available"
			}
			// Format like flags: "subcommand           description"
			formatted := fmt.Sprintf("%-20s %s", c.Name(), subDesc)
			fmt.Fprintf(out, "    %s\n", white(formatted))
		}
		fmt.Fprintln(out)
	}

	// Usage examples if available
	if ex := strings.TrimSpace(cmd.Example); ex != "" {
		fmt.Fprintf(out, "%s %s Usage Examples:\n", bold("[GORECON]"), cyan("[*]"))
		examples := strings.Split(strings.TrimSpace(ex), "\n")
		for _, example := range examples {
			if strings.TrimSpace(example) != "" {
				fmt.Fprintf(out, "    %s %s\n", cyan("[*]"), white(strings.TrimSpace(example)))
			}
		}
		fmt.Fprintln(out)
	}

	// Usage section with decorative separator
	fmt.Fprintf(out, "\n%s\n", cyan(separator))
	fmt.Fprintf(out, "                               %s                                \n", bold(cyan("[GORECON] USAGE")))
	fmt.Fprintf(out, "%s\n\n", cyan(separator))

	fmt.Fprintf(out, "%s %s Basic usage: %s\n", bold("[GORECON]"), cyan("[*]"), white(fmt.Sprintf("gorecon %s [flags]", cmd.Name())))
	if len(cmd.Commands()) > 0 {
		fmt.Fprintf(out, "%s %s With subcommand: %s\n", bold("[GORECON]"), cyan("[*]"), white(fmt.Sprintf("gorecon %s <subcommand> [flags]", cmd.Name())))
	}

	// Show flags in styled format
	localFlags := strings.TrimSpace(cmd.LocalFlags().FlagUsages())
	inheritedFlags := strings.TrimSpace(cmd.InheritedFlags().FlagUsages())
	
	if localFlags != "" || inheritedFlags != "" {
		fmt.Fprintf(out, "%s %s Available flags:\n", bold("[GORECON]"), cyan("[*]"))
		if localFlags != "" {
			for _, line := range strings.Split(localFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					formatted := formatFlag(strings.TrimSpace(line))
					fmt.Fprintf(out, "    %s\n", white(formatted))
				}
			}
		}
		if inheritedFlags != "" {
			for _, line := range strings.Split(inheritedFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					formatted := formatFlag(strings.TrimSpace(line))
					fmt.Fprintf(out, "    %s\n", white(formatted))
				}
			}
		}
		fmt.Fprintln(out)
	}
}

func renderFlags(out io.Writer, cmd *cobra.Command) {
	bold := color.New(color.Bold).SprintFunc()
	fmt.Fprintln(out, bold("FLAGS"))
	
	// Get local and inherited flags
	localFlags := strings.TrimSpace(cmd.LocalFlags().FlagUsages())
	inheritedFlags := strings.TrimSpace(cmd.InheritedFlags().FlagUsages())
	
	if localFlags == "" && inheritedFlags == "" {
		fmt.Fprintln(out, "    (none)")
	} else {
		if localFlags != "" {
			for _, line := range strings.Split(localFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(out, "    %s\n", strings.TrimSpace(line))
				}
			}
		}
		if inheritedFlags != "" {
			for _, line := range strings.Split(inheritedFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(out, "    %s\n", strings.TrimSpace(line))
				}
			}
		}
	}
	fmt.Fprintln(out)
}

func renderFlagsStyled(out io.Writer, cmd *cobra.Command, bold, cyan func(a ...interface{}) string) {
	fmt.Fprintln(out, bold("FLAGS"))
	
	// Get local and inherited flags
	localFlags := strings.TrimSpace(cmd.LocalFlags().FlagUsages())
	inheritedFlags := strings.TrimSpace(cmd.InheritedFlags().FlagUsages())
	
	if localFlags == "" && inheritedFlags == "" {
		fmt.Fprintln(out, "    (none)")
	} else {
		// Process and display flags with colored markers
		if localFlags != "" {
			for _, line := range strings.Split(localFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(out, "    %s\n", strings.TrimSpace(line))
				}
			}
		}
		if inheritedFlags != "" {
			for _, line := range strings.Split(inheritedFlags, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(out, "    %s\n", strings.TrimSpace(line))
				}
			}
		}
	}
	fmt.Fprintln(out)
}

// formatFlag formats a flag usage line to match the takeover step style
func formatFlag(flagLine string) string {
	// Parse cobra flag format: "  -f, --flag string   description (default value)"
	// Convert to takeover format: "-f, --flag string      description"
	
	parts := strings.Fields(flagLine)
	if len(parts) < 2 {
		return flagLine
	}
	
	// Find the flag part and description part
	flagPart := ""
	descStart := -1
	
	for i, part := range parts {
		if strings.HasPrefix(part, "-") {
			if flagPart == "" {
				flagPart = part
			} else {
				flagPart += " " + part
			}
		} else if flagPart != "" && descStart == -1 {
			// This might be the type (string, int, etc.) or start of description
			if part == "string" || part == "int" || part == "duration" || part == "bool" {
				flagPart += " " + part
			} else {
				descStart = i
				break
			}
		}
	}
	
	if descStart == -1 {
		return flagLine
	}
	
	// Get description (everything after flag part)
	description := strings.Join(parts[descStart:], " ")
	
	// Format with proper spacing (25 chars for flag part)
	return fmt.Sprintf("%-25s %s", flagPart, description)
}

type stageInfo struct {
	name        string
	description string
	tools       string
}