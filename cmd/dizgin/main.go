// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/log"
)

// phaseTime logs elapsed since ref when DIZGIN_PHASE_TIMING is active.
func phaseTime(name string, ref time.Time) {
	if !log.IsTimingEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, brand.Name+": phase %-22s elapsed %.2fs (since-start)\n", name, time.Since(ref).Seconds())
}

func goVersion() string { return runtime.Version() }

// ensureDizginHome proactively creates the ~/.dizgin directory tree
// (profiles, permissions, audit) on startup so the zero-config flow has
// nothing to set up by hand and the dirs are visible for the user to
// drop their own profiles into. Each subdir is also created lazily on
// first write, so this is purely a UX/observability nicety — failures
// are non-fatal and silent (the lazy path will surface a real error if
// it matters).
func ensureDizginHome() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	base := filepath.Join(home, brand.DotDir)
	for _, sub := range brand.StateSubdirs {
		_ = os.MkdirAll(filepath.Join(base, sub), 0o755)
	}
}

// Exit codes defined by the dizgin spec.
const (
	exitToolError          = 1
	exitToolNotFound       = 126
	exitBackendUnavailable = 127
)

var (
	// workdir is the -w/--workdir flag value.
	workdir string
	// configFile is the -c/--config flag value.
	configFile string
	// profilesDir is the --profiles flag value.
	profilesDir string
	// noTTY disables PTY allocation when set (--no-pty flag).
	noTTY bool
	// learnMode enables Phase 5 permission-learning: the restricted
	// backend keeps DENY ACEs in place but dizgin captures stderr access-
	// denial lines and prints a summary at session exit (--learn flag).
	learnMode bool
)

var rootCmd = &cobra.Command{
	Use:                "dizgin [-w <workdir>] [-c <config>] [--no-pty] [KEY=val...] <tool> [tool-args...]",
	Short:              "dizgin — platform-native sandbox wrapper for AI coding tools",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	RunE:               run,
}

func init() {
	rootCmd.Version = version
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			runGlobalCleanup()
			// Scrub the process env before re-panicking so a goroutine
			// dump that includes os.Environ() (Go's default for some
			// crash tooling) does not leak API keys to stderr / crash
			// reports. Best-effort: setenv failures are ignored so the
			// recover path always reaches the panic re-throw.
			for _, e := range log.ScrubEnv(os.Environ()) {
				if i := strings.IndexByte(e, '='); i > 0 {
					_ = os.Setenv(e[:i], e[i+1:])
				}
			}
			// Log the stack so the diagnostic survives the re-panic even
			// when crash tooling strips the goroutine dump.
			log.Error("panic: %v\n%s", r, debug.Stack())
			panic(r)
		}
	}()

	t0 := time.Now()
	// Verbose framework: dump the system inventory once before any
	// other work so "stale install" / "missing dependency" failures
	// surface BEFORE the request reaches the broker. Production
	// (DIZGIN_DEBUG unset) short-circuits inside PreflightWindows.
	log.PreflightWindows()
	phaseTime("preflight", t0)

	ensureDizginHome()
	config.LoadProfiles(profilesDir)
	phaseTime("profiles-load", t0)

	if !isInfoCommand(os.Args[1:]) {
		ensureDaemonRunning()
		phaseTime("ensure-daemon", t0)
		// Wire the stamp-storm progress renderer once daemon is up.
		// Info commands (--help, version, doctor, completion) don't
		// trigger the stamp pool, so the install is wasted work for
		// them.
		installStampProgress()
		phaseTime("install-progress", t0)
	}

	startVersionCheck()
	phaseTime("version-check", t0)

	if err := run(rootCmd, os.Args[1:]); err != nil {
		phaseTime("run-end-err", t0)
		fmt.Fprintf(os.Stderr, brand.Name+": %s\n", decorateError(err))
		os.Exit(exitToolError)
	}
	phaseTime("run-end-ok", t0)
}

func run(cmd *cobra.Command, args []string) error {
	remaining := parseOwnFlags(args)
	if remaining == nil {
		return nil // --help or --version handled
	}
	toolArgs, envOverrides := parseArgs(remaining)
	if len(toolArgs) == 0 {
		printUsage()
		return fmt.Errorf("no tool specified")
	}

	if handled, err := dispatchBuiltin(cmd, toolArgs); handled {
		return err
	}

	toolBin, toolExtraArgs := prepareToolArgs(toolArgs)

	tPhase := time.Now()
	// Phase 1: Resolve paths and load config.
	wd, toolPath, cfg, err := resolveSession(toolBin)
	if err != nil {
		return err
	}
	phaseTime("resolve-session", tPhase)

	setupAuditAndConfig(cfg, toolBin, tPhase)

	// Phase 3: Create context + discover credentials.
	ctx, cancel := createContext(cfg)
	defer cancel()
	toolDef := cfg.LookupTool(toolBin)
	finalCreds, sandboxCreds := prepareCredentials(cfg, toolDef, envOverrides)
	phaseTime("creds-prepare", tPhase)

	// Phase 4: Resolve backend + create sandbox.
	backendName, box, err := createSandbox(ctx, cfg, wd, toolDef, toolPath, sandboxCreds)
	if err != nil {
		return err
	}
	phaseTime("create-sandbox", tPhase)
	registerBoxCleanup(box)
	defer func() {
		unregisterBoxCleanup()
		if cleanErr := box.Cleanup(); cleanErr != nil {
			fmt.Fprintf(os.Stderr, brand.Name+": cleanup: %v\n", cleanErr)
		}
		runGlobalCleanup()
	}()

	// Phase 5: Start the sandboxed tool.
	return executeTool(ctx, &executionContext{
		cfg:          cfg,
		box:          box,
		toolDef:      toolDef,
		toolPath:     toolPath,
		toolBin:      toolBin,
		toolArgs:     toolExtraArgs,
		envOverrides: envOverrides,
		finalCreds:   finalCreds,
		sandboxCreds: sandboxCreds,
		wd:           wd,
		backendName:  backendName,
	})
}

// dispatchBuiltin checks toolArgs[0] for built-in dizgin sub-commands
// (completion, doctor, add-path, diagnose-hang, run). Returns (true, err)
// when a sub-command matched and was handled, (false, nil) when the caller
// should continue with the sandbox path.
func dispatchBuiltin(cmd *cobra.Command, toolArgs []string) (bool, error) {
	switch toolArgs[0] {
	case "completion":
		if cmd == nil {
			// Reachable only via `dizgin run "completion ..."` — the
			// completion generators dereference cmd.Root(), and
			// handleRunSubcommand passes nil to break a package-init
			// cycle. Refuse cleanly rather than panic.
			return true, fmt.Errorf("completion is not supported through 'dizgin run'")
		}
		handleCompletion(cmd, toolArgs[1:])
		return true, nil
	case "doctor":
		return true, runDoctor(toolArgs[1:])
	case "add-path":
		return true, runAddPath(toolArgs[1:])
	case "diagnose-hang":
		// iter6 Layer 6 — Wait Chain Traversal probe. Manual route
		// here because root cobra has DisableFlagParsing=true, so the
		// AddCommand registration alone never dispatches.
		return true, runDiagnoseHang(nil, toolArgs[1:])
	case "update":
		// Same DisableFlagParsing caveat as diagnose-hang: the
		// AddCommand(updateCmd) registration never dispatches on its own,
		// so route the self-update path here explicitly.
		return true, runUpdate(nil, toolArgs[1:])
	case "run":
		// `dizgin run "<line>"` — single-string passthrough that bypasses
		// MSYS path conversion. See run_subcommand.go for the splitter.
		if len(toolArgs) == 1 {
			runSubcommandUsage()
			return true, fmt.Errorf("run: missing command line argument")
		}
		// Re-join everything after "run" so a user typing without
		// quotes still gets a sensible error rather than a confused
		// passthrough. The splitter below will fail loudly on the
		// concatenated form when it contains unbalanced quotes.
		joined := strings.Join(toolArgs[1:], " ")
		return true, handleRunSubcommand(joined)
	}
	return false, nil
}

// prepareToolArgs emits guard-rail warnings and strips the optional leading
// "--" separator, then returns (toolBin, toolExtraArgs).
func prepareToolArgs(toolArgs []string) (string, []string) {
	// MSYS path-conversion guard rail. Emit a one-time stderr hint when
	// the user is in a Git Bash / MSYS2 / Cygwin shell and at least one
	// arg has the /letter shape that MSYS converts. Opt-out: DIZGIN_NO_SHELL_DETECT=1.
	warnIfMSYSConversionRisk(os.Stderr, toolArgs)

	toolBin := toolArgs[0]
	toolExtraArgs := toolArgs[1:]
	// cmd /c re-parse guard rail. cmd reconstructs its argv under its
	// own quoting rules and a `dizgin -- cmd /c "foo bar"` often lands in
	// interactive mode because the kernel quoting doesn't match what
	// cmd expects. Recommend `dizgin run "<line>"` for that case.
	warnIfCmdShellWithSwitches(os.Stderr, toolBin, toolExtraArgs)
	// Strip a leading "--" if present (e.g. "dizgin claude -- --flag").
	// The "--" separator is dizgin's own convention and must not reach the tool.
	if len(toolExtraArgs) > 0 && toolExtraArgs[0] == "--" {
		toolExtraArgs = toolExtraArgs[1:]
	}
	return toolBin, toolExtraArgs
}

// setupAuditAndConfig applies the persistent debug switch from config and
// initialises audit logging. It also triggers zero-config starter-profile
// persistence and records the phase timing.
func setupAuditAndConfig(cfg *config.Config, toolBin string, tPhase time.Time) {
	// Zero-config: when a freshly-detected tool has no profile yet, write
	// a starter one so the auto-detect result is visible + editable. Skips
	// known tools, existing files, and commands with nothing to detect.
	maybePersistStarterProfile(toolBin)

	// Persistent debug switch: ~/.dizgin/config.yaml `setup.debug: true`
	// behaves like exporting DIZGIN_DEBUG=1 for the lifetime of this
	// process. Idempotent — env-var-driven verbose already enabled the
	// switch via the package init.
	if cfg != nil && cfg.Setup.Debug {
		log.EnableVerbose(false)
	}

	// Phase 2: Set up audit logging.
	initAuditLog(cfg)
	phaseTime("audit-init", tPhase)
}

// handleCompletion generates shell completion scripts.
func handleCompletion(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: dizgin completion [bash|zsh|fish|powershell]")
		os.Exit(exitToolError)
	}
	var err error
	switch args[0] {
	case "bash":
		err = cmd.Root().GenBashCompletion(os.Stdout)
	case "zsh":
		err = cmd.Root().GenZshCompletion(os.Stdout)
	case "fish":
		err = cmd.Root().GenFishCompletion(os.Stdout, true)
	case "powershell":
		err = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, brand.Name+": completion: unsupported shell %q (choose bash, zsh, fish, or powershell)\n", args[0])
		os.Exit(exitToolError)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, brand.Name+": completion: %v\n", err)
		os.Exit(exitToolError)
	}
}

// parseOwnFlags parses dizgin's own flags before the tool name.
// Returns the remaining args (env overrides + tool command), or nil if handled.
func parseOwnFlags(args []string) []string {
	if len(args) == 0 {
		return []string{}
	}
	var remaining []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			printUsage()
			return nil
		case a == "-v" || a == "--version" || a == "version":
			fmt.Printf("dizgin %s\n", version)
			if a == "version" {
				fmt.Printf("  commit: %s\n", commit)
				fmt.Printf("  built:  %s\n", date)
				fmt.Printf("  go:     %s\n", goVersion())
			}
			return nil
		case a == "completion" || a == "update":
			remaining = append(remaining, args[i:]...)
			return remaining
		case a == "-w" || a == "--workdir":
			if i+1 < len(args) {
				i++
				workdir = args[i]
			}
		case strings.HasPrefix(a, "-w="):
			workdir = a[3:]
		case strings.HasPrefix(a, "--workdir="):
			workdir = a[10:]
		case a == "-c" || a == "--config":
			if i+1 < len(args) {
				i++
				configFile = args[i]
			}
		case strings.HasPrefix(a, "-c="):
			configFile = a[3:]
		case strings.HasPrefix(a, "--config="):
			configFile = a[9:]
		case a == "--no-pty":
			noTTY = true
		case a == "--learn":
			learnMode = true
		case a == "--profiles":
			if i+1 < len(args) {
				i++
				profilesDir = args[i]
			}
		case strings.HasPrefix(a, "--profiles="):
			profilesDir = a[len("--profiles="):]
		case a == "--":
			// End of dizgin's flags — pass everything after, without the "--" itself.
			remaining = append(remaining, args[i+1:]...)
			return remaining
		default:
			remaining = append(remaining, args[i:]...)
			return remaining
		}
	}
	return remaining
}

func printUsage() {
	fmt.Print(`dizgin — platform-native sandbox wrapper for AI coding tools

Usage: dizgin [flags] [KEY=val...] <tool> [tool-args...]

Flags:
  -w, --workdir <dir>    Working directory (default: current directory)
  -c, --config <file>    Config file (default: dizgin.yaml in workdir, then ~/.config/dizgin/config.yaml)
  --profiles <dir>       Additional profile directory (overrides built-in profiles)
  --no-pty               Disable PTY — use plain pipes (for scripting and CI)
  --learn                Phase 5 permission learning — keep sensitive DENY in
                         place, capture stderr access-denial lines, print
                         summary at session exit
  -h, --help             Show this help
  -v, --version          Show version

Commands:
  version                Print detailed version information
  completion             Generate shell completion script (bash, zsh, fish, powershell)
  doctor [--json]        Run preflight health checks
  add-path <path>...     Append paths to the per-tool profile (use after "tool referenced paths" hint)
  run "<cmdline>"        Run a quoted command line (MSYS path-conversion bypass)

Environment overrides: KEY=val pairs placed before the tool name are merged
with discovered host credentials. Example: dizgin ANTHROPIC_API_KEY=sk-... claude

Exit codes:
  0    Tool exited successfully
  1    Tool exited with error
  126  Tool binary not found in PATH
  127  Sandbox backend unavailable
`)
}

// parseArgs separates KEY=val env overrides from the tool command.
func parseArgs(args []string) (toolArgs []string, envOverrides []string) {
	for i, a := range args {
		if isEnvOverride(a) {
			envOverrides = append(envOverrides, a)
		} else {
			return args[i:], envOverrides
		}
	}
	return nil, envOverrides
}

// isEnvOverride returns true if a matches KEY=VALUE with a valid identifier key.
func isEnvOverride(a string) bool {
	idx := strings.IndexByte(a, '=')
	if idx <= 0 {
		return false
	}
	key := a[:idx]
	for i, ch := range key {
		if i == 0 {
			if !isLetter(ch) && ch != '_' {
				return false
			}
		} else {
			if !isLetter(ch) && !isDigit(ch) && ch != '_' {
				return false
			}
		}
	}
	return true
}

func isLetter(r rune) bool { return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') }
func isDigit(r rune) bool  { return r >= '0' && r <= '9' }

// isInfoCommand returns true for commands that don't require a running daemon.
//
// `doctor` is intentionally listed here even though one of its checks
// pings the daemon — the doctor itself reports daemon absence rather
// than autostarting it. Otherwise we would hide the very condition
// the user ran doctor to detect.
func isInfoCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-h", "--help", "-v", "--version", "version", "completion", "doctor", "add-path", "diagnose-hang", "update":
		return true
	}
	return false
}

func lookupTool(name string) (string, error) {
	return lookPath(name)
}

func resolveWorkdir(wd string) (string, error) {
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getwd: %w", err)
		}
	}
	abs, err := filepath.Abs(wd)
	if err != nil {
		return "", fmt.Errorf("abs workdir: %w", err)
	}
	// Refuse the user home directory as workdir. The restricted backend
	// runs the child as the same user with the full home accessible (R1
	// DENY stamps only block sensitive sub-paths), so mounting the
	// home root as the working directory would silently expose the entire
	// profile tree — defeating the R1 sensitive-surface isolation.
	if home, hErr := os.UserHomeDir(); hErr == nil && home != "" {
		if strings.EqualFold(filepath.Clean(abs), filepath.Clean(home)) {
			return "", fmt.Errorf(
				"workdir cannot be the user home directory (%s) — run dizgin from a project subdirectory",
				abs)
		}
	}
	return abs, nil
}

// loadConfig finds and loads the configuration file.
// Search order: --config flag → <workdir>/dizgin.yaml → ~/.config/dizgin/config.yaml → defaults.
func loadConfig(wd string) (*config.Config, error) {
	if configFile != "" {
		return config.Load(configFile)
	}
	candidates := []string{
		filepath.Join(wd, "dizgin.yaml"),
		filepath.Join(wd, ".dizgin.yaml"),
		configHomeFile(),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return config.Load(p)
		}
	}
	return config.Load("") // defaults only
}

func configHomeFile() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		if filepath.IsAbs(d) && !strings.Contains(d, "..") {
			return filepath.Join(d, brand.Name, "config.yaml")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", brand.Name, "config.yaml")
}
