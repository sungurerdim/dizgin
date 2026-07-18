// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sungurerdim/dizgin/internal/brand"
	"github.com/sungurerdim/dizgin/internal/config"
	"github.com/sungurerdim/dizgin/internal/daemon"
	logpkg "github.com/sungurerdim/dizgin/internal/log"
)

// detachMode is true unless --foreground is passed to "dizgind start".
// Read by ensureElevated so it can hide the console window in background mode.
var detachMode = true

var rootCmd = &cobra.Command{
	Use:   brand.DaemonName,
	Short: "dizgind — orchestration daemon for dizgin sandbox sessions",
	// Version is overridden in init() with the ldflags-injected value so cobra
	// can auto-generate the --version flag. We keep the field here (without a
	// value) only so readers grepping for "Version" in this file see the link.
	SilenceUsage: true,
	RunE:         runDaemon,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the dizgind daemon in the background",
	Long: `Start the dizgind daemon as a background process.

Use --foreground to keep the daemon attached to the terminal (useful for
debugging). The daemon requires administrator privileges on Windows; dizgind
will request elevation automatically if needed.`,
	RunE: runDaemon,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running dizgind daemon",
	RunE:  runStop,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active sandbox sessions",
	RunE:  runStatus,
}

var completionCmd = &cobra.Command{
	Use:                   "completion [bash|zsh|fish|powershell]",
	Short:                 "Generate shell completion script",
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %q", args[0])
		}
	},
}

func init() {
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("dizgind {{.Version}}\n")

	// Foreground flag — start only.
	startCmd.Flags().Bool("foreground", false, "Run daemon in foreground, attached to terminal (for debugging)")
	// Metrics endpoint flag — opt-in Prometheus exposition.
	startCmd.Flags().String("metrics", "", "Prometheus /metrics bind address (e.g. 'localhost:9876' for loopback, ':9876' for all interfaces). Empty disables.")

	// status --json flag.
	statusCmd.Flags().Bool("json", false, "Output as JSON instead of a human-readable table")

	rootCmd.AddCommand(startCmd, stopCmd, statusCmd, completionCmd, versionCmd)
}

func main() {
	// Pre-parse --foreground before cobra so ensureElevated can read detachMode.
	// While we're walking the args once, also rewrite any `-v` token to the
	// canonical `--version` so cobra's built-in version flag picks it up.
	// cobra does not auto-register a short alias for --version, and adding one
	// manually clashes with InitDefaultVersionFlag; rewriting here is the
	// least-invasive way to expose `dizgind -v` alongside `dizgind --version`.
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--foreground":
			detachMode = false
		case "-v":
			os.Args[i+1] = "--version"
		}
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runDaemon starts the daemon and blocks until killed or signalled.
func runDaemon(cmd *cobra.Command, _ []string) error {
	fg, _ := cmd.Flags().GetBool("foreground")
	if fg {
		detachMode = false
	}

	if daemon.IsDaemonRunning() {
		if !detachMode {
			fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon is already running")
		}
		return nil
	}

	ensureElevated()

	// In detach mode the elevated child runs with a hidden console — its
	// stderr disappears unless we redirect it. Open a per-boot log file
	// under %ProgramData%\dizgin\logs\daemon.log and tee Stdout+Stderr to
	// it so server logs and stamp-broker output are recoverable for
	// debugging without recompiling with --foreground.
	if detachMode {
		redirectDaemonOutput()
	}

	// Verbose framework: dump the system inventory + start the merged
	// log aggregator (only when DIZGIN_DEBUG=all). Both helpers
	// short-circuit on production so startup latency is unaffected.
	logpkg.PreflightWindows()
	logpkg.StartAggregator()

	if _, err := config.Load(""); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Apply persistent debug switch from config (if env didn't already
	// flip it). config.Load reads ~/.dizgin/config.yaml so cfg.Setup.Debug
	// is the place we honour a user-pinned preference.
	if cfg, err := config.Load(""); err == nil && cfg != nil && cfg.Setup.Debug {
		logpkg.EnableVerbose(false)
	}

	srv := daemon.NewServer()
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("daemon: listen: %w", err)
	}
	if !detachMode {
		fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon listening")
	}

	// Optional Prometheus /metrics endpoint. Bound only when --metrics
	// is passed; the daemon-startedAt timestamp captured here drives
	// the dizgin_daemon_uptime_seconds gauge.
	metricsAddr, _ := cmd.Flags().GetString("metrics")
	daemonStartedAt := time.Now()
	stopMetrics, err := startMetricsServer(metricsAddr, srv, daemonStartedAt)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	defer func() { _ = stopMetrics() }()

	// Cleanup is the FIRST work the daemon does after the listener is up:
	// any orphan staging trees left behind by a previous crashed dizgin
	// invocation are reaped before any new session can register.
	// StartStagingCleanupLoop runs an immediate sweep + schedules the
	// periodic ticker. No-op on non-Windows.
	stopStagingCleanup := daemon.StartStagingCleanupLoop()
	defer stopStagingCleanup()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigC
		_ = srv.Close()
	}()

	srv.Serve()
	logpkg.StopAggregator()
	return nil
}

// runStop sends a graceful shutdown request to the running daemon.
func runStop(_ *cobra.Command, _ []string) error {
	if !daemon.IsDaemonRunning() {
		fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon is not running")
		return nil
	}
	if err := daemon.Shutdown(); err != nil {
		return fmt.Errorf(brand.DaemonName+": %w", err)
	}
	fmt.Fprintln(os.Stderr, brand.DaemonName+": daemon stopped")
	return nil
}

// runStatus prints active sandbox instances.
// Default output is a human-readable table; --json outputs raw JSON.
func runStatus(cmd *cobra.Command, _ []string) error {
	instances, err := daemon.QueryStatus()
	if err != nil {
		return fmt.Errorf(brand.DaemonName+": %w", err)
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(instances)
	}

	if len(instances) == 0 {
		fmt.Println("No active sessions.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TOOL\tSTATUS\tUPTIME\tWORKDIR")
	for _, s := range instances {
		uptime := formatUptime(s.UptimeSeconds)
		wd := shortenPath(s.Workdir, 40)
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Tool, string(s.Status), uptime, wd)
	}
	return w.Flush()
}

func formatUptime(secs int64) string {
	if secs <= 0 {
		return "-"
	}
	d := time.Duration(secs) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func shortenPath(p string, maxLen int) string {
	if len(p) <= maxLen {
		return p
	}
	sep := string(filepath.Separator)
	parts := strings.Split(p, sep)
	result := p[len(p)-maxLen+1:]
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.Join(parts[i:], sep)
		if len(candidate) <= maxLen-1 {
			return "…" + sep + candidate
		}
	}
	return "…" + result
}
