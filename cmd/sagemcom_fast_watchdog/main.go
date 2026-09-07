// Command sagemcom_fast_watchdog watches for loss of internet connectivity and
// reboots a Sagemcom F@st device when its WAN uplink drops and does not come
// back on its own, while the device's LAN-side management API is still
// reachable.
//
// It is intentionally separate from the exporter: it needs write access to the
// device and a persistent process, neither of which the exporter wants.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
)

const (
	defaultProbeTargets = "1.1.1.1:53,8.8.8.8:53"
	defaultRebootAfter  = 5 * time.Minute
	defaultCooldown     = 30 * time.Minute

	throttledLogInterval = 1 * time.Minute
	stateFileName        = "state.json"
	passwordEnvVar       = "WATCHDOG_PASSWORD"

	// systemdStateDirEnv is set by systemd to the StateDirectory= path (a
	// colon-separated list if more than one is declared). See systemd.exec(5).
	systemdStateDirEnv = "STATE_DIRECTORY"

	// On startup a persisted reboot is discarded as belonging to a finished
	// outage once it is older than this, or older than four -cooldown periods,
	// whichever is longer.
	stateStaleFloor = 6 * time.Hour
)

type config struct {
	Host         string
	Username     string
	Password     string
	PasswordFile string
	AuthMethod   string
	LogLevel     string
	ProbeTargets string
	StateFile    string

	targets []string // parsed from ProbeTargets by parseFlags

	RebootAfter time.Duration
	Cooldown    time.Duration

	DryRun bool
}

func main() {
	cfg := &config{}

	if err := parseFlags(flag.CommandLine, cfg, os.Args[1:]); err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	slog.SetDefault(setupLogger(cfg.LogLevel))

	if err := run(context.Background(), cfg); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("exiting with error", "err", err)
		os.Exit(1)
	}
}

func parseFlags(fs *flag.FlagSet, cfg *config, args []string) error {
	fs.StringVar(&cfg.Host, "host", "192.168.2.1", "IP address or hostname of the device")
	fs.StringVar(&cfg.Username, "username", "admin", "Username for authentication")
	fs.StringVar(&cfg.Password, "password", "",
		"Password for authentication (discouraged - visible in ps; prefer -password-file or $"+passwordEnvVar+")")
	fs.StringVar(&cfg.PasswordFile, "password-file", "", "File to read the password from")
	fs.StringVar(&cfg.AuthMethod, "auth-method", client.EncryptionMethodSHA512,
		"Authentication method to use (SHA512 or MD5)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	fs.StringVar(&cfg.StateFile, "state-file", "",
		"File to persist reboot state across restarts (defaults to $STATE_DIRECTORY/"+stateFileName+" when set)")

	fs.StringVar(&cfg.ProbeTargets, "probe-targets", defaultProbeTargets,
		"Comma-separated ip:port targets to TCP-probe; connectivity is OK if any one connects")
	fs.DurationVar(&cfg.RebootAfter, "reboot-after", defaultRebootAfter,
		"Reboot the device after this long with no connectivity")
	fs.DurationVar(&cfg.Cooldown, "cooldown", defaultCooldown,
		"Minimum time between reboots")
	fs.BoolVar(&cfg.DryRun, "dry-run", false,
		"Log what would happen but never actually reboot the device")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if err := resolvePassword(cfg); err != nil {
		return err
	}

	return validateConfig(cfg)
}

// resolvePassword fills cfg.Password from -password, then -password-file, then
// $WATCHDOG_PASSWORD, in that order.
func resolvePassword(cfg *config) error {
	switch {
	case cfg.Password != "":
	case cfg.PasswordFile != "":
		b, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return fmt.Errorf("read password file: %w", err)
		}

		cfg.Password = strings.TrimSpace(string(b))
	default:
		cfg.Password = strings.TrimSpace(os.Getenv(passwordEnvVar))
	}

	if cfg.Password == "" {
		return fmt.Errorf("no password provided: set -password, -password-file, or $%s", passwordEnvVar)
	}

	return nil
}

func validateConfig(cfg *config) error {
	if cfg.RebootAfter <= 0 {
		return errors.New("-reboot-after must be positive")
	}

	if cfg.Cooldown < 0 {
		return errors.New("-cooldown must not be negative")
	}

	targets, err := parseTargets(cfg.ProbeTargets)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		return errors.New("-probe-targets is empty")
	}

	cfg.targets = targets

	return nil
}

// parseTargets splits and validates the -probe-targets list. Targets must be
// ip:port literals - a hostname would add a DNS dependency to the health check.
func parseTargets(s string) ([]string, error) {
	var targets []string

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		host, port, err := net.SplitHostPort(part)
		if err != nil {
			return nil, fmt.Errorf("probe target %q: %w", part, err)
		}

		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("probe target %q: host must be an IP literal, not a name", part)
		}

		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("probe target %q: invalid port", part)
		}

		targets = append(targets, part)
	}

	return targets, nil
}

func run(ctx context.Context, cfg *config) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	w := &watchdog{
		cfg:       cfg,
		ctrl:      client.NewController(cfg.Host, cfg.Username, cfg.Password, cfg.AuthMethod, &http.Client{}),
		dialer:    &net.Dialer{},
		targets:   cfg.targets,
		statePath: resolveStatePath(cfg),
	}

	w.restoreState(ctx)

	slog.InfoContext(ctx, "starting watchdog",
		slog.String("host", cfg.Host),
		slog.Any("targets", cfg.targets),
		slog.Duration("reboot_after", cfg.RebootAfter),
		slog.Duration("cooldown", cfg.Cooldown),
		slog.String("state_file", w.statePath),
		slog.Bool("dry_run", cfg.DryRun),
	)

	return w.loop(ctx)
}

func (w *watchdog) restoreState(ctx context.Context) {
	if w.statePath == "" {
		return
	}

	now := time.Now()

	st, err := loadState(w.statePath)
	if err != nil {
		// We had state but can't read it. Assume a reboot just happened and one
		// give-up credit was spent: the cooldown applies, and a watchdog that
		// keeps crash-looping (and corrupting its own state) still gives up.
		slog.ErrorContext(ctx, "state file unreadable; assuming a recent reboot for safety",
			slog.String("path", w.statePath), slog.Any("err", err))

		w.lastReboot = now
		w.rebootsSinceOK = 1

		return
	}

	staleAfter := max(stateStaleFloor, 4*w.cfg.Cooldown)

	switch {
	case st.LastReboot.IsZero() && st.RebootsSinceOK == 0:
		return
	case st.LastReboot.After(now):
		slog.WarnContext(ctx, "persisted last_reboot is in the future (clock skew?); ignoring persisted state",
			slog.Time("last_reboot", st.LastReboot))

		return
	case !st.LastReboot.IsZero() && now.Sub(st.LastReboot) > staleAfter:
		slog.InfoContext(ctx, "persisted state is stale; treating the previous outage as resolved",
			slog.Time("last_reboot", st.LastReboot), slog.Duration("age", now.Sub(st.LastReboot)))

		return
	}

	w.lastReboot = st.LastReboot
	w.rebootsSinceOK = st.RebootsSinceOK
	w.gaveUpLogged = st.RebootsSinceOK >= maxReboots

	slog.InfoContext(ctx, "restored reboot state",
		slog.Time("last_reboot", st.LastReboot),
		slog.Int("reboots_since_ok", st.RebootsSinceOK),
	)
}

func resolveStatePath(cfg *config) string {
	if cfg.StateFile != "" {
		return cfg.StateFile
	}

	if dir := os.Getenv(systemdStateDirEnv); dir != "" {
		// a colon-separated list if several were declared; use the first
		first, _, _ := strings.Cut(dir, ":")

		return filepath.Join(first, stateFileName)
	}

	return ""
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level

	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
