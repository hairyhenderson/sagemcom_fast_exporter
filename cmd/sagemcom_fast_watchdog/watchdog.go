package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
)

// Fixed tuning. These were once flags; promote one back if a real need turns up.
const (
	checkInterval     = 15 * time.Second // between connectivity checks
	probeTimeout      = 5 * time.Second  // per connectivity check
	retryInterval     = 1 * time.Minute  // between reboot attempts that didn't go through
	rebootTimeout     = 45 * time.Second // for one login+reboot exchange
	settleDelay       = 5 * time.Minute  // pause after a reboot while the device comes back
	maxReboots        = 3                // give up after this many with no recovery in between
	recoveryThreshold = 2                // consecutive good checks before an outage is "over"
)

// controller is the subset of [client.Controller] the watchdog needs. It's
// declared here so tests can substitute a fake.
type controller interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	Reboot(ctx context.Context) error
}

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

//nolint:govet // field alignment: one instance per process
type watchdog struct {
	cfg       *config
	ctrl      controller
	dialer    dialer
	targets   []string
	statePath string

	downSince   time.Time // when the current outage started; zero when up
	lastReboot  time.Time
	lastAttempt time.Time
	lastDownLog time.Time

	consecutiveOK  int
	rebootsSinceOK int
	gaveUpLogged   bool
}

// loop runs connectivity checks until ctx is cancelled.
func (w *watchdog) loop(ctx context.Context) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	w.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick performs one connectivity check and reacts to the result.
func (w *watchdog) tick(ctx context.Context) {
	if w.online(ctx) {
		w.onProbeOK(ctx)

		return
	}

	w.onFailure(ctx)
}

// onProbeOK handles a successful check. A full recovery (which re-arms the
// give-up limit) requires recoveryThreshold consecutive good checks so a
// flapping WAN can't defeat it.
func (w *watchdog) onProbeOK(ctx context.Context) {
	w.downSince = time.Time{}
	w.lastDownLog = time.Time{}
	w.consecutiveOK++

	recovering := w.rebootsSinceOK > 0 || w.gaveUpLogged
	if !recovering {
		return
	}

	if w.consecutiveOK < recoveryThreshold {
		slog.InfoContext(ctx, "connectivity looks back; confirming",
			slog.Int("good_checks", w.consecutiveOK), slog.Int("needed", recoveryThreshold))

		return
	}

	slog.InfoContext(ctx, "connectivity restored", slog.Int("reboots_this_outage", w.rebootsSinceOK))

	w.rebootsSinceOK = 0
	w.lastReboot = time.Time{}
	w.lastAttempt = time.Time{}
	w.gaveUpLogged = false

	w.persist(ctx)
}

func (w *watchdog) onFailure(ctx context.Context) {
	w.consecutiveOK = 0

	now := time.Now()
	if w.downSince.IsZero() {
		w.downSince = now
	}

	down := now.Sub(w.downSince)

	if now.Sub(w.lastDownLog) >= throttledLogInterval {
		w.lastDownLog = now

		slog.WarnContext(ctx, "no connectivity",
			slog.Duration("down_for", down.Round(time.Second)),
			slog.Duration("reboot_after", w.cfg.RebootAfter),
			slog.Int("reboots_this_outage", w.rebootsSinceOK),
		)
	}

	if down >= w.cfg.RebootAfter {
		w.maybeReboot(ctx)
	}
}

// online reports whether any probe target accepts a TCP connection. Targets are
// dialled in parallel; the first success wins and cancels the rest.
func (w *watchdog) online(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	results := make(chan bool, len(w.targets))
	for _, target := range w.targets {
		go func(target string) {
			results <- w.probe(ctx, target)
		}(target)
	}

	// drain every result so no probe goroutine outlives this call
	reachable := false

	for range w.targets {
		if <-results {
			reachable = true

			cancel()
		}
	}

	return reachable
}

func (w *watchdog) probe(ctx context.Context, target string) bool {
	conn, err := w.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		slog.DebugContext(ctx, "probe target unreachable",
			slog.String("target", target), slog.Any("err", err))

		return false
	}

	_ = conn.Close()

	return true
}

// maybeReboot reboots the device, subject to the give-up limit and the cooldown
// / retry backoff.
func (w *watchdog) maybeReboot(ctx context.Context) {
	if w.rebootsSinceOK >= maxReboots {
		w.logGaveUp(ctx)

		return
	}

	now := time.Now()
	if w.backoffRemaining(now) > 0 {
		return // still cooling down; onFailure already logged that we're down
	}

	w.lastAttempt = now

	if w.cfg.DryRun {
		slog.InfoContext(ctx, "dry-run: would reboot the device now")
		w.recordReboot(ctx, now)

		return
	}

	w.attemptReboot(ctx, now)
}

func (w *watchdog) attemptReboot(ctx context.Context, now time.Time) {
	err := w.reboot(ctx)

	switch {
	case errors.Is(err, context.Canceled):
		return
	case err == nil:
		slog.InfoContext(ctx, "reboot initiated", slog.Duration("settle_delay", settleDelay))
		w.recordReboot(ctx, now)
		w.sleep(ctx, settleDelay)
	case errors.Is(err, client.ErrRebootRejected):
		slog.ErrorContext(ctx, "device rejected the reboot request; it will not recover on its own",
			slog.Any("err", err))
		w.recordReboot(ctx, now) // count it: back off and tick the give-up tally
	default:
		slog.WarnContext(ctx, "reboot attempt did not complete; will retry",
			slog.Any("err", err), slog.Duration("retry_after", retryInterval))
		// not recorded: only the retry-interval backoff (via lastAttempt) applies
	}
}

// backoffRemaining returns how long maybeReboot must still wait: the longer of
// the post-reboot cooldown and the between-attempts retry interval.
func (w *watchdog) backoffRemaining(now time.Time) time.Duration {
	var wait time.Duration

	if !w.lastReboot.IsZero() {
		if d := w.cfg.Cooldown - now.Sub(w.lastReboot); d > wait {
			wait = d
		}
	}

	if !w.lastAttempt.IsZero() {
		if d := retryInterval - now.Sub(w.lastAttempt); d > wait {
			wait = d
		}
	}

	return wait
}

func (w *watchdog) recordReboot(ctx context.Context, now time.Time) {
	w.lastReboot = now
	w.rebootsSinceOK++

	w.persist(ctx)

	if w.rebootsSinceOK >= maxReboots {
		w.logGaveUp(ctx)
	}
}

func (w *watchdog) logGaveUp(ctx context.Context) {
	if w.gaveUpLogged {
		return
	}

	slog.ErrorContext(ctx, "giving up: rebooted the device repeatedly with no connectivity restored; "+
		"will keep probing but stop rebooting until it recovers",
		slog.Int("reboots", w.rebootsSinceOK),
	)

	w.gaveUpLogged = true
}

// reboot logs in, sends one reboot request, and logs out. The exchange is
// bounded by rebootTimeout; a cancellation of the parent ctx (shutdown) is
// reported as context.Canceled rather than a reboot failure.
func (w *watchdog) reboot(ctx context.Context) error {
	opCtx, cancel := context.WithTimeout(ctx, rebootTimeout)
	defer cancel()

	if err := w.ctrl.Login(opCtx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return fmt.Errorf("login: %w", err)
	}

	slog.InfoContext(ctx, "logged in to device, sending reboot request")

	rebootErr := w.ctrl.Reboot(opCtx)

	// best effort, with its own short deadline: the device is likely gone
	logoutCtx, logoutCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	if err := w.ctrl.Logout(logoutCtx); err != nil {
		slog.DebugContext(ctx, "logout failed (expected if the device is already going down)",
			slog.Any("err", err))
	}

	logoutCancel()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if rebootErr != nil {
		// our own rebootTimeout fired: the device took the request and went
		// quiet, which is what a reboot looks like
		if errors.Is(rebootErr, context.DeadlineExceeded) {
			return nil
		}

		return fmt.Errorf("reboot: %w", rebootErr)
	}

	return nil
}

func (w *watchdog) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (w *watchdog) persist(ctx context.Context) {
	if w.statePath == "" {
		return
	}

	err := saveState(w.statePath, persistentState{
		LastReboot:     w.lastReboot,
		RebootsSinceOK: w.rebootsSinceOK,
	})
	if err != nil {
		slog.ErrorContext(ctx, "could not persist state",
			slog.String("path", w.statePath), slog.Any("err", err))
	}
}
