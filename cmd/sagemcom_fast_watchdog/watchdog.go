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

	// wanStableSlack is how much longer than the outage the device's WAN must
	// have been up for the outage to count as a wedge rather than the tail of
	// a WAN reconnect. It covers a WAN bounce that fits between two checks.
	wanStableSlack = 1 * time.Minute
)

// Reasons for a reboot decision: which WAN state the device reported.
const (
	reasonWedged       = "wedged"        // WAN up throughout the outage: the device itself is stuck
	reasonWANRecovered = "wan_recovered" // WAN came back during the outage, but traffic still isn't flowing
	reasonWANDown      = "wan_down"      // WAN down: probably upstream, and a reboot is unlikely to help
	reasonWANUnknown   = "wan_unknown"   // the device's WAN state couldn't be read
)

// errWANUnsupported stands in for the WAN status of a device that doesn't
// report one.
var errWANUnsupported = errors.New("device does not report WAN status")

// controller is the subset of [client.Controller] the watchdog needs. It's
// declared here so tests can substitute a fake.
type controller interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	Reboot(ctx context.Context) error
	WANStatus(ctx context.Context) (*client.WANStatus, error)
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
	m         *metrics

	downSince   time.Time // when the current run of failed checks started; zero when up
	outageStart time.Time // like downSince, but kept until the outage is logged as over
	lastReboot  time.Time
	lastAttempt time.Time
	lastDownLog time.Time

	consecutiveOK  int
	rebootsSinceOK int
	gaveUpLogged   bool
	wanUnsupported bool // the device doesn't report WAN status; don't ask again
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
	ok := w.online(ctx)
	boolGauge(w.m.connectivityUp, ok)

	if ok {
		w.onProbeOK(ctx)
	} else {
		w.onFailure(ctx)
	}

	setTimestamp(w.m.outageStart, w.outageStart)
}

// onProbeOK handles a successful check, logging the end of any outage. After
// a reboot, a full recovery (which re-arms the give-up limit) requires
// recoveryThreshold consecutive good checks so a flapping WAN can't defeat it.
func (w *watchdog) onProbeOK(ctx context.Context) {
	w.downSince = time.Time{}
	w.lastDownLog = time.Time{}
	w.consecutiveOK++

	recovering := w.rebootsSinceOK > 0 || w.gaveUpLogged
	if recovering && w.consecutiveOK < recoveryThreshold {
		slog.InfoContext(ctx, "connectivity looks back; confirming",
			slog.Int("good_checks", w.consecutiveOK), slog.Int("needed", recoveryThreshold))

		return
	}

	if !recovering && w.outageStart.IsZero() {
		return // no outage to report
	}

	attrs := []any{slog.Int("reboots_this_outage", w.rebootsSinceOK)}
	// unknown after a restart mid-outage
	if !w.outageStart.IsZero() {
		attrs = append(attrs, slog.Duration("down_for", time.Since(w.outageStart).Round(time.Second)))
	}

	slog.InfoContext(ctx, "connectivity restored", attrs...)

	w.outageStart = time.Time{}

	if !recovering {
		return
	}

	w.rebootsSinceOK = 0
	w.lastReboot = time.Time{}
	w.lastAttempt = time.Time{}
	w.gaveUpLogged = false

	setTimestamp(w.m.lastReboot, w.lastReboot)
	w.m.gaveUp.Set(0)

	w.persist(ctx)
}

func (w *watchdog) onFailure(ctx context.Context) {
	w.consecutiveOK = 0

	now := time.Now()
	if w.downSince.IsZero() {
		w.downSince = now
	}

	if w.outageStart.IsZero() {
		w.outageStart = now
	}

	down := now.Sub(w.downSince)

	if now.Sub(w.lastDownLog) >= throttledLogInterval {
		w.lastDownLog = now

		slog.WarnContext(ctx, "no connectivity",
			slog.Duration("down_for", down.Round(time.Second)),
			slog.Int("reboots_this_outage", w.rebootsSinceOK),
		)
	}

	if down >= w.firstDecisionAfter() {
		w.maybeReboot(ctx, now, down)
	}
}

// firstDecisionAfter is how long an outage must last before the watchdog
// starts checking the device's WAN status to decide whether to reboot it: the
// shortest threshold that could apply.
func (w *watchdog) firstDecisionAfter() time.Duration {
	first := w.cfg.RebootAfter
	if w.wanUnsupported {
		return first
	}

	for _, d := range []time.Duration{w.cfg.WedgedRebootAfter, w.cfg.WANDownRebootAfter} {
		if d > 0 && d < first {
			first = d
		}
	}

	return first
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
	start := time.Now()

	conn, err := w.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		// online() cancels the remaining dials once one target connects; that
		// isn't a failure worth reporting.
		if !errors.Is(err, context.Canceled) {
			w.m.observeProbe(target, false, time.Since(start))
			slog.DebugContext(ctx, "probe target unreachable",
				slog.String("target", target), slog.Any("err", err))
		}

		return false
	}

	w.m.observeProbe(target, true, time.Since(start))

	_ = conn.Close()

	return true
}

// maybeReboot checks the device's WAN status and reboots it if the outage has
// lasted long enough for that state, subject to the give-up limit and the
// cooldown / retry backoff.
func (w *watchdog) maybeReboot(ctx context.Context, now time.Time, down time.Duration) {
	if w.rebootsSinceOK >= maxReboots {
		w.logGaveUp(ctx)

		return
	}

	if w.backoffRemaining(now) > 0 {
		return // still cooling down; onFailure already logged that we're down
	}

	w.lastAttempt = now

	v, sent, err := w.session(ctx, down)

	switch {
	case errors.Is(err, context.Canceled):
		return
	case errors.Is(err, client.ErrRebootRejected):
		slog.ErrorContext(ctx, "device rejected the reboot request; it will not recover on its own",
			slog.Any("err", err))
		w.m.reboots.WithLabelValues(v.reason, rebootRejected).Inc()
		w.recordReboot(ctx, now) // count it: back off and tick the give-up tally
	case err != nil:
		if sent {
			w.m.reboots.WithLabelValues(v.reason, rebootFailed).Inc()
		} else {
			w.m.sessionFailures.Inc()
		}

		slog.WarnContext(ctx, "device session did not complete; will retry",
			slog.Any("err", err), slog.Duration("retry_after", retryInterval))
		// not recorded: only the retry-interval backoff (via lastAttempt) applies
	case !v.due():
		// not yet; checkWAN logged the WAN state and what we're waiting for
	case !sent:
		slog.InfoContext(ctx, "dry-run: would reboot the device now", slog.String("reason", v.reason))
		w.m.reboots.WithLabelValues(v.reason, rebootDryRun).Inc()
		w.recordReboot(ctx, now)
	default:
		slog.InfoContext(ctx, "reboot initiated",
			slog.String("reason", v.reason), slog.Duration("settle_delay", settleDelay))
		w.m.reboots.WithLabelValues(v.reason, rebootInitiated).Inc()
		w.recordReboot(ctx, now)
		w.sleep(ctx, settleDelay)
	}
}

// verdict is a reboot decision: the WAN state behind it, and how long that
// state must persist (threshold) versus how long it has (elapsed).
type verdict struct {
	reason    string
	threshold time.Duration // 0 means never
	elapsed   time.Duration
}

func (v verdict) due() bool {
	return v.threshold > 0 && v.elapsed >= v.threshold
}

// assess decides how long to wait before rebooting, given the WAN status the
// device reported (or the error reading it) and how long we've been down:
//
//   - WAN up for the whole outage: the device is wedged and only a reboot
//     clears it, so reboot after -wedged-reboot-after.
//   - WAN came back during the outage: the LAN side can take a few minutes to
//     catch up (e.g. a router renewing its lease), so wait -reboot-after from
//     when the WAN came back.
//   - WAN down: probably an upstream problem a reboot won't fix. Reboot only
//     after -wan-down-reboot-after, in case the device's own WAN client is
//     what's stuck.
//   - unknown: fall back to -reboot-after.
func (w *watchdog) assess(st *client.WANStatus, err error, down time.Duration) verdict {
	switch {
	case err != nil || st == nil:
		return verdict{reason: reasonWANUnknown, threshold: w.cfg.RebootAfter, elapsed: down}
	case !st.Up:
		return verdict{reason: reasonWANDown, threshold: w.cfg.WANDownRebootAfter, elapsed: down}
	case st.Since >= down+wanStableSlack:
		threshold := w.cfg.WedgedRebootAfter
		if threshold == 0 {
			threshold = w.cfg.RebootAfter
		}

		return verdict{reason: reasonWedged, threshold: threshold, elapsed: down}
	default:
		return verdict{reason: reasonWANRecovered, threshold: w.cfg.RebootAfter, elapsed: st.Since}
	}
}

// session logs in, checks the WAN status, reboots the device if the verdict
// says it's time (and this isn't a dry run), and logs out. sent reports
// whether a reboot request went out. The exchange is bounded by
// rebootTimeout; a cancellation of the parent ctx (shutdown) is reported as
// context.Canceled.
func (w *watchdog) session(ctx context.Context, down time.Duration) (v verdict, sent bool, err error) {
	opCtx, cancel := context.WithTimeout(ctx, rebootTimeout)
	defer cancel()

	if err := w.ctrl.Login(opCtx); err != nil {
		if ctx.Err() != nil {
			return verdict{}, false, ctx.Err()
		}

		return verdict{}, false, fmt.Errorf("login: %w", err)
	}

	defer w.logout(ctx)

	v = w.checkWAN(opCtx, down)
	if !v.due() || w.cfg.DryRun {
		return v, false, ctx.Err()
	}

	slog.InfoContext(ctx, "logged in to device, sending reboot request", slog.String("reason", v.reason))

	rebootErr := w.ctrl.Reboot(opCtx)

	switch {
	case ctx.Err() != nil:
		return v, true, ctx.Err()
	case rebootErr == nil:
		return v, true, nil
	case errors.Is(rebootErr, context.DeadlineExceeded):
		// our own rebootTimeout fired: the device took the request and went
		// quiet, which is what a reboot looks like
		return v, true, nil
	default:
		return v, true, fmt.Errorf("reboot: %w", rebootErr)
	}
}

// checkWAN asks the device for its WAN status, logs it, and returns the
// resulting verdict.
func (w *watchdog) checkWAN(ctx context.Context, down time.Duration) verdict {
	st, err := w.wanStatus(ctx)
	v := w.assess(st, err, down)

	attrs := []any{
		slog.Duration("down_for", down.Round(time.Second)),
		slog.String("verdict", v.reason),
		slog.Bool("reboot_due", v.due()),
	}

	if v.threshold > 0 && !v.due() {
		attrs = append(attrs, slog.Duration("reboot_in", (v.threshold-v.elapsed).Round(time.Second)))
	}

	if st != nil {
		attrs = append(attrs,
			slog.Bool("wan_up", st.Up),
			slog.String("wan_status", st.Status),
			slog.String("wan_connection_status", st.ConnectionStatus),
			slog.String("wan_last_error", st.LastConnectionError),
			slog.Duration("wan_since", st.Since),
		)
	} else {
		attrs = append(attrs, slog.Any("wan_err", err))
	}

	slog.InfoContext(ctx, "checked device WAN status", attrs...)

	return v
}

func (w *watchdog) wanStatus(ctx context.Context) (*client.WANStatus, error) {
	if w.wanUnsupported {
		return nil, errWANUnsupported
	}

	st, err := w.ctrl.WANStatus(ctx)

	switch {
	case err == nil:
		result := wanCheckDown
		if st.Up {
			result = wanCheckUp
		}

		w.m.wanChecks.WithLabelValues(result).Inc()

		return st, nil
	case errors.Is(err, client.ErrNoWANInterface), errors.Is(err, client.ErrUnknownPath):
		slog.InfoContext(ctx, "device does not report WAN status; using -reboot-after for every outage",
			slog.Any("err", err))

		w.wanUnsupported = true

		return nil, errWANUnsupported
	default:
		w.m.wanChecks.WithLabelValues(wanCheckError).Inc()

		return nil, err
	}
}

func (w *watchdog) logout(ctx context.Context) {
	// best effort, with its own short deadline: the device may be going down
	logoutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if err := w.ctrl.Logout(logoutCtx); err != nil {
		slog.DebugContext(ctx, "logout failed (expected if the device is already going down)",
			slog.Any("err", err))
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

	setTimestamp(w.m.lastReboot, now)
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
	w.m.gaveUp.Set(1)
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
