package main

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

//nolint:funlen // table test
func TestAssess(t *testing.T) {
	t.Parallel()

	cfg := &config{
		RebootAfter:        5 * time.Minute,
		WedgedRebootAfter:  2 * time.Minute,
		WANDownRebootAfter: 30 * time.Minute,
	}

	cases := map[string]struct {
		st     *client.WANStatus
		err    error
		cfg    *config
		reason string
		down   time.Duration
		due    bool
	}{
		"unknown, not yet": {err: errors.New("boom"), down: 4 * time.Minute, reason: reasonWANUnknown},
		"unknown, due":     {err: errors.New("boom"), down: 5 * time.Minute, reason: reasonWANUnknown, due: true},
		"wedged, due": {
			st: &client.WANStatus{Up: true, Since: time.Hour}, down: 2 * time.Minute,
			reason: reasonWedged, due: true,
		},
		"wedged, not yet": {
			st: &client.WANStatus{Up: true, Since: time.Hour}, down: time.Minute,
			reason: reasonWedged,
		},
		"wedged threshold 0 falls back to reboot-after": {
			st:  &client.WANStatus{Up: true, Since: time.Hour},
			cfg: &config{RebootAfter: 5 * time.Minute}, down: 3 * time.Minute,
			reason: reasonWedged,
		},
		// the WAN bounced just before our first failed check: not a wedge
		"WAN changed within the slack": {
			st: &client.WANStatus{Up: true, Since: 2*time.Minute + 30*time.Second}, down: 2 * time.Minute,
			reason: reasonWANRecovered,
		},
		// like 2026-11-25: PPP reconnected ~20s into a ~4 minute outage
		"WAN came back during the outage": {
			st: &client.WANStatus{Up: true, Since: 3*time.Minute + 40*time.Second}, down: 4 * time.Minute,
			reason: reasonWANRecovered,
		},
		"WAN back long enough": {
			st: &client.WANStatus{Up: true, Since: 5 * time.Minute}, down: 8 * time.Minute,
			reason: reasonWANRecovered, due: true,
		},
		"WAN down, not yet": {
			st: &client.WANStatus{Up: false}, down: 29 * time.Minute, reason: reasonWANDown,
		},
		"WAN down, due": {
			st: &client.WANStatus{Up: false}, down: 30 * time.Minute, reason: reasonWANDown, due: true,
		},
		"WAN down, never": {
			st:  &client.WANStatus{Up: false},
			cfg: &config{RebootAfter: 5 * time.Minute}, down: 24 * time.Hour,
			reason: reasonWANDown,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w, _, _ := newTestWatchdog(t)

			w.cfg = cfg
			if tc.cfg != nil {
				w.cfg = tc.cfg
			}

			v := w.assess(tc.st, tc.err, tc.down)
			if v.reason != tc.reason || v.due() != tc.due {
				t.Errorf("assess = %+v (due=%v), want reason %s due=%v", v, v.due(), tc.reason, tc.due)
			}
		})
	}
}

func TestWatchdog_WedgedRebootsEarly(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		w.cfg.WedgedRebootAfter = time.Minute

		fc.setWAN(&fakeWAN{up: true, since: time.Now().Add(-time.Hour)})
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.WedgedRebootAfter + 2*checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d, want 1 (wedged: reboot after -wedged-reboot-after)", reboots)
		}

		if got := testutil.ToFloat64(w.m.reboots.WithLabelValues(reasonWedged, rebootInitiated)); got != 1 {
			t.Errorf("reboots_total{reason=wedged,result=initiated} = %v, want 1", got)
		}
	})
}

func TestWatchdog_WANDownWaitsLonger(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		w.cfg.WedgedRebootAfter = time.Minute
		w.cfg.WANDownRebootAfter = 10 * time.Minute

		fc.setWAN(&fakeWAN{up: false})
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.WANDownRebootAfter - checkInterval)
		synctest.Wait()

		_, reboots, _ := fc.counts()
		if reboots != 0 {
			t.Fatalf("reboots = %d before -wan-down-reboot-after, want 0", reboots)
		}

		if got := testutil.ToFloat64(w.m.wanChecks.WithLabelValues(wanCheckDown)); got < 5 {
			t.Errorf("wan_checks_total{result=down} = %v, want the WAN checked about once a minute", got)
		}

		time.Sleep(retryInterval + 2*checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d after -wan-down-reboot-after, want 1", reboots)
		}
	})
}

func TestWatchdog_WANDownNeverRebootsWhenDisabled(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		w.cfg.WANDownRebootAfter = 0

		fc.setWAN(&fakeWAN{up: false})
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(3 * time.Hour)
		synctest.Wait()

		if _, reboots, logouts := fc.counts(); reboots != 0 || logouts == 0 {
			t.Fatalf("reboots=%d logouts=%d, want no reboots, but sessions closed", reboots, logouts)
		}
	})
}

func TestWatchdog_WANRecoveredWaitsFromWhenItCameBack(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t) // RebootAfter: 2m
		w.cfg.WedgedRebootAfter = time.Minute

		fd.set(false)
		fc.setWAN(&fakeWAN{up: false})

		stop := runLoop(w)
		defer stop()

		// the WAN comes back 30s in, but traffic still doesn't flow
		time.Sleep(30 * time.Second)
		fc.setWAN(&fakeWAN{up: true, since: time.Now()})

		// at 2m15s we've been down longer than -reboot-after, but the WAN has
		// only been back for 1m45s
		time.Sleep(time.Minute + 45*time.Second)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 0 {
			t.Fatalf("reboots = %d, want 0: the WAN hasn't been back for -reboot-after yet", reboots)
		}

		time.Sleep(time.Minute + checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d, want 1", reboots)
		}

		if got := testutil.ToFloat64(w.m.reboots.WithLabelValues(reasonWANRecovered, rebootInitiated)); got != 1 {
			t.Errorf("reboots_total{reason=wan_recovered,result=initiated} = %v, want 1", got)
		}
	})
}

func TestWatchdog_UnsupportedWANFallsBackAndStopsAsking(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t) // fake reports no WAN interface
		w.cfg.WedgedRebootAfter = 30 * time.Second

		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.RebootAfter - checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 0 {
			t.Fatalf("reboots = %d before -reboot-after, want 0", reboots)
		}

		time.Sleep(3 * checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d, want 1 at -reboot-after", reboots)
		}

		fc.mu.Lock()
		checks := fc.wanChecks
		fc.mu.Unlock()

		if checks != 1 || !w.wanUnsupported {
			t.Errorf("WANStatus called %d times (unsupported=%v), want once", checks, w.wanUnsupported)
		}

		if got := testutil.ToFloat64(w.m.reboots.WithLabelValues(reasonWANUnknown, rebootInitiated)); got != 1 {
			t.Errorf("reboots_total{reason=wan_unknown,result=initiated} = %v, want 1", got)
		}
	})
}

func TestWatchdog_WANCheckErrorFallsBackToRebootAfter(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		w.cfg.WedgedRebootAfter = 30 * time.Second

		fc.setWAN(&fakeWAN{err: errors.New("garbled reply")})
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.toFirstReboot() + retryInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d, want 1", reboots)
		}

		if w.wanUnsupported {
			t.Error("a transient WAN check error marked WAN status as unsupported")
		}

		if got := testutil.ToFloat64(w.m.wanChecks.WithLabelValues(wanCheckError)); got < 2 {
			t.Errorf("wan_checks_total{result=error} = %v, want >= 2", got)
		}
	})
}

// An outage that ends without a reboot still gets a "connectivity restored"
// line saying how long it lasted.
//
//nolint:paralleltest // swaps the global slog default
func TestWatchdog_LogsRecoveryWithoutReboot(t *testing.T) {
	var buf syncBuffer

	prev := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.RebootAfter / 2)
		synctest.Wait()

		if got := gathered(t, w, "outage_start_timestamp_seconds"); got == 0 {
			t.Error("outage_start_timestamp_seconds = 0 during an outage")
		}

		if got := gathered(t, w, "connectivity_up"); got != 0 {
			t.Errorf("connectivity_up = %v during an outage, want 0", got)
		}

		fd.set(true)
		time.Sleep(checkInterval)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 0 {
			t.Fatalf("setup: reboots = %d, want 0", reboots)
		}

		out := buf.String()
		if !strings.Contains(out, `msg="connectivity restored"`) || !strings.Contains(out, "down_for=1m") {
			t.Fatalf("no recovery line with the outage length; log:\n%s", out)
		}

		if got := gathered(t, w, "outage_start_timestamp_seconds"); got != 0 {
			t.Errorf("outage_start_timestamp_seconds = %v after recovery, want 0", got)
		}

		if got := gathered(t, w, "connectivity_up"); got != 1 {
			t.Errorf("connectivity_up = %v after recovery, want 1", got)
		}

		// a second good check doesn't log it again
		time.Sleep(checkInterval)
		synctest.Wait()

		if n := strings.Count(buf.String(), "connectivity restored"); n != 1 {
			t.Errorf("logged recovery %d times, want 1", n)
		}
	})
}
