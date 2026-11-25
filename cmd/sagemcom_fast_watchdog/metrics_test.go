package main

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// gathered returns the value of the watchdog's gauge or counter called
// sagemcom_fast_watchdog_<name>, which must have exactly one series. Gathering
// through a pedantic registry also checks that Collect matches Describe.
func gathered(t *testing.T, w *watchdog, name string) float64 {
	t.Helper()

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(w)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != metricsNamespace+"_"+name {
			continue
		}

		if n := len(mf.GetMetric()); n != 1 {
			t.Fatalf("%s has %d series, want 1", mf.GetName(), n)
		}

		m := mf.GetMetric()[0]
		if g := m.GetGauge(); g != nil {
			return g.GetValue()
		}

		return m.GetCounter().GetValue()
	}

	t.Fatalf("metric %s_%s not collected", metricsNamespace, name)

	return 0
}

func TestWatchdog_CollectorLints(t *testing.T) {
	t.Parallel()

	w, _, _ := newTestWatchdog(t)

	problems, err := testutil.CollectAndLint(w)
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range problems {
		t.Errorf("%s: %s", p.Metric, p.Text)
	}
}

func TestWatchdog_CollectReportsRebootState(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, _, fd := newTestWatchdog(t)
		fd.set(false)

		if got := gathered(t, w, "last_reboot_timestamp_seconds"); got != 0 {
			t.Fatalf("last_reboot_timestamp_seconds = %v before any reboot, want 0", got)
		}

		stop := runLoop(w)
		defer stop()

		// still inside the settle delay after the first reboot: the gauges
		// must already show it
		time.Sleep(w.cfg.RebootAfter + 2*checkInterval)
		synctest.Wait()

		if got := gathered(t, w, "last_reboot_timestamp_seconds"); got == 0 {
			t.Error("last_reboot_timestamp_seconds = 0 during the settle delay after a reboot")
		}

		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+1))
		synctest.Wait()

		if got := gathered(t, w, "gave_up"); got != 1 {
			t.Errorf("gave_up = %v after maxReboots, want 1", got)
		}

		fd.set(true)
		time.Sleep(time.Duration(recoveryThreshold+1) * checkInterval)
		synctest.Wait()

		if got := gathered(t, w, "gave_up"); got != 0 {
			t.Errorf("gave_up = %v after recovery, want 0", got)
		}

		if got := gathered(t, w, "last_reboot_timestamp_seconds"); got != 0 {
			t.Errorf("last_reboot_timestamp_seconds = %v after recovery, want 0", got)
		}
	})
}

// Scrapes happen on the HTTP server's goroutine while the loop runs; with
// -race this catches Collect reading loop-owned state without the lock. It
// runs in real time, not in a synctest bubble: the bubble's fake clock orders
// the goroutines, which hides races from the detector.
func TestWatchdog_CollectConcurrentWithLoop(t *testing.T) {
	t.Parallel()

	w, _, fd := newTestWatchdog(t)
	fd.set(false)

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(w)

	stop := runLoop(w) // the first check runs immediately
	defer stop()

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := reg.Gather(); err != nil {
			t.Fatalf("gather: %v", err)
		}
	}
}
