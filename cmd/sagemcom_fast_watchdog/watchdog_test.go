package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

type fakeController struct {
	loginErr    error
	rebootErr   error
	mu          sync.Mutex
	rebootDelay time.Duration
	logins      int
	reboots     int
	logouts     int
}

func (f *fakeController) Login(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.logins++

	return f.loginErr
}

func (f *fakeController) Logout(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.logouts++

	return nil
}

func (f *fakeController) Reboot(ctx context.Context) error {
	f.mu.Lock()
	f.reboots++
	delay, err := f.rebootDelay, f.rebootErr
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return err
}

func (f *fakeController) counts() (logins, reboots, logouts int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.logins, f.reboots, f.logouts
}

func (f *fakeController) setErrors(login, reboot error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.loginErr, f.rebootErr = login, reboot
}

type fakeDialer struct {
	mu     sync.Mutex
	online bool
}

func (d *fakeDialer) set(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.online = v
}

func (d *fakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	up := d.online
	d.mu.Unlock()

	if !up {
		return nil, errors.New("offline")
	}

	c1, c2 := net.Pipe()
	_ = c2.Close()

	return c1, nil
}

func newTestWatchdog(t *testing.T) (*watchdog, *fakeController, *fakeDialer) {
	t.Helper()

	fc := &fakeController{}
	fd := &fakeDialer{online: true}

	w := &watchdog{
		cfg: &config{
			RebootAfter: 2 * time.Minute,
			Cooldown:    20 * time.Minute,
		},
		ctrl:    fc,
		dialer:  fd,
		targets: []string{"192.0.2.1:53"},
	}

	return w, fc, fd
}

// toFirstReboot is long enough for one full outage-then-reboot-then-settle cycle.
func (w *watchdog) toFirstReboot() time.Duration {
	return w.cfg.RebootAfter + settleDelay + 2*checkInterval
}

// runLoop starts w.loop in the bubble and returns a stop func that cancels it
// and waits for it to exit.
func runLoop(w *watchdog) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		_ = w.loop(ctx)

		close(done)
	}()

	return func() {
		cancel()
		<-done
	}
}

func TestWatchdog_RebootsOnceWhenDown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.toFirstReboot())
		synctest.Wait()

		if _, reboots, logouts := fc.counts(); reboots != 1 || logouts != 1 {
			t.Fatalf("reboots=%d logouts=%d, want 1/1 (session must be closed after use)", reboots, logouts)
		}

		// still inside cooldown: no further reboots
		time.Sleep(w.cfg.Cooldown / 2)
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("reboots = %d after cooldown/2, want 1", reboots)
		}
	})
}

func TestWatchdog_RebootsAgainAfterCooldown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.Cooldown + w.toFirstReboot())
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 2 {
			t.Fatalf("reboots = %d, want 2 (one per cooldown period)", reboots)
		}
	})
}

func TestWatchdog_CircuitBreakerStopsRebooting(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		// run well past maxReboots cooldown periods
		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+3))
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != maxReboots {
			t.Fatalf("reboots = %d, want %d (circuit breaker)", reboots, maxReboots)
		}
	})
}

func TestWatchdog_RecoveryResetsAndResumes(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.toFirstReboot())
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 1 {
			t.Fatalf("setup: reboots = %d, want 1", reboots)
		}

		// recover: takes recoveryThreshold consecutive good checks
		fd.set(true)
		time.Sleep(time.Duration(recoveryThreshold+2) * checkInterval)
		synctest.Wait()

		if !w.downSince.IsZero() || w.rebootsSinceOK != 0 {
			t.Fatalf("after recovery: downSince set=%v rebootsSinceOK=%d, want false/0",
				!w.downSince.IsZero(), w.rebootsSinceOK)
		}

		// go down again: recovery cleared the cooldown, so a fresh reboot
		// should happen once we're down long enough again
		fd.set(false)
		time.Sleep(w.toFirstReboot())
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != 2 {
			t.Fatalf("after second outage: reboots = %d, want 2", reboots)
		}
	})
}

func TestWatchdog_RejectedRebootCountsButKeepsTrying(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)
		fc.setErrors(nil, fmt.Errorf("boom: %w", client.ErrRebootRejected))

		stop := runLoop(w)
		defer stop()

		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+3))
		synctest.Wait()

		// a rejected reboot still counts toward cooldown and the give-up limit
		if _, reboots, _ := fc.counts(); reboots != maxReboots {
			t.Fatalf("reboot attempts = %d, want %d", reboots, maxReboots)
		}

		if !w.gaveUpLogged {
			t.Error("expected the watchdog to give up after repeated rejections")
		}
	})
}

func TestWatchdog_LoginFailureBacksOffAndDoesNotCountAsReboot(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)
		fc.setErrors(errors.New("device unreachable"), nil)

		stop := runLoop(w)
		defer stop()

		window := 5 * retryInterval
		time.Sleep(w.cfg.RebootAfter + window)
		synctest.Wait()

		logins, reboots, _ := fc.counts()

		if reboots != 0 {
			t.Fatalf("Reboot called %d times despite Login failing", reboots)
		}

		// attempts are paced by retryInterval, not the check interval
		if want := int(window/retryInterval) + 2; logins > want {
			t.Fatalf("login attempts = %d, want <= ~%d (should be rate-limited by the retry interval)", logins, want)
		}

		if !w.lastReboot.IsZero() {
			t.Error("a failed login should not record a reboot / start the cooldown")
		}

		if w.rebootsSinceOK != 0 {
			t.Errorf("rebootsSinceOK = %d, want 0 for login failures", w.rebootsSinceOK)
		}
	})
}

func TestWatchdog_DryRunNeverRebootsButRespectsBackoff(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		w.cfg.DryRun = true

		fd.set(false)

		stop := runLoop(w)
		defer stop()

		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+2))
		synctest.Wait()

		if logins, reboots, _ := fc.counts(); logins != 0 || reboots != 0 {
			t.Fatalf("dry-run touched the device: logins=%d reboots=%d", logins, reboots)
		}

		if w.rebootsSinceOK != maxReboots {
			t.Errorf("dry-run rebootsSinceOK = %d, want %d (cooldown/give-up bookkeeping still applies)",
				w.rebootsSinceOK, maxReboots)
		}
	})
}

func TestWatchdog_ShutsDownPromptlyDuringSettle(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, _, fd := newTestWatchdog(t)
		fd.set(false)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)

		go func() { done <- w.loop(ctx) }()

		time.Sleep(w.cfg.RebootAfter + 2*checkInterval)
		synctest.Wait() // loop is now parked in the settle sleep

		cancel()
		synctest.Wait()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("loop returned %v, want context.Canceled", err)
			}
		default:
			t.Fatal("loop did not return after cancel during the settle sleep")
		}
	})
}

func TestWatchdog_OnlineParallelFirstSuccessWins(t *testing.T) {
	t.Parallel()

	w, _, _ := newTestWatchdog(t)
	w.targets = []string{"192.0.2.1:53", "192.0.2.2:53"}
	w.dialer = firstTargetDialer{ok: "192.0.2.2:53"}

	if !w.online(t.Context()) {
		t.Fatal("online() = false, want true (one target reachable)")
	}

	w.dialer = firstTargetDialer{ok: ""}
	if w.online(t.Context()) {
		t.Fatal("online() = true, want false (no target reachable)")
	}
}

type firstTargetDialer struct{ ok string }

func (d firstTargetDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	if address != d.ok {
		return nil, errors.New("nope")
	}

	c1, c2 := net.Pipe()
	_ = c2.Close()

	return c1, nil
}

func TestWatchdog_PersistAndRestoreCooldown(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	rebootedAt := time.Now().Add(-2 * time.Minute)

	if err := saveState(path, persistentState{LastReboot: rebootedAt, RebootsSinceOK: 2}); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	w, _, _ := newTestWatchdog(t)
	w.cfg.Cooldown = 30 * time.Minute
	w.statePath = path
	w.restoreState(t.Context())

	if w.rebootsSinceOK != 2 {
		t.Errorf("rebootsSinceOK = %d, want 2 restored", w.rebootsSinceOK)
	}

	if got := w.backoffRemaining(time.Now()); got <= 0 {
		t.Errorf("backoffRemaining = %v, want > 0 (cooldown must survive a restart)", got)
	}
}

func TestWatchdog_RestoreStateClampsAndAgesOut(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		st           persistentState
		cooldown     time.Duration
		wantReboots  int
		wantCooldown bool // backoffRemaining > 0
	}{
		"future timestamp is ignored": {
			st:          persistentState{LastReboot: time.Now().Add(time.Hour), RebootsSinceOK: 2},
			cooldown:    30 * time.Minute,
			wantReboots: 0, wantCooldown: false,
		},
		"stale state is dropped": {
			st:          persistentState{LastReboot: time.Now().Add(-24 * time.Hour), RebootsSinceOK: 3},
			cooldown:    30 * time.Minute,
			wantReboots: 0, wantCooldown: false,
		},
		"long cooldown keeps state past the 6h floor": {
			st:          persistentState{LastReboot: time.Now().Add(-24 * time.Hour), RebootsSinceOK: 2},
			cooldown:    12 * time.Hour,         // staleAfter = 48h
			wantReboots: 2, wantCooldown: false, // 24h < 48h stale, but > 12h cooldown
		},
		"recent state is kept": {
			st:          persistentState{LastReboot: time.Now().Add(-time.Minute), RebootsSinceOK: 1},
			cooldown:    30 * time.Minute,
			wantReboots: 1, wantCooldown: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "state.json")
			if err := saveState(path, tc.st); err != nil {
				t.Fatal(err)
			}

			w, _, _ := newTestWatchdog(t)
			w.cfg.Cooldown = tc.cooldown
			w.statePath = path
			w.restoreState(t.Context())

			if w.rebootsSinceOK != tc.wantReboots {
				t.Errorf("rebootsSinceOK = %d, want %d", w.rebootsSinceOK, tc.wantReboots)
			}

			if got := w.backoffRemaining(time.Now()) > 0; got != tc.wantCooldown {
				t.Errorf("cooldown active = %v, want %v", got, tc.wantCooldown)
			}
		})
	}
}

func TestWatchdog_CorruptStateAssumesRecentReboot(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, _, _ := newTestWatchdog(t)
	w.cfg.Cooldown = 30 * time.Minute
	w.statePath = path
	w.restoreState(t.Context())

	// unreadable state => assume we just rebooted (cooldown in force) and spent
	// one give-up credit (a crash-looping watchdog still gives up)
	if got := w.backoffRemaining(time.Now()); got <= 0 {
		t.Errorf("backoffRemaining = %v, want > 0 after a corrupt state file", got)
	}

	if w.rebootsSinceOK != 1 {
		t.Errorf("rebootsSinceOK = %d, want 1 after a corrupt state file", w.rebootsSinceOK)
	}
}

func TestWatchdog_RebootTimeoutCountsAsInitiated(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		fc.mu.Lock()
		fc.rebootDelay = 2 * rebootTimeout // device accepts, then goes silent
		fc.mu.Unlock()

		stop := runLoop(w)
		defer stop()

		time.Sleep(w.cfg.RebootAfter + rebootTimeout + settleDelay + 2*checkInterval)
		synctest.Wait()

		// a silent device is a successful reboot: it must be recorded so the
		// cooldown and the give-up limit both apply
		if w.rebootsSinceOK != 1 {
			t.Fatalf("rebootsSinceOK = %d, want 1 (a timed-out reboot is still a reboot)", w.rebootsSinceOK)
		}

		if got := w.backoffRemaining(time.Now()); got <= 0 {
			t.Errorf("cooldown not started after a timed-out reboot (backoffRemaining=%v)", got)
		}
	})
}

func TestWatchdog_TransientRebootErrorRetriesWithoutCounting(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)
		fc.setErrors(nil, errors.New("reboot did not complete: session expired"))

		stop := runLoop(w)
		defer stop()

		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+2))
		synctest.Wait()

		if !w.lastReboot.IsZero() || w.rebootsSinceOK != 0 {
			t.Fatalf("transient reboot error was counted: lastReboot set=%v rebootsSinceOK=%d",
				!w.lastReboot.IsZero(), w.rebootsSinceOK)
		}

		// it should keep trying (paced by retryInterval), not give up
		if _, reboots, _ := fc.counts(); reboots < 3 {
			t.Errorf("only %d attempts; a transient error should be retried", reboots)
		}
	})
}

func TestWatchdog_FlappingRecoveryDoesNotDefeatCircuitBreaker(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		w, fc, fd := newTestWatchdog(t)
		fd.set(false)

		stop := runLoop(w)
		defer stop()

		// one reboot, then a single good probe (a flap), then back down
		time.Sleep(w.toFirstReboot())
		synctest.Wait()

		fd.set(true)
		time.Sleep(checkInterval) // one good check only - below recoveryThreshold
		synctest.Wait()

		if w.rebootsSinceOK == 0 {
			t.Fatal("a single good probe reset the reboot count (flap defeats the breaker)")
		}

		fd.set(false)
		time.Sleep((w.cfg.Cooldown + settleDelay) * time.Duration(maxReboots+3))
		synctest.Wait()

		if _, reboots, _ := fc.counts(); reboots != maxReboots {
			t.Fatalf("reboots = %d, want %d - flapping must not grant extra reboots", reboots, maxReboots)
		}
	})
}
