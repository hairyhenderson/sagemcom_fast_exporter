package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	t.Parallel()

	ok := []struct {
		in   string
		want int
	}{
		{"1.1.1.1:53,8.8.8.8:53", 2},
		{"1.1.1.1:53 ,, 8.8.8.8:53 ", 2}, // whitespace and empty segments tolerated
		{"[2606:4700:4700::1111]:53", 1},
	}
	for _, tc := range ok {
		got, err := parseTargets(tc.in)
		if err != nil {
			t.Errorf("parseTargets(%q) errored: %v", tc.in, err)

			continue
		}

		if len(got) != tc.want {
			t.Errorf("parseTargets(%q) = %v, want %d entries", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"1.1.1.1",       // no port
		"dns.google:53", // hostname, not IP
		"1.1.1.1:0",     // port out of range
		"1.1.1.1:99999", // port out of range
		"1.1.1.1:http",  // non-numeric port
	}
	for _, in := range bad {
		if _, err := parseTargets(in); err == nil {
			t.Errorf("parseTargets(%q) = nil error, want an error", in)
		}
	}
}

func TestResolvePassword(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		t.Setenv(passwordEnvVar, "fromenv")

		cfg := &config{Password: "fromflag"}
		if err := resolvePassword(cfg); err != nil {
			t.Fatal(err)
		}

		if cfg.Password != "fromflag" {
			t.Errorf("password = %q, want %q", cfg.Password, "fromflag")
		}
	})

	t.Run("file when no flag", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(p, []byte("  filesecret\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		t.Setenv(passwordEnvVar, "fromenv")

		cfg := &config{PasswordFile: p}
		if err := resolvePassword(cfg); err != nil {
			t.Fatal(err)
		}

		if cfg.Password != "filesecret" {
			t.Errorf("password = %q, want %q (trimmed)", cfg.Password, "filesecret")
		}
	})

	t.Run("env last", func(t *testing.T) {
		t.Setenv(passwordEnvVar, "fromenv")

		cfg := &config{}
		if err := resolvePassword(cfg); err != nil {
			t.Fatal(err)
		}

		if cfg.Password != "fromenv" {
			t.Errorf("password = %q, want %q", cfg.Password, "fromenv")
		}
	})

	t.Run("none is an error", func(t *testing.T) {
		t.Setenv(passwordEnvVar, "")

		if err := resolvePassword(&config{}); err == nil {
			t.Error("want an error when no password is available")
		}
	})
}

func baseConfig() *config {
	return &config{
		ProbeTargets: defaultProbeTargets,
		RebootAfter:  defaultRebootAfter,
		Cooldown:     defaultCooldown,
	}
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	if err := validateConfig(baseConfig()); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}

	mutations := map[string]func(*config){
		"zero reboot-after":     func(c *config) { c.RebootAfter = 0 },
		"negative reboot-after": func(c *config) { c.RebootAfter = -time.Second },
		"negative cooldown":     func(c *config) { c.Cooldown = -time.Second },
		"bad target":            func(c *config) { c.ProbeTargets = "1.1.1.1" },
		"empty targets":         func(c *config) { c.ProbeTargets = " , " },
	}
	for name, mutate := range mutations {
		cfg := baseConfig()
		mutate(cfg)

		if err := validateConfig(cfg); err == nil {
			t.Errorf("%s: validateConfig accepted an invalid config", name)
		}
	}
}

func TestParseFlagsRequiresPassword(t *testing.T) {
	t.Setenv(passwordEnvVar, "")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.NewFile(0, os.DevNull))

	if err := parseFlags(fs, &config{}, []string{"-host", "10.0.0.1"}); err == nil {
		t.Fatal("expected parseFlags to fail without a password")
	}
}

func TestResolveStatePath(t *testing.T) {
	t.Run("explicit flag wins", func(t *testing.T) {
		t.Setenv(systemdStateDirEnv, "/run/whatever")

		if got := resolveStatePath(&config{StateFile: "/tmp/x.json"}); got != "/tmp/x.json" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("systemd STATE_DIRECTORY", func(t *testing.T) {
		t.Setenv(systemdStateDirEnv, "/var/lib/sagemcom_fast_watchdog:/other")

		want := filepath.Join("/var/lib/sagemcom_fast_watchdog", stateFileName)
		if got := resolveStatePath(&config{}); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("neither: disabled", func(t *testing.T) {
		t.Setenv(systemdStateDirEnv, "")

		if got := resolveStatePath(&config{}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}
