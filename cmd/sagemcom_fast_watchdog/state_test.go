package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	want := persistentState{
		LastReboot:     time.Now().Truncate(time.Second),
		RebootsSinceOK: 3,
	}

	if err := saveState(path, want); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	got, err := loadState(path)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}

	if !got.LastReboot.Equal(want.LastReboot) || got.RebootsSinceOK != want.RebootsSinceOK {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestLoadStateMissingFileIsZero(t *testing.T) {
	t.Parallel()

	got, err := loadState(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}

	if !got.LastReboot.IsZero() || got.RebootsSinceOK != 0 {
		t.Errorf("got %+v, want zero value", got)
	}
}

func TestLoadStateCorruptErrors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadState(path); err == nil {
		t.Error("want an error for corrupt state file")
	}
}

func TestSaveStateAtomicNoTempLeft(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := saveState(path, persistentState{RebootsSinceOK: 1}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file left behind after saveState")
	}
}

func benchState() persistentState {
	return persistentState{LastReboot: time.Now(), RebootsSinceOK: 2}
}

func BenchmarkSaveState(b *testing.B) {
	path := filepath.Join(b.TempDir(), "state.json")
	s := benchState()

	b.ReportAllocs()

	for b.Loop() {
		if err := saveState(path, s); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadState(b *testing.B) {
	path := filepath.Join(b.TempDir(), "state.json")
	if err := saveState(path, benchState()); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := loadState(path); err != nil {
			b.Fatal(err)
		}
	}
}
