package main

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"time"
)

// persistentState is carried across restarts so a bounce of the watchdog - or
// of the whole host, on the same power event that took the WAN down - can't
// reset the cooldown or the give-up count.
type persistentState struct {
	LastReboot     time.Time `json:"last_reboot"`
	RebootsSinceOK int       `json:"reboots_since_ok"`
}

// loadState reads state from path. A missing file is not an error; a corrupt
// one is, and restoreState then errs on the side of caution.
func loadState(path string) (persistentState, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return persistentState{}, nil
	}

	if err != nil {
		return persistentState{}, err
	}

	var s persistentState

	err = json.Unmarshal(b, &s)

	return s, err
}

// saveState writes state via a temp file and a rename, so a crash mid-write can
// never leave path itself truncated. It is not fsync-durable: at worst a power
// loss costs the most recent update (one cooldown cycle), which restoreState
// tolerates.
func saveState(path string, s persistentState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)

		return err
	}

	return nil
}
