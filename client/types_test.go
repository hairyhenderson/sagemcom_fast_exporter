package client

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestRadioUnmarshalJSON(t *testing.T) {
	const data = `{
		"CurrentOperatingChannelBandwidth": "40MHz",
		"TransmitPower": 75,
		"MaxBitRate": 300
	}`

	var r Radio
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if want := int64(40_000_000); r.CurrentOperatingChannelBandwidth != want {
		t.Errorf("CurrentOperatingChannelBandwidth = %d, want %d", r.CurrentOperatingChannelBandwidth, want)
	}

	if want := 0.75; r.TransmitPower != want {
		t.Errorf("TransmitPower = %v, want %v", r.TransmitPower, want)
	}

	if want := int64(300 * 1024 * 1024); r.MaxBitRate != want {
		t.Errorf("MaxBitRate = %d, want %d", r.MaxBitRate, want)
	}
}

// TestRadioUnmarshalJSONNull verifies that a null radio decodes to zero.
func TestRadioUnmarshalJSONNull(t *testing.T) {
	t.Parallel()

	const data = `{"Radios": [null]}`

	var wifi struct {
		Radios []Radio
	}

	if err := json.Unmarshal([]byte(data), &wifi); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if len(wifi.Radios) != 1 {
		t.Fatalf("Radios = %d, want 1", len(wifi.Radios))
	}

	if want := (Radio{}); !reflect.DeepEqual(wifi.Radios[0], want) {
		t.Errorf("Radios[0] = %+v, want the zero value", wifi.Radios[0])
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Time
		wantErr bool
	}{
		{
			name: "empty",
			in:   "",
			want: time.Time{},
		},
		{
			name: "year 0 sentinel",
			in:   "0-01-01T00:00:00+0000",
			want: time.Time{},
		},
		{
			name: "year 1 sentinel",
			in:   "1-01-01T00:00:00+0000",
			want: time.Time{},
		},
		{
			name: "zero-padded year 1",
			in:   "0001-01-01T00:00:00+0000",
			want: time.Time{},
		},
		{
			name: "rfc3339 with Z suffix",
			in:   "2024-03-05T12:34:56Z",
			want: time.Date(2024, 3, 5, 12, 34, 56, 0, time.UTC),
		},
		{
			name: "default layout",
			in:   "2024-03-05T12:34:56-0700",
			want: time.Date(2024, 3, 5, 12, 34, 56, 0, time.FixedZone("", -7*60*60)),
		},
		{
			name:    "unparseable",
			in:      "not a timestamp",
			want:    time.Time{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimestamp(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTimestamp(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}

			if !got.Equal(tt.want) {
				t.Errorf("parseTimestamp(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseTimestampSentinels verifies that every form of the router's "never
// set" timestamp yields the zero value.
func TestParseTimestampSentinels(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"0-01-01T00:00:00+0000",
		"1-01-01T00:00:00+0000",
		"1-01-01T00:00:00Z",
		"1-01-01T00:00:00-0500",
	}

	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			t.Parallel()

			got, err := parseTimestamp(in)
			if err != nil {
				t.Fatalf("parseTimestamp(%q) error = %v", in, err)
			}

			if got != (time.Time{}) {
				t.Errorf("parseTimestamp(%q) = %v, want the zero time", in, got)
			}
		})
	}
}

// TestDeviceInfoUnmarshalJSONSentinelTimestamps verifies that the router's
// "never set" timestamps decode to the zero value, rather than to a year 1
// timestamp in a fixed zone, so that callers can compare against time.Time{}.
func TestDeviceInfoUnmarshalJSONSentinelTimestamps(t *testing.T) {
	t.Parallel()

	const data = `{
		"FirstUseDate": "1-01-01T00:00:00+0000",
		"BackupTimeStamp": "0-01-01T00:00:00+0000",
		"BuildDate": "2022-08-10T02:18:11Z"
	}`

	var di DeviceInfo
	if err := json.Unmarshal([]byte(data), &di); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if di.FirstUseDate != (time.Time{}) {
		t.Errorf("FirstUseDate = %v, want the zero time", di.FirstUseDate)
	}

	if di.BackupTimeStamp != (time.Time{}) {
		t.Errorf("BackupTimeStamp = %v, want the zero time", di.BackupTimeStamp)
	}

	if want := time.Date(2022, 8, 10, 2, 18, 11, 0, time.UTC); !di.BuildDate.Equal(want) {
		t.Errorf("BuildDate = %v, want %v", di.BuildDate, want)
	}
}

// TestCrashHistoryUnmarshalJSONSentinelTimestamp verifies that a never-crashed
// router decodes to the zero value for LastCrashDate.
func TestCrashHistoryUnmarshalJSONSentinelTimestamp(t *testing.T) {
	t.Parallel()

	const data = `{
		"LastCrashDate": "1-01-01T00:00:00+0000",
		"NumberOfCrash": 0
	}`

	var ch CrashHistory
	if err := json.Unmarshal([]byte(data), &ch); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	if ch.LastCrashDate != (time.Time{}) {
		t.Errorf("LastCrashDate = %v, want the zero time", ch.LastCrashDate)
	}
}
