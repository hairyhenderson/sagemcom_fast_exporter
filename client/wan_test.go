package client

import (
	_ "embed"
	"errors"
	"net/http"
	"testing"
	"time"
)

//go:embed testdata/fast5670/wan_status_response.json
var wanStatusResponse string

func TestControllerWANStatus(t *testing.T) {
	t.Parallel()

	ctrl, got := rebootTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wanStatusResponse))
	})

	mustLogin(t, ctrl)

	st, err := ctrl.WANStatus(t.Context())
	if err != nil {
		t.Fatalf("WANStatus: %v", err)
	}

	if len(*got) != 1 || (*got)[0].Method != methodGetValue || (*got)[0].XPath != wanXPath {
		t.Fatalf("actions = %+v, want one getValue of %s", *got, wanXPath)
	}

	want := WANStatus{
		Interface:           "PPP_DATA",
		Status:              "UP",
		ConnectionStatus:    "CONNECTED",
		LastConnectionError: "ERROR_NONE",
		Since:               1623 * time.Second,
		Up:                  true,
	}
	if *st != want {
		t.Errorf("WANStatus = %+v, want %+v", *st, want)
	}
}

func TestControllerWANStatus_NotLoggedIn(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(http.ResponseWriter, *http.Request) {})

	if _, err := ctrl.WANStatus(t.Context()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("WANStatus err = %v, want ErrNotLoggedIn", err)
	}
}

//nolint:funlen // table test
func TestSelectWAN(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		ifaces  []pppInterfaceStatus
		wantErr error
		want    WANStatus
	}{
		"none": {wantErr: ErrNoWANInterface},
		"only disabled": {
			ifaces:  []pppInterfaceStatus{{Alias: "A", Status: "UP", ConnectionStatus: "CONNECTED"}},
			wantErr: ErrNoWANInterface,
		},
		"down": {
			ifaces: []pppInterfaceStatus{{
				Alias: "A", Enable: true, Status: "DOWN", ConnectionStatus: "DISCONNECTED",
				LastConnectionError: "ERROR_NO_ANSWER", LastChange: 30,
			}},
			want: WANStatus{
				Interface: "A", Status: "DOWN", ConnectionStatus: "DISCONNECTED",
				LastConnectionError: "ERROR_NO_ANSWER", Since: 30 * time.Second,
			},
		},
		"up but not connected is down": {
			ifaces: []pppInterfaceStatus{{Alias: "A", Enable: true, Status: "UP", ConnectionStatus: "CONNECTING"}},
			want:   WANStatus{Interface: "A", Status: "UP", ConnectionStatus: "CONNECTING"},
		},
		"case-insensitive": {
			ifaces: []pppInterfaceStatus{{Alias: "A", Enable: true, Status: "Up", ConnectionStatus: "Connected"}},
			want:   WANStatus{Interface: "A", Status: "Up", ConnectionStatus: "Connected", Up: true},
		},
		"prefers the default route": {
			ifaces: []pppInterfaceStatus{
				{Alias: "A", Enable: true, Status: "DOWN"},
				{Alias: "B", Enable: true, Status: "UP", ConnectionStatus: "CONNECTED", DefaultRoute: "DefaultRoute"},
			},
			want: WANStatus{Interface: "B", Status: "UP", ConnectionStatus: "CONNECTED", Up: true},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := selectWAN(tc.ifaces)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("err = %v", err)
			}

			if *got != tc.want {
				t.Errorf("got %+v, want %+v", *got, tc.want)
			}
		})
	}
}
