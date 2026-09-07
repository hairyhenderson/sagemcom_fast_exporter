package client

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	//go:embed testdata/fast5670/reboot_success_response.json
	rebootSuccessResponse string
	//go:embed testdata/fast5670/reboot_rejected_response.json
	rebootRejectedResponse string
)

// rebootTestServer returns a Controller wired to a test server. The handler for
// the reboot action is supplied by respond; auth actions always succeed.
func rebootTestServer(t *testing.T, respond http.HandlerFunc) (Controller, *[]action) {
	t.Helper()

	var got []action

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]requestBody{}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.Unmarshal([]byte(r.FormValue("req")), &payload); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}

		if m := payload["request"].Actions[0].Method; m == "logIn" || m == "logOut" {
			_, _ = w.Write([]byte(authSuccessResponse))

			return
		}

		got = append(got, payload["request"].Actions...)

		respond(w, r)
	}))

	t.Cleanup(server.Close)

	ctrl := NewController(strings.TrimPrefix(server.URL, "http://"), "admin", "", EncryptionMethodSHA512, server.Client())

	return ctrl, &got
}

func mustLogin(t *testing.T, ctrl Controller) {
	t.Helper()

	if err := ctrl.Login(t.Context()); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func TestControllerReboot_SendsCorrectAction(t *testing.T) {
	t.Parallel()

	ctrl, got := rebootTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(rebootSuccessResponse))
	})

	mustLogin(t, ctrl)

	if err := ctrl.Reboot(t.Context()); err != nil {
		t.Fatalf("Reboot: %v", err)
	}

	if len(*got) != 1 {
		t.Fatalf("got %d actions, want 1: %+v", len(*got), *got)
	}

	act := (*got)[0]
	if act.Method != "reboot" || act.XPath != "Device" {
		t.Errorf("action = {method:%q xpath:%q}, want {reboot Device}", act.Method, act.XPath)
	}

	if src, _ := act.Parameters["source"].(string); src != "GUI" {
		t.Errorf("parameters[source] = %v, want GUI", act.Parameters["source"])
	}
}

func TestControllerReboot_XMOErrorReplyIsRejected(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(rebootRejectedResponse))
	})

	mustLogin(t, ctrl)

	err := ctrl.Reboot(t.Context())
	if !errors.Is(err, ErrRebootRejected) {
		t.Fatalf("Reboot err = %v, want ErrRebootRejected", err)
	}
}

func TestControllerReboot_HTTP4xxIsRejected(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403: won't fix itself
	})

	mustLogin(t, ctrl)

	err := ctrl.Reboot(t.Context())
	if !errors.Is(err, ErrRebootRejected) {
		t.Fatalf("Reboot err = %v, want ErrRebootRejected", err)
	}
}

func TestControllerReboot_TransportErrorIsTreatedAsInitiated(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(http.ResponseWriter, *http.Request) {
		// drop the connection without writing a response, like a device that
		// takes the request and immediately starts rebooting
		panic(http.ErrAbortHandler)
	})

	mustLogin(t, ctrl)

	if err := ctrl.Reboot(t.Context()); err != nil {
		t.Fatalf("Reboot err = %v, want nil (transport error == reboot accepted)", err)
	}
}

func TestControllerReboot_DeadlineIsTreatedAsInitiated(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answer: device went silent after accepting
	})

	mustLogin(t, ctrl)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	if err := ctrl.Reboot(ctx); err != nil {
		t.Fatalf("Reboot err = %v, want nil (no answer within the deadline == rebooting)", err)
	}
}

func TestControllerReboot_TransientErrorIsRetryable(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // 502: server-side, might clear
	})

	mustLogin(t, ctrl)

	err := ctrl.Reboot(t.Context())
	if err == nil || errors.Is(err, ErrRebootRejected) {
		t.Fatalf("Reboot err = %v, want a plain retryable error (not nil, not ErrRebootRejected)", err)
	}
}

func TestControllerReboot_NotLoggedIn(t *testing.T) {
	t.Parallel()

	ctrl, _ := rebootTestServer(t, func(http.ResponseWriter, *http.Request) {})

	if err := ctrl.Reboot(t.Context()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Reboot err = %v, want ErrNotLoggedIn", err)
	}
}
