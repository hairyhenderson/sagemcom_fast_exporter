package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"syscall"
)

// Controller logs in to a device and performs administrative actions such as
// rebooting it. Unlike [Scraper] it does not maintain a long-lived scrape
// session - callers should Login, perform an action, then Logout.
//
// A Controller is not safe for concurrent use.
type Controller interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	Reboot(ctx context.Context) error
}

var _ Controller = (*client)(nil)

// NewController creates a [Controller] for performing administrative actions on
// a device. It accepts the same connection parameters as [New], minus the
// scrape session refresh interval.
func NewController(host, username, password, authMethod string, hc *http.Client) Controller {
	// refresh interval is 0: Reboot uses apiRequest directly, not
	// apiRequestWithRefresh, so no session refresh happens. Do not switch
	// Reboot to apiRequestWithRefresh without revisiting this - a 0 interval
	// makes it refresh (log out + back in) on every call.
	return newClient(host, username, password, authMethod, hc, 0)
}

// Reboot instructs the device to reboot. Login must be called first.
//
// It returns:
//   - nil if the device accepted the reboot. This covers both a clean "200 OK"
//     and the usual case where the request fails at the transport layer because
//     the device dropped the connection (or stopped answering) as it went down.
//   - [ErrRebootRejected] (wrapped) if the device answered with an error it will
//     not clear on its own - a permission restriction, a bad path, a 4xx.
//   - a plain wrapped error for transient conditions worth retrying: an expired
//     session, a 5xx, or the device refusing the connection outright.
//   - context.Canceled if ctx was cancelled.
func (c *client) Reboot(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "SagemcomClient.Reboot")
	defer span.End()

	if c.serverNonce == "" {
		return ErrNotLoggedIn
	}

	actions := []action{
		{
			ID:     0,
			Method: "reboot",
			Parameters: map[string]any{
				"source": "GUI",
			},
			XPath: "Device",
		},
	}

	_, err := c.apiRequest(ctx, actions)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, context.DeadlineExceeded):
		// no answer within the deadline: the device took the request and went
		// quiet, i.e. it is rebooting
		return nil
	case isPermanentRebootError(err):
		return fmt.Errorf("%w: %w", ErrRebootRejected, err)
	case isTransientRebootError(err):
		return fmt.Errorf("reboot did not complete: %w", err)
	default:
		// connection reset / EOF / other transport failure after a good login:
		// the device stopped answering mid-request because it is rebooting
		return nil
	}
}

// isPermanentRebootError reports whether err is a device response that a retry
// will not fix.
func isPermanentRebootError(err error) bool {
	if errors.Is(err, ErrAccessRestriction) ||
		errors.Is(err, ErrNonWritableParam) ||
		errors.Is(err, ErrUnknownPath) {
		return true
	}

	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
	}

	return false
}

// isTransientRebootError reports whether err is worth retrying soon rather than
// treating as either success or a permanent rejection.
func isTransientRebootError(err error) bool {
	if errors.Is(err, ErrInvalidSession) ||
		errors.Is(err, ErrAuthentication) ||
		errors.Is(err, ErrMaxSessionCount) {
		return true
	}

	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 500
	}

	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}
