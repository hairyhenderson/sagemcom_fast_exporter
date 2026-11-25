package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoWANInterface is returned by WANStatus when the device has no enabled
// PPP interface to report on - for example a device that doesn't use PPPoE
// for its uplink.
var ErrNoWANInterface = errors.New("no enabled PPP interface")

const wanXPath = "Device/PPP/Interfaces"

// WANStatus is the state of the device's WAN (PPP) uplink as the device itself
// reports it.
type WANStatus struct {
	// Interface is the PPP interface's alias, e.g. "PPP_DATA".
	Interface string
	// Status is the interface status, e.g. "UP" or "DOWN".
	Status string
	// ConnectionStatus is the PPP session state, e.g. "CONNECTED".
	ConnectionStatus string
	// LastConnectionError is the reason the last session ended, e.g.
	// "ERROR_NONE".
	LastConnectionError string
	// Since is how long the interface has been in its current Status (TR-181
	// LastChange).
	Since time.Duration
	// Up is true when the interface is up and the PPP session is connected.
	Up bool
}

type pppInterfaceStatus struct {
	Alias               string `json:"Alias"`
	Status              string `json:"Status"`
	ConnectionStatus    string `json:"ConnectionStatus"`
	LastConnectionError string `json:"LastConnectionError"`
	DefaultRoute        string `json:"DefaultRoute"`
	LastChange          int64  `json:"LastChange"`
	Enable              bool   `json:"Enable"`
}

// WANStatus reports the state of the device's PPP uplink. Login must be called
// first. When there are several enabled PPP interfaces, the one carrying the
// default route is preferred.
func (c *client) WANStatus(ctx context.Context) (*WANStatus, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.WANStatus")
	defer span.End()

	if c.serverNonce == "" {
		return nil, ErrNotLoggedIn
	}

	result, err := c.apiRequest(ctx, []action{{ID: 0, Method: methodGetValue, XPath: wanXPath}})
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", wanXPath, err)
	}

	reply, ok := result["reply"]
	if !ok || len(reply.Actions) == 0 || len(reply.Actions[0].Callbacks) == 0 {
		return nil, fmt.Errorf("get %s: empty reply", wanXPath)
	}

	var ifaces []pppInterfaceStatus

	value := reply.Actions[0].Callbacks[0].Parameters["value"]
	if err := json.Unmarshal(value, &ifaces); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", wanXPath, err)
	}

	return selectWAN(ifaces)
}

func selectWAN(ifaces []pppInterfaceStatus) (*WANStatus, error) {
	var chosen *pppInterfaceStatus

	for i := range ifaces {
		iface := &ifaces[i]
		if !iface.Enable {
			continue
		}

		if chosen == nil || (chosen.DefaultRoute == "" && iface.DefaultRoute != "") {
			chosen = iface
		}
	}

	if chosen == nil {
		return nil, ErrNoWANInterface
	}

	return &WANStatus{
		Interface:           chosen.Alias,
		Status:              chosen.Status,
		ConnectionStatus:    chosen.ConnectionStatus,
		LastConnectionError: chosen.LastConnectionError,
		Since:               time.Duration(chosen.LastChange) * time.Second,
		Up: strings.EqualFold(chosen.Status, "UP") &&
			strings.EqualFold(chosen.ConnectionStatus, "CONNECTED"),
	}, nil
}
