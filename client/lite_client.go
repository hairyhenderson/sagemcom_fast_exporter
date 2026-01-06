package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// XPath constants for GetValue requests
const (
	xpathDeviceInfo = "Device/DeviceInfo"
	xpathWiFi       = "Device/WiFi"
	xpathEthernet   = "Device/Ethernet"
	xpathOptical    = "Device/Optical"
)

// XPath constants for GetResourceUsage requests
const (
	xpathMemoryStatus      = "Device/DeviceInfo/MemoryStatus"
	xpathFlashMemoryStatus = "Device/DeviceInfo/FlashMemoryStatus"
	xpathLoadAverage       = "Device/DeviceInfo/ProcessStatus/LoadAverage"
	xpathCPUUsage          = "Device/DeviceInfo/ProcessStatus/CPUUsage"
)

// NewLite creates a new LiteClient that uses a lite scraper implementation.
// It accepts the same parameters as the standard client constructor.
func NewLite(host, username, password, authMethod string, hc *http.Client, refresh time.Duration) *LiteClient {
	return &LiteClient{client: newClient(host, username, password, authMethod, hc, refresh)}
}

var _ Scraper = (*LiteClient)(nil)

// LiteClient is a lite implementation of the Scraper interface.
type LiteClient struct {
	*client
}

// GetValue retrieves comprehensive device information including DeviceInfo, WiFi, Ethernet, and Optical data.
//
// Note: The LiteClient implementation intentionally ignores the xpath parameter from the
// Scraper interface. Instead of querying a single XPath, it always fetches a fixed set of
// XPaths to minimize the number of round-trips to the device.
//
//nolint:gocyclo,funlen
func (c *LiteClient) GetValue(ctx context.Context, xpath string) (*ValueResponse, error) {
	// The xpath parameter is accepted to satisfy the Scraper interface but is not used,
	// because LiteClient always requests the same predefined XPaths.
	_ = xpath
	ctx, span := tracer.Start(ctx, "SagemcomClient.GetDeviceInfo")
	defer span.End()

	actions := []action{
		{
			ID:     0,
			Method: "getValue",
			XPath:  xpathDeviceInfo,
		},
		{
			ID:     1,
			Method: "getValue",
			XPath:  xpathWiFi,
		},
		{
			ID:     2,
			Method: "getValue",
			XPath:  xpathEthernet,
		},
		{
			ID:     3,
			Method: "getValue",
			XPath:  xpathOptical,
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return nil, fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	reply, ok := result["reply"]
	if !ok {
		return nil, errors.New("no reply in result")
	}

	deviceInfo := ValueResponse{}
	// temporary value to unmarshal and copy data
	d := Device{}

	for _, action := range reply.Actions {
		for _, cb := range action.Callbacks {
			if cb.Result.Code != ErrNoError.Code {
				return nil, fmt.Errorf("failed to fetch device info: %v", cb.Result)
			}

			value := cb.Parameters["value"]

			switch cb.XPath {
			case xpathDeviceInfo:
				// replace invalid time format
				value = bytes.ReplaceAll(value,
					[]byte("1-01-01T00:00:00+0000"),
					[]byte("0001-01-01T00:00:00+0000"),
				)

				err = json.Unmarshal(value, &deviceInfo.Device)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}
			case xpathWiFi:
				err = json.Unmarshal(value, &d)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				deviceInfo.Device.WiFi = d.WiFi
			case xpathEthernet:
				err = json.Unmarshal(value, &d)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				deviceInfo.Device.Ethernet = d.Ethernet
			case xpathOptical:
				err = json.Unmarshal(value, &d)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				deviceInfo.Device.Optical = d.Optical
			}
		}
	}

	return &deviceInfo, nil
}

// GetResourceUsage retrieves system resource usage including memory, flash memory, load average, and CPU usage.
//
//nolint:gocyclo,funlen
func (c *LiteClient) GetResourceUsage(ctx context.Context) (*ResourceUsage, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.GetResourceUsage")
	defer span.End()

	actions := []action{
		{
			ID:     0,
			Method: "getValue",
			XPath:  xpathMemoryStatus,
		},
		{
			ID:     1,
			Method: "getValue",
			XPath:  xpathFlashMemoryStatus,
		},
		{
			ID:     2,
			Method: "getValue",
			XPath:  xpathLoadAverage,
		},
		{
			ID:     3,
			Method: "getValue",
			XPath:  xpathCPUUsage,
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return nil, fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	reply, ok := result["reply"]
	if !ok {
		return nil, errors.New("no reply in result")
	}

	ru := ResourceUsage{}

	for _, action := range reply.Actions {
		for _, cb := range action.Callbacks {
			if cb.Result.Code != ErrNoError.Code {
				return nil, fmt.Errorf("non-success result for %s: code=%v", cb.XPath, cb.Result.Code)
			}

			switch cb.XPath {
			case xpathLoadAverage:
				var value struct {
					LoadAverage struct {
						Load1  float64
						Load5  float64
						Load15 float64
					}
				}

				err = json.Unmarshal(cb.Parameters["value"], &value)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				ru.LoadAverage = value.LoadAverage.Load1
				ru.LoadAverage5 = value.LoadAverage.Load5
				ru.LoadAverage15 = value.LoadAverage.Load15
			case xpathMemoryStatus:
				var value struct {
					MemoryStatus struct {
						Total int64
						Free  int64
					}
				}

				err = json.Unmarshal(cb.Parameters["value"], &value)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				ru.TotalMemory = value.MemoryStatus.Total
				ru.FreeMemory = value.MemoryStatus.Free
			case xpathFlashMemoryStatus:
				var value struct {
					FlashMemoryStatus struct {
						Total int64
						Free  int64
					}
				}

				err = json.Unmarshal(cb.Parameters["value"], &value)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}

				ru.AvailableFlashMemory = value.FlashMemoryStatus.Free
				ru.UsedFlashMemory = value.FlashMemoryStatus.Total - value.FlashMemoryStatus.Free
			case xpathCPUUsage:
				err = json.Unmarshal(cb.Parameters["value"], &ru.CPUUsage)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s: %w", cb.XPath, err)
				}
			}
		}
	}

	return &ru, nil
}
