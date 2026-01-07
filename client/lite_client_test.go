package client

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	//go:embed testdata/fast5670/auth_success_response.json
	authSuccessResponse string
	//go:embed testdata/fast5670/device_success_response.json
	deviceSuccessResponse string
	//go:embed testdata/fast5670/device_error_response.json
	deviceErrorResponse string
	//go:embed testdata/fast5670/resource_usage_success_response.json
	resourceUsageSuccessResponse string
	//go:embed testdata/fast5670/resource_usage_error_response.json
	resourceUsageErrorResponse string
)

// createLiteClientToTestServer creates a test server.
func createLiteClientToTestServer(t *testing.T, mockData string) *LiteClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]requestBody{}

		err := json.Unmarshal([]byte(r.FormValue("req")), &payload)
		if err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}

		var data string

		switch payload["request"].Actions[0].Method {
		case "logIn", "logOut":
			data = authSuccessResponse
		default:
			data = mockData
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write([]byte(data))
		if err != nil {
			t.Fatalf("Failed to write body: %v", err)
		}
	}))

	t.Cleanup(server.Close)
	addr := server.URL[7:] // strip protocol

	return NewLite(addr, "admin", "", EncryptionMethodSHA512, server.Client(), time.Minute)
}

// TestLiteClientGetDevice tests the GetDevice method with anonymized device data.
func TestLiteClientGetDevice(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, deviceSuccessResponse)

	result, err := lc.GetDevice(t.Context())
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetDevice returned nil result")
	}

	device := result.Device

	// Verify device info was parsed
	if device.DeviceInfo.Manufacturer != "SagemCom" {
		t.Errorf("want Manufacturer 'SagemCom', got '%s'", result.Device.DeviceInfo.Manufacturer)
	}

	if device.DeviceInfo.ModelName != "Fast5670_ABRV" {
		t.Errorf("want ModelName 'Fast5670_ABRV', got '%s'", result.Device.DeviceInfo.ModelName)
	}

	if len(device.WiFi.AccessPoints) != 1 {
		t.Errorf("WiFi AccessPoints are missing")
	}

	if len(device.WiFi.Radios) != 1 {
		t.Errorf("WiFi Radios are missing")
	}

	if len(device.WiFi.SSIDs) != 1 {
		t.Errorf("WiFi SSIDs are missing")
	}

	if len(device.Ethernet.Interfaces) != 1 {
		t.Errorf("Ethernet Interfaces are missing")
	}

	if len(device.Optical.Interfaces) != 1 {
		t.Errorf("Optical Interfaces are missing")
	}
}

// TestLiteClientGetResourceUsage tests the GetResourceUsage method.
func TestLiteClientGetResourceUsage(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, resourceUsageSuccessResponse)

	result, err := lc.GetResourceUsage(t.Context())
	if err != nil {
		t.Fatalf("GetResourceUsage failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetResourceUsage returned nil result")
	}

	// Verify memory status
	if result.TotalMemory != 504160 {
		t.Errorf("want TotalMemory 504160, got %d", result.TotalMemory)
	}

	if result.FreeMemory != 94440 {
		t.Errorf("want FreeMemory 94440, got %d", result.FreeMemory)
	}

	// Load average values should match
	if result.LoadAverage != 2.961426 {
		t.Errorf("want LoadAverage 2.961426, got %f", result.LoadAverage)
	}

	if result.LoadAverage5 != 2.860840 {
		t.Errorf("want LoadAverage5 2.860840, got %f", result.LoadAverage5)
	}

	if result.LoadAverage15 != 2.869141 {
		t.Errorf("want LoadAverage15 2.869141, got %f", result.LoadAverage15)
	}

	// Verify CPU usage
	if result.CPUUsage != 5 {
		t.Errorf("want CPUUsage 5, got %d", result.CPUUsage)
	}
}

// TestLiteClientGetDeviceInvalidResponse tests error handling for invalid responses.
func TestLiteClientGetDeviceInvalidResponse(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, `{"invalid":"response"}`)

	_, err := lc.GetDevice(t.Context())
	if err == nil {
		t.Fatal("want error for invalid response, but got none")
	}
}

// TestLiteClientGetResourceUsageInvalidResponse tests error handling for invalid responses.
func TestLiteClientGetResourceUsageInvalidResponse(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, `{"invalid":"response"}`)

	_, err := lc.GetResourceUsage(t.Context())
	if err == nil {
		t.Fatal("want error for invalid response, but got none")
	}
}

// TestLiteClientGetDeviceErrorResponse tests error handling for error code responses.
func TestLiteClientGetDeviceErrorResponse(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, deviceErrorResponse)

	_, err := lc.GetDevice(t.Context())
	if err == nil {
		t.Fatal("want error for error response, but got none")
	}
}

// TestLiteClientGetResourceUsageErrorResponse tests error handling for error code responses.
func TestLiteClientGetResourceUsageErrorResponse(t *testing.T) {
	t.Parallel()

	lc := createLiteClientToTestServer(t, resourceUsageErrorResponse)

	_, err := lc.GetResourceUsage(t.Context())
	if err == nil {
		t.Fatal("want error for error response, but got none")
	}
}
