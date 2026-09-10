package client

import (
	"encoding/json/v2"
	"testing"
)

// BenchmarkUnmarshalDeviceResponse measures the pure decode of a full device
// reply - the hot path in apiRequest / GetDevice.
func BenchmarkUnmarshalDeviceResponse(b *testing.B) {
	data := []byte(deviceSuccessResponse)

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var result map[string]responseBody
		if err := json.Unmarshal(data, &result); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarshalLoginRequest measures marshaling a login request.
func BenchmarkMarshalLoginRequest(b *testing.B) {
	payload := map[string]requestBody{
		"request": {
			SessionID: -1,
			Priority:  true,
			Actions:   []action{loginAction("admin")},
			Cnonce:    12345,
			AuthKey:   "deadbeef",
		},
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := json.Marshal(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetDevice measures the full scrape decode path: request marshal,
// response unmarshal, and the nested value decoding in the lite client.
func BenchmarkGetDevice(b *testing.B) {
	lc := createLiteClientToTestServer(b, deviceSuccessResponse)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := lc.GetDevice(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}
