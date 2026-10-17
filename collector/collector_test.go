package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hairyhenderson/sagemcom_fast_exporter/client"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeScraper struct {
	deviceErr   error
	resourceErr error
}

func (f fakeScraper) GetDevice(_ context.Context) (*client.DeviceResponse, error) {
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}

	return &client.DeviceResponse{}, nil
}

func (f fakeScraper) GetResourceUsage(_ context.Context) (*client.ResourceUsage, error) {
	if f.resourceErr != nil {
		return nil, f.resourceErr
	}

	return &client.ResourceUsage{}, nil
}

type fakeObserver struct {
	calls   int
	success bool
}

func (o *fakeObserver) Observe(_ context.Context, _ time.Duration, success bool) {
	o.calls++
	o.success = success
}

// collectNames runs a scrape and returns the fully-qualified names of all of
// the metrics that were emitted.
func collectNames(t *testing.T, s client.Scraper) ([]string, *fakeObserver) {
	t.Helper()

	obs := &fakeObserver{}
	coll := New(t.Context(), s, obs)

	ch := make(chan prometheus.Metric, 1024)
	coll.Collect(ch)
	close(ch)

	names := []string{}

	for m := range ch {
		desc := m.Desc().String()
		names = append(names, desc)
	}

	return names, obs
}

func anyContains(names []string, sub string) bool {
	for _, n := range names {
		if strings.Contains(n, sub) {
			return true
		}
	}

	return false
}

func TestCollect_ResourceUsageFailureIsNotFatal(t *testing.T) {
	t.Parallel()

	names, obs := collectNames(t, fakeScraper{resourceErr: errors.New("XMO_UNKNOWN_PATH_ERR (16777242)")})

	if obs.calls != 1 {
		t.Fatalf("expected 1 observation, got %d", obs.calls)
	}

	if !obs.success {
		t.Error("a resource usage failure shouldn't fail the scrape")
	}

	if !anyContains(names, "sagemcom_fast_sys") {
		t.Errorf("device metrics should still be exported: %v", names)
	}

	if anyContains(names, "sagemcom_fast_resources") {
		t.Errorf("resource metrics shouldn't be exported: %v", names)
	}
}

func TestCollect_DeviceFailureIsFatal(t *testing.T) {
	t.Parallel()

	names, obs := collectNames(t, fakeScraper{deviceErr: errors.New("boom")})

	if obs.calls != 1 {
		t.Fatalf("expected 1 observation, got %d", obs.calls)
	}

	if obs.success {
		t.Error("a device failure should fail the scrape")
	}

	if len(names) != 0 {
		t.Errorf("expected no metrics, got %v", names)
	}
}

func TestCollect_Success(t *testing.T) {
	t.Parallel()

	names, obs := collectNames(t, fakeScraper{})

	if !obs.success {
		t.Error("expected a successful scrape")
	}

	for _, want := range []string{"sagemcom_fast_sys", "sagemcom_fast_resources"} {
		if !anyContains(names, want) {
			t.Errorf("expected %s metrics: %v", want, names)
		}
	}
}
