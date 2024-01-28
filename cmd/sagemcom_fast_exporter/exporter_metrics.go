package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type scrapeObserver struct {
	scrapeDuration prometheus.Histogram
	scrapeSuccess  prometheus.Gauge
}

func newScrapeObserver() *scrapeObserver {
	ns := "sagemcom_fast_exporter"
	return &scrapeObserver{
		scrapeDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: ns,
				Name:      "collector_scrape_duration_seconds",
				Help:      "Duration of a collector scrape.",
				Buckets:   prometheus.DefBuckets,

				// Enable native histograms, with the factor suggested in the docs
				NativeHistogramBucketFactor: 1.1,
				// OTel default
				NativeHistogramMaxBucketNumber: 160,
				// Reset buckets every 24 hours
				NativeHistogramMinResetDuration: 24 * time.Hour,
			},
		),
		scrapeSuccess: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: ns,
				Name:      "collector_scrape_success",
				Help:      "Whether a collection succeeded.",
			},
		),
	}
}

func (o *scrapeObserver) Observe(duration time.Duration, success bool) {
	o.scrapeDuration.Observe(duration.Seconds())
	if success {
		o.scrapeSuccess.Set(1)
	} else {
		o.scrapeSuccess.Set(0)
	}
}

func (o *scrapeObserver) Describe(ch chan<- *prometheus.Desc) {
	ch <- o.scrapeDuration.Desc()
	ch <- o.scrapeSuccess.Desc()
}

func (o *scrapeObserver) Collect(ch chan<- prometheus.Metric) {
	o.scrapeDuration.Collect(ch)
	o.scrapeSuccess.Collect(ch)
}
