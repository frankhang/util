package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics for the timestamp oracle.
var (
	TSFutureWaitDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "pdclient",
			Name:      "ts_future_wait_seconds",
			Help:      "Bucketed histogram of seconds cost for waiting timestamp future.",
			Buckets:   prometheus.ExponentialBuckets(0.000005, 2, 20), // 5us ~ 5s
		})
)
