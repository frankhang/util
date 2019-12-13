package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics for the GC worker.
var (
	GCWorkerCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_worker_actions_total",
			Help:      "Counter of gc worker actions.",
		}, []string{"type"})

	GCHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_seconds",
			Help:      "Bucketed histogram of gc duration.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 20), // 1s ~ 12days
		}, []string{"stage"})

	GCConfigGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_config",
			Help:      "Gauge of GC configs.",
		}, []string{"type"})

	GCJobFailureCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_failure",
			Help:      "Counter of gc job failure.",
		}, []string{"type"})

	GCActionRegionResultCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_action_result",
			Help:      "Counter of gc action result on region level.",
		}, []string{"type"})

	GCRegionTooManyLocksCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_region_too_many_locks",
			Help:      "Counter of gc scan lock request more than once in the same region.",
		})

	GCUnsafeDestroyRangeFailuresCounterVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "tikvclient",
			Name:      "gc_unsafe_destroy_range_failures",
			Help:      "Counter of unsafe destroyrange failures",
		}, []string{"type"})
)
