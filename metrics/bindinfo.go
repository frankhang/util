package metrics

import "github.com/prometheus/client_golang/prometheus"

// bindinfo metrics.
var (
	BindUsageCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "bindinfo",
			Name:      "bind_usage_counter",
			Help:      "Counter of query using sql bind",
		}, []string{LableScope})

	BindTotalGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "tidb",
			Subsystem: "bindinfo",
			Name:      "bind_total_gauge",
			Help:      "Total number of sql bind",
		}, []string{LableScope, LblType})

	BindMemoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "tidb",
			Subsystem: "bindinfo",
			Name:      "bind_memory_usage",
			Help:      "Memory usage of sql bind",
		}, []string{LableScope, LblType})
)
