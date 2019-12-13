package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics for the domain package.
var (
	// LoadSchemaCounter records the counter of load schema.
	LoadSchemaCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "domain",
			Name:      "load_schema_total",
			Help:      "Counter of load schema",
		}, []string{LblType})

	// LoadSchemaDuration records the duration of load schema.
	LoadSchemaDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "domain",
			Name:      "load_schema_duration_seconds",
			Help:      "Bucketed histogram of processing time (s) in load schema.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 20), // 1ms ~ 4000s
		})

	// LoadPrivilegeCounter records the counter of load privilege.
	LoadPrivilegeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "domain",
			Name:      "load_privilege_total",
			Help:      "Counter of load privilege",
		}, []string{LblType})

	SchemaValidatorStop       = "stop"
	SchemaValidatorRestart    = "restart"
	SchemaValidatorReset      = "reset"
	SchemaValidatorCacheEmpty = "cache_empty"
	SchemaValidatorCacheMiss  = "cache_miss"
	// HandleSchemaValidate records the counter of handling schema validate.
	HandleSchemaValidate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "domain",
			Name:      "handle_schema_validate",
			Help:      "Counter of handle schema validate",
		}, []string{LblType})
)
