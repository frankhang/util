package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// distsql metrics.
var (
	DistSQLQueryHistgram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "distsql",
			Name:      "handle_query_duration_seconds",
			Help:      "Bucketed histogram of processing time (s) of handled queries.",
			Buckets:   prometheus.ExponentialBuckets(0.0005, 2, 18), // 0.5ms ~ 128s
		}, []string{LblType, LblSQLType})

	DistSQLScanKeysPartialHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "distsql",
			Name:      "scan_keys_partial_num",
			Help:      "number of scanned keys for each partial result.",
		},
	)
	DistSQLScanKeysHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "distsql",
			Name:      "scan_keys_num",
			Help:      "number of scanned keys for each query.",
		},
	)
	DistSQLPartialCountHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "distsql",
			Name:      "partial_num",
			Help:      "number of partial results for each query.",
		},
	)
)
