package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics to monitor gRPC service
var (
	GRPCConnTransientFailureCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "grpc",
			Name:      "connection_transient_failure_count",
			Help:      "Counter of gRPC connection transient failure",
		}, []string{LblAddress, LblStore})
)
