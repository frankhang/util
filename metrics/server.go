package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ResettablePlanCacheCounterFortTest be used to support reset counter in test.
	ResettablePlanCacheCounterFortTest = false
)

// Metrics
var (



	ConnGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "frank",
			Subsystem: "tcp",
			Name:      "connections",
			Help:      "Number of connections.",
		})




	CriticalErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "critical_error_total",
			Help:      "Counter of critical errors.",
		})

	EventStart        = "start"
	EventGracefulDown = "graceful_shutdown"
	// Eventkill occurs when the server.Kill() function is called.
	EventKill = "kill"
	// EventHang occurs when server meet some critical error. It will close the listening port and hang for ever.
	EventHang          = "hang"
	EventClose         = "close"
	ServerEventCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "event_total",
			Help:      "Counter of erver event.",
		}, []string{LblType})

	TimeJumpBackCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "monitor",
			Name:      "time_jump_back_total",
			Help:      "Counter of system time jumps backward.",
		})

	KeepAliveCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "monitor",
			Name:      "keep_alive_total",
			Help:      "Counter of keep alive.",
		})


	HandShakeErrorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "handshake_error_total",
			Help:      "Counter of hand shake error.",
		},
	)

	GetTokenDurationHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "get_token_duration_seconds",
			Help:      "Duration (us) for getting token, it should be small until concurrency limit is reached.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 26), // 1us ~ 67s
		})

	TotalQueryProcHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "slow_query_process_duration_seconds",
			Help:      "Bucketed histogram of processing time (s) of of slow queries.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 22), // 1ms ~ 4096s
		})

	CPUUsagePercentageGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "cpu_usage",
			Help:      "Percentage of CPU usage.",
		})
)

// ExecuteErrorToLabel converts an execute error to label.
//func ExecuteErrorToLabel(err error) string {
//	err = errors.Cause(err)
//	switch x := err.(type) {
//	case *terror.Error:
//		return x.Class().String() + ":" + strconv.Itoa(int(x.Code()))
//	default:
//		return "unknown"
//	}
//}
