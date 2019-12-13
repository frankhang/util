package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics
var (
	NewSessionHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "tidb",
			Subsystem: "owner",
			Name:      "new_session_duration_seconds",
			Help:      "Bucketed histogram of processing time (s) of new session.",
			Buckets:   prometheus.ExponentialBuckets(0.0005, 2, 22), // 500us ~ 2097s
		}, []string{LblType, LblResult})

	WatcherClosed     = "watcher_closed"
	Cancelled         = "cancelled"
	Deleted           = "deleted"
	SessionDone       = "session_done"
	CtxDone           = "context_done"
	WatchOwnerCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "owner",
			Name:      "watch_owner_total",
			Help:      "Counter of watch owner.",
		}, []string{LblType, LblResult})

	NoLongerOwner        = "no_longer_owner"
	CampaignOwnerCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "owner",
			Name:      "campaign_owner_total",
			Help:      "Counter of campaign owner.",
		}, []string{LblType, LblResult})
)
