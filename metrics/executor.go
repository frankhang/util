package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ExecutorCounter records the number of expensive executors.
	ExecutorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "executor",
			Name:      "expensive_total",
			Help:      "Counter of Expensive Executors.",
		}, []string{LblType},
	)

	// StmtNodeCounter records the number of statement with the same type.
	StmtNodeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "executor",
			Name:      "statement_total",
			Help:      "Counter of StmtNode.",
		}, []string{LblType})

	// DbStmtNodeCounter records the number of statement with the same type and db.
	DbStmtNodeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tidb",
			Subsystem: "executor",
			Name:      "statement_db_total",
			Help:      "Counter of StmtNode by Database.",
		}, []string{LblDb, LblType})
)
