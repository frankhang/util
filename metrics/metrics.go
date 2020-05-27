package metrics

import "github.com/prometheus/client_golang/prometheus"

// Label constants.
const (
	LblUnretryable = "unretryable"
	LblReachMax    = "reach_max"
	LblOK          = "ok"
	LblError       = "error"
	LblCommit      = "commit"
	LblAbort       = "abort"
	LblRollback    = "rollback"
	LblComRol      = "com_rol"
	LblType        = "type"
	LblDb          = "db"
	LblResult      = "result"
	LblSQLType     = "sql_type"
	LblGeneral     = "general"
	LblInternal    = "internal"
	LblStore       = "store"
	LblAddress     = "address"
)


var (
	// PanicCounter measures the count of panics.
	PanicCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "frank",
			Subsystem: "server",
			Name:      "panic_total",
			Help:      "Counter of panic.",
		}, []string{LblType})
)

// metrics labels.
const (
	LabelSession   = "session"
	LabelDomain    = "domain"
	LabelDDLOwner  = "ddl-owner"
	LabelDDL       = "ddl"
	LabelDDLSyncer = "ddl-syncer"
	LabelGCWorker  = "gcworker"
	LabelAnalyze   = "analyze"

	LabelBatchRecvLoop = "batch-recv-loop"
	LabelBatchSendLoop = "batch-send-loop"

	opSucc   = "ok"
	opFailed = "err"

	LableScope   = "scope"
	ScopeGlobal  = "global"
	ScopeSession = "session"
)

// RetLabel returns "ok" when err == nil and "err" when err != nil.
// This could be useful when you need to observe the operation result.
func RetLabel(err error) string {
	if err == nil {
		return opSucc
	}
	return opFailed
}

// RegisterMetrics registers the metrics which are ONLY used in TiDB server.
func RegisterMetrics() {
	prometheus.MustRegister(AutoAnalyzeCounter)
	prometheus.MustRegister(AutoAnalyzeHistogram)
	prometheus.MustRegister(ConnGauge)
	prometheus.MustRegister(CriticalErrorCounter)
	prometheus.MustRegister(DumpFeedbackCounter)
	prometheus.MustRegister(GetTokenDurationHistogram)
	prometheus.MustRegister(HandShakeErrorCounter)
	prometheus.MustRegister(SignificantFeedbackCounter)
	prometheus.MustRegister(FastAnalyzeHistogram)
	prometheus.MustRegister(KeepAliveCounter)
	prometheus.MustRegister(PanicCounter)
	prometheus.MustRegister(PseudoEstimation)
	prometheus.MustRegister(ServerEventCounter)
	prometheus.MustRegister(StatsInaccuracyRate)
	prometheus.MustRegister(StoreQueryFeedbackCounter)
	prometheus.MustRegister(GetStoreLimitErrorCounter)
	prometheus.MustRegister(TimeJumpBackCounter)
	prometheus.MustRegister(UpdateStatsCounter)
	prometheus.MustRegister(TotalQueryProcHistogram)
	prometheus.MustRegister(CPUUsagePercentageGauge)
}
