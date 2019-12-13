package tcp

import (
	"context"
	"fmt"
	"github.com/pingcap/tidb/config"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"time"

	"github.com/frankhang/util/logutil"

	"github.com/gorilla/mux"
	"github.com/pingcap/fn"
	"github.com/pingcap/parser/terror"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tiancaiamao/appdash/traceapp"
	"go.uber.org/zap"
	static "sourcegraph.com/sourcegraph/appdash-data"
)

const defaultStatusPort = 10080

func (s *Server) startStatusHTTP() {
	go s.startHTTPServer()
}

func serveError(w http.ResponseWriter, status int, txt string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Go-Pprof", "1")
	w.Header().Del("Content-Disposition")
	w.WriteHeader(status)
	_, err := fmt.Fprintln(w, txt)
	terror.Log(err)
}

func sleepWithCtx(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func (s *Server) startHTTPServer() {
	router := mux.NewRouter()

	// HTTP path for prometheus.
	router.Handle("/metrics", promhttp.Handler()).Name("Metrics")

	// HTTP path for dump statistics.

	// HTTP path for get the TiDB config
	router.Handle("/config", fn.Wrap(func() (*config.Config, error) {
		return config.GetGlobalConfig(), nil
	}))

	// HTTP path for get server info.

	// HTTP path for get db and table info that is related to the tableID.

	// HTTP path for get MVCC info

	// HTTP path for web UI.
	if host, port, err := net.SplitHostPort("localhost"); err == nil {
		if host == "" {
			host = "localhost"
		}
		baseURL := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%s", host, port),
		}
		router.HandleFunc("/web/trace", traceapp.HandleTiDB).Name("Trace Viewer")
		sr := router.PathPrefix("/web/trace/").Subrouter()
		if _, err := traceapp.New(traceapp.NewRouter(sr), baseURL); err != nil {
			logutil.BgLogger().Error("new failed", zap.Error(err))
		}
		router.PathPrefix("/static/").Handler(http.StripPrefix("/static", http.FileServer(static.Data)))
	}

	serverMux := http.NewServeMux()
	serverMux.Handle("/", router)

	serverMux.HandleFunc("/debug/pprof/", pprof.Index)
	serverMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	serverMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	serverMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	serverMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// status of TiDB.
type status struct {
	Connections int    `json:"connections"`
	Version     string `json:"version"`
	GitHash     string `json:"git_hash"`
}