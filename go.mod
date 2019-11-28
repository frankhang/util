module mod-demo

go 1.13

//replace github.com/frankhang/util/check => github.com/tiancaiamao/check v0.0.0-20191119042138-8e73d07b629d

//replace github.com/frankhang/util => /Users/hang/go/src/github.com/frankhang/util

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/blacktear23/go-proxyprotocol v0.0.0-20180807104634-af7a81e8dd0d
	github.com/frankhang/util v0.0.0-00010101000000-000000000000
	github.com/gorilla/mux v1.7.3
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pingcap/errors v0.11.4
	github.com/pingcap/failpoint v0.0.0-20191029060244-12f4ac2fd11d
	github.com/pingcap/fn v0.0.0-20191016082858-07623b84a47d
	github.com/pingcap/parser v0.0.0-20191127110312-37cd7d635816
	github.com/pingcap/tidb v2.0.11+incompatible
	github.com/prometheus/client_golang v1.2.1
	github.com/tiancaiamao/appdash v0.0.0-20181126055449-889f96f722a2
	github.com/uber/jaeger-client-go v2.20.1+incompatible
	go.uber.org/atomic v1.5.1
	go.uber.org/zap v1.13.0
	sourcegraph.com/sourcegraph/appdash-data v0.0.0-20151005221446-73f23eafcf67
)
