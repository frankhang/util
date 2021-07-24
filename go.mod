module github.com/frankhang/util

go 1.15

//replace github.com/frankhang/util => /Users/hang/go/src/github.com/frankhang/util

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/golang/protobuf v1.4.2
	github.com/opentracing/opentracing-go v1.2.0
	github.com/pingcap/errors v0.11.4
	github.com/pingcap/parser v3.1.2+incompatible
	github.com/pingcap/tipb v0.0.0-20200813070854-57da1e63f73e // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/uber/jaeger-client-go v2.29.1+incompatible
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	go.uber.org/atomic v1.6.0
	go.uber.org/zap v1.16.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)
