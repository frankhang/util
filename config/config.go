package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/frankhang/util/errors"
	zaplog "github.com/frankhang/util/log"
	"github.com/frankhang/util/logutil"
	tracing "github.com/uber/jaeger-client-go/config"
	"go.uber.org/atomic"
)

// Config number limitations
const (
	MaxLogFileSize = 4096 // MB
	// DefTxnTotalSizeLimit is the default value of TxnTxnTotalSizeLimit.
	DefTxnTotalSizeLimit = 100 * 1024 * 1024
)

// Valid config maps
var ()

// Config contains configuration options.
type Config struct {
	Host             string      `toml:"host" json:"host"`
	AdvertiseAddress string      `toml:"advertise-address" json:"advertise-address"`
	Port             uint        `toml:"port" json:"port"`
	ReadTimeout      uint        `toml:"read-timeout" json:"read-timeout"`
	WriteTimeout     uint        `toml:"write-timeout" json:"write-timeout"`
	TokenLimit       uint        `toml:"token-limit" json:"token-limit"`
	Log              Log         `toml:"log" json:"log"`
	Status           Status      `toml:"status" json:"status"`
	Performance      Performance `toml:"performance" json:"performance"`
	OpenTracing      OpenTracing `toml:"opentracing" json:"opentracing"`
}

// nullableBool defaults unset bool options to unset instead of false, which enables us to know if the user has set 2
// conflict options at the same time.
type nullableBool struct {
	IsValid bool
	IsTrue  bool
}

var (
	nbUnset = nullableBool{false, false}
	nbFalse = nullableBool{true, false}
	nbTrue  = nullableBool{true, true}
)

func (b *nullableBool) toBool() bool {
	return b.IsValid && b.IsTrue
}

func (b nullableBool) MarshalJSON() ([]byte, error) {
	switch b {
	case nbTrue:
		return json.Marshal(true)
	case nbFalse:
		return json.Marshal(false)
	default:
		return json.Marshal(nil)
	}
}

func (b *nullableBool) UnmarshalText(text []byte) error {
	str := string(text)
	switch str {
	case "", "null":
		*b = nbUnset
		return nil
	case "true":
		*b = nbTrue
	case "false":
		*b = nbFalse
	default:
		*b = nbUnset
		return errors.New("Invalid value for bool type: " + str)
	}
	return nil
}

func (b *nullableBool) UnmarshalJSON(data []byte) error {
	var err error
	var v interface{}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch raw := v.(type) {
	case bool:
		*b = nullableBool{true, raw}
	default:
		*b = nbUnset
	}
	return err
}

// Log is the log section of config.
type Log struct {
	// Log level.
	Level string `toml:"level" json:"level"`
	// Log format. one of json, text, or console.
	Format string `toml:"format" json:"format"`
	// Disable automatic timestamps in output. Deprecated: use EnableTimestamp instead.
	DisableTimestamp nullableBool `toml:"disable-timestamp" json:"disable-timestamp"`
	// EnableTimestamp enables automatic timestamps in log output.
	EnableTimestamp nullableBool `toml:"enable-timestamp" json:"enable-timestamp"`
	// DisableErrorStack stops annotating logs with the full stack error
	// message. Deprecated: use EnableErrorStack instead.
	DisableErrorStack nullableBool `toml:"disable-error-stack" json:"disable-error-stack"`
	// EnableErrorStack enables annotating logs with the full stack error
	// message.
	EnableErrorStack nullableBool `toml:"enable-error-stack" json:"enable-error-stack"`
	// File log config.
	File logutil.FileLogConfig `toml:"file" json:"file"`
}

func (l *Log) getDisableTimestamp() bool {
	if l.EnableTimestamp == nbUnset && l.DisableTimestamp == nbUnset {
		return false
	}
	if l.EnableTimestamp == nbUnset {
		return l.DisableTimestamp.toBool()
	}
	return !l.EnableTimestamp.toBool()
}

func (l *Log) getDisableErrorStack() bool {
	if l.EnableErrorStack == nbUnset && l.DisableErrorStack == nbUnset {
		return true
	}
	if l.EnableErrorStack == nbUnset {
		return l.DisableErrorStack.toBool()
	}
	return !l.EnableErrorStack.toBool()
}

// Security is the security section of the config.
type Security struct {
	SkipGrantTable bool   `toml:"skip-grant-table" json:"skip-grant-table"`
	SSLCA          string `toml:"ssl-ca" json:"ssl-ca"`
	SSLCert        string `toml:"ssl-cert" json:"ssl-cert"`
	SSLKey         string `toml:"ssl-key" json:"ssl-key"`
	ClusterSSLCA   string `toml:"cluster-ssl-ca" json:"cluster-ssl-ca"`
	ClusterSSLCert string `toml:"cluster-ssl-cert" json:"cluster-ssl-cert"`
	ClusterSSLKey  string `toml:"cluster-ssl-key" json:"cluster-ssl-key"`
}

// The ErrConfigValidationFailed error is used so that external callers can do a type assertion
// to defer handling of this specific error when someone does not want strict type checking.
// This is needed only because logging hasn't been set up at the time we parse the config file.
// This should all be ripped out once strict config checking is made the default behavior.
type ErrConfigValidationFailed struct {
	ConfFile       string
	UndecodedItems []string
}

func (e *ErrConfigValidationFailed) Error() string {
	return fmt.Sprintf("config file %s contained unknown configuration options: %s", e.ConfFile, strings.Join(e.UndecodedItems, ", "))
}

// ToTLSConfig generates tls's config based on security section of the config.
func (s *Security) ToTLSConfig() (*tls.Config, error) {
	var tlsConfig *tls.Config
	if len(s.ClusterSSLCA) != 0 {
		var certificates = make([]tls.Certificate, 0)
		if len(s.ClusterSSLCert) != 0 && len(s.ClusterSSLKey) != 0 {
			// Load the client certificates from disk
			certificate, err := tls.LoadX509KeyPair(s.ClusterSSLCert, s.ClusterSSLKey)
			if err != nil {
				return nil, errors.Errorf("could not load client key pair: %s", err)
			}
			certificates = append(certificates, certificate)
		}

		// Create a certificate pool from the certificate authority
		certPool := x509.NewCertPool()
		ca, err := ioutil.ReadFile(s.ClusterSSLCA)
		if err != nil {
			return nil, errors.Errorf("could not read ca certificate: %s", err)
		}

		// Append the certificates from the CA
		if !certPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("failed to append ca certs")
		}

		tlsConfig = &tls.Config{
			Certificates: certificates,
			RootCAs:      certPool,
		}
	}

	return tlsConfig, nil
}

// Status is the status section of the config.
type Status struct {
	StatusHost      string `toml:"status-host" json:"status-host"`
	MetricsAddr     string `toml:"metrics-addr" json:"metrics-addr"`
	StatusPort      uint   `toml:"status-port" json:"status-port"`
	MetricsInterval uint   `toml:"metrics-interval" json:"metrics-interval"`
	ReportStatus    bool   `toml:"report-status" json:"report-status"`
	RecordQPSbyDB   bool   `toml:"record-db-qps" json:"record-db-qps"`
}

// Performance is the performance section of the config.
type Performance struct {
	MaxProcs     uint   `toml:"max-procs" json:"max-procs"`
	MaxMemory    uint64 `toml:"max-memory" json:"max-memory"`
	TCPKeepAlive bool   `toml:"tcp-keep-alive" json:"tcp-keep-alive"`
}

// OpenTracing is the opentracing section of the config.
type OpenTracing struct {
	Enable     bool                `toml:"enable" json:"enable"`
	RPCMetrics bool                `toml:"rpc-metrics" json:"rpc-metrics"`
	Sampler    OpenTracingSampler  `toml:"sampler" json:"sampler"`
	Reporter   OpenTracingReporter `toml:"reporter" json:"reporter"`
}

// OpenTracingSampler is the config for opentracing sampler.
// See https://godoc.org/github.com/uber/jaeger-client-go/config#SamplerConfig
type OpenTracingSampler struct {
	Type                    string        `toml:"type" json:"type"`
	Param                   float64       `toml:"param" json:"param"`
	SamplingServerURL       string        `toml:"sampling-server-url" json:"sampling-server-url"`
	MaxOperations           int           `toml:"max-operations" json:"max-operations"`
	SamplingRefreshInterval time.Duration `toml:"sampling-refresh-interval" json:"sampling-refresh-interval"`
}

// OpenTracingReporter is the config for opentracing reporter.
// See https://godoc.org/github.com/uber/jaeger-client-go/config#ReporterConfig
type OpenTracingReporter struct {
	QueueSize           int           `toml:"queue-size" json:"queue-size"`
	BufferFlushInterval time.Duration `toml:"buffer-flush-interval" json:"buffer-flush-interval"`
	LogSpans            bool          `toml:"log-spans" json:"log-spans"`
	LocalAgentHostPort  string        `toml:"local-agent-host-port" json:"local-agent-host-port"`
}

var DefaultConf = Config{
	Host:             "0.0.0.0",
	AdvertiseAddress: "",
	Port:             10001,
	TokenLimit:       1000,
	ReadTimeout:      30,
	WriteTimeout:     30,

	Log: Log{
		Level:  "info",
		Format: "text",
		File:   logutil.NewFileLogConfig(logutil.DefaultLogMaxSize),
	},
	Status: Status{
		ReportStatus:    true,
		StatusHost:      "0.0.0.0",
		StatusPort:      10080,
		MetricsInterval: 15,
	},
	Performance: Performance{
		MaxMemory:    0,
		TCPKeepAlive: true,
	},

	OpenTracing: OpenTracing{
		Enable: false,
		Sampler: OpenTracingSampler{
			Type:  "const",
			Param: 1.0,
		},
		Reporter: OpenTracingReporter{},
	},
}

var (
	GlobalConf              = atomic.Value{}
	reloadConfPath          = ""
	confReloader            func(nc, c *Config)
	confReloadLock          sync.Mutex
	supportedReloadConfigs  = make(map[string]struct{}, 32)
	supportedReloadConfList = make([]string, 0, 32)
)

// NewConfig creates a new config instance with default value.
func NewConfig() *Config {
	conf := DefaultConf
	return &conf
}

// SetConfReloader sets reload config path and a reloader.
// It should be called only once at start time.
func SetConfReloader(cpath string, reloader func(nc, c *Config), confItems ...string) {
	reloadConfPath = cpath
	confReloader = reloader
	for _, item := range confItems {
		supportedReloadConfigs[item] = struct{}{}
		supportedReloadConfList = append(supportedReloadConfList, item)
	}
}

// GetGlobalConfig returns the global configuration for this server.
// It should store configuration from command line and configuration file.
// Other parts of the system can read the global configuration use this function.
func GetGlobalConfig() *Config {
	return GlobalConf.Load().(*Config)
}

// StoreGlobalConfig stores a new config to the GlobalConf. It mostly uses in the test to avoid some data races.
func StoreGlobalConfig(config *Config) {
	GlobalConf.Store(config)
}

// ReloadGlobalConfig reloads global configuration for this server.
func ReloadGlobalConfig() error {
	confReloadLock.Lock()
	defer confReloadLock.Unlock()

	nc := NewConfig()
	if err := nc.Load(reloadConfPath); err != nil {
		return err
	}
	if err := nc.Valid(); err != nil {
		return err
	}
	c := GetGlobalConfig()

	diffs := collectsDiff(*nc, *c, "")
	if len(diffs) == 0 {
		return nil
	}
	var formattedDiff bytes.Buffer
	for k, vs := range diffs {
		formattedDiff.WriteString(fmt.Sprintf(", %v:%v->%v", k, vs[1], vs[0]))
	}
	unsupported := make([]string, 0, 2)
	for k := range diffs {
		if _, ok := supportedReloadConfigs[k]; !ok {
			unsupported = append(unsupported, k)
		}
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("reloading config %v is not supported, only %v are supported now, "+
			"your changes%s", unsupported, supportedReloadConfList, formattedDiff.String())
	}

	confReloader(nc, c)
	GlobalConf.Store(nc)
	logutil.BgLogger().Info("reload config changes" + formattedDiff.String())
	return nil
}

// collectsDiff collects different config items.
// map[string][]string -> map[field path][]{new value, old value}
func collectsDiff(i1, i2 interface{}, fieldPath string) map[string][]interface{} {
	diff := make(map[string][]interface{})
	t := reflect.TypeOf(i1)
	if t.Kind() != reflect.Struct {
		if reflect.DeepEqual(i1, i2) {
			return diff
		}
		diff[fieldPath] = []interface{}{i1, i2}
		return diff
	}

	v1 := reflect.ValueOf(i1)
	v2 := reflect.ValueOf(i2)
	for i := 0; i < v1.NumField(); i++ {
		p := t.Field(i).Name
		if fieldPath != "" {
			p = fieldPath + "." + p
		}
		m := collectsDiff(v1.Field(i).Interface(), v2.Field(i).Interface(), p)
		for k, v := range m {
			diff[k] = v
		}
	}
	return diff
}

// Load loads config options from a toml file.
func (c *Config) Load(confFile string) error {
	metaData, err := toml.DecodeFile(confFile, c)
	if c.TokenLimit == 0 {
		c.TokenLimit = 1000
	}
	// If any items in ConfFile file are not mapped into the Config struct, issue
	// an error and stop the server from starting.
	undecoded := metaData.Undecoded()
	if len(undecoded) > 0 && err == nil {
		var undecodedItems []string
		for _, item := range undecoded {
			undecodedItems = append(undecodedItems, item.String())
		}
		err = &ErrConfigValidationFailed{confFile, undecodedItems}
	}

	return err
}

// Valid checks if this config is valid.
func (c *Config) Valid() error {
	if c.Log.EnableErrorStack == c.Log.DisableErrorStack && c.Log.EnableErrorStack != nbUnset {
		logutil.BgLogger().Warn(fmt.Sprintf("\"enable-error-stack\" (%v) conflicts \"disable-error-stack\" (%v). \"disable-error-stack\" is deprecated, please use \"enable-error-stack\" instead. disable-error-stack is ignored.", c.Log.EnableErrorStack, c.Log.DisableErrorStack))
		// if two options conflict, we will use the value of EnableErrorStack
		c.Log.DisableErrorStack = nbUnset
	}
	if c.Log.EnableTimestamp == c.Log.DisableTimestamp && c.Log.EnableTimestamp != nbUnset {
		logutil.BgLogger().Warn(fmt.Sprintf("\"enable-timestamp\" (%v) conflicts \"disable-timestamp\" (%v). \"disable-timestamp\" is deprecated, please use \"enable-timestamp\" instead", c.Log.EnableTimestamp, c.Log.DisableTimestamp))
		// if two options conflict, we will use the value of EnableTimestamp
		c.Log.DisableTimestamp = nbUnset
	}

	if c.Log.File.MaxSize > MaxLogFileSize {
		return fmt.Errorf("invalid max log file size=%v which is larger than max=%v", c.Log.File.MaxSize, MaxLogFileSize)
	}

	return nil
}

func hasRootPrivilege() bool {
	return os.Geteuid() == 0
}

// ToLogConfig converts *Log to *logutil.LogConfig.
func (l *Log) ToLogConfig() *logutil.LogConfig {
	return logutil.NewLogConfig(l.Level, l.Format, l.File, l.getDisableTimestamp(), func(config *zaplog.Config) { config.DisableErrorVerbose = l.getDisableErrorStack() })
}

// ToTracingConfig converts *OpenTracing to *tracing.Configuration.
func (t *OpenTracing) ToTracingConfig() *tracing.Configuration {
	ret := &tracing.Configuration{
		Disabled:   !t.Enable,
		RPCMetrics: t.RPCMetrics,
		Reporter:   &tracing.ReporterConfig{},
		Sampler:    &tracing.SamplerConfig{},
	}
	ret.Reporter.QueueSize = t.Reporter.QueueSize
	ret.Reporter.BufferFlushInterval = t.Reporter.BufferFlushInterval
	ret.Reporter.LogSpans = t.Reporter.LogSpans
	ret.Reporter.LocalAgentHostPort = t.Reporter.LocalAgentHostPort

	ret.Sampler.Type = t.Sampler.Type
	ret.Sampler.Param = t.Sampler.Param
	ret.Sampler.SamplingServerURL = t.Sampler.SamplingServerURL
	ret.Sampler.MaxOperations = t.Sampler.MaxOperations
	ret.Sampler.SamplingRefreshInterval = t.Sampler.SamplingRefreshInterval
	return ret
}

func init() {
	GlobalConf.Store(&DefaultConf)

}
