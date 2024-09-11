package main

import (
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/adaricorp/tc-cpumap/tc"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
)

var (
	listenAddr    *[]string
	metricsPath   *string
	webConfigFile *string
	logger        *slog.Logger
)

// Print program usage
func printUsage(fs ff.Flags) {
	fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
	os.Exit(1)
}

// Print program version
func printVersion() {
	fmt.Printf("tc_cpumap_exporter v%s built on %s\n", version.Version, version.BuildDate)
	os.Exit(0)
}

func init() {
	defaultLogLevel := "info"
	logLevels := []string{defaultLogLevel}
	for _, l := range promslog.LevelFlagOptions {
		if l == defaultLogLevel {
			continue
		}
		logLevels = append(logLevels, l)
	}

	fs := ff.NewFlagSet("tc_cpumap_exporter")
	displayVersion := fs.BoolLong("version", "Print version")
	listenAddr = fs.StringSetLong(
		"web.listen-address",
		"Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. (default: :9812)",
	)
	metricsPath = fs.StringLong(
		"web.telemetry-path",
		"/metrics",
		"Path under which to expose metrics.",
	)
	webConfigFile = fs.StringLong(
		"web.config.file",
		"",
		"Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md",
	)
	logLevel := fs.StringEnumLong(
		"log.level",
		fmt.Sprintf(
			"Only log messages with the given severity or above. (valid options: %s)",
			strings.Join(logLevels, ", "),
		),
		logLevels...,
	)
	logFormat := fs.StringEnumLong(
		"log.format",
		fmt.Sprintf(
			"Output format of log messages. (valid options: %s)",
			strings.Join(promslog.FormatFlagOptions, ", "),
		),
		promslog.FormatFlagOptions...,
	)

	err := ff.Parse(fs, os.Args[1:])

	if err != nil {
		printUsage(fs)
	}

	if *displayVersion {
		printVersion()
	}

	logConfig := &promslog.Config{
		Level:  &promslog.AllowedLevel{},
		Format: &promslog.AllowedFormat{},
	}
	if err := logConfig.Level.Set(*logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting log level: %v\n", err)
	}
	if err := logConfig.Format.Set(*logFormat); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting log format: %v\n", err)
	}
	logger = promslog.New(logConfig)

	if len(*listenAddr) == 0 {
		// Set default value
		listenAddr = &[]string{":9812"}
	}
}

func main() {
	webConfig := web.FlagConfig{
		WebListenAddresses: listenAddr,
		WebConfigFile:      webConfigFile,
	}

	logger.Info(
		"Starting tc_cpumap_exporter",
		"version", version.Info(),
		"build_context", version.BuildContext(),
	)

	var tcHandleNames tc.TcHandleNames
	if _, err := os.Stat(tc.TC_CLASS_FILE); err == nil {
		tcHandleNames, err = tc.ParseTcClassFile(tc.TC_CLASS_FILE)
		if err != nil {
			logger.Error("Error parsing TC class names", "error", err.Error())
		}
	}

	versionCollector := versioncollector.NewCollector("tc_cpumap")
	prometheus.MustRegister(versionCollector)

	tcCpumapCollector := newTcCpumapCollector(logger, tcHandleNames)
	prometheus.MustRegister(tcCpumapCollector)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(
			[]byte(`<html>
<head><title>tc-cpumap exporter</title></head>
<body>
<h1>tc-cpumap exporter</h1>
<p><a href='` + *metricsPath + `'>Metrics</a></p>
<h2>Build</h2>
<pre>` + version.Info() + ` ` + version.BuildContext() + `</pre>
</body>
</html>`)); err != nil {
			logger.Error("Error writing HTTP response", "error", err.Error())
		}
	})

	srv := &http.Server{}
	if err := web.ListenAndServe(srv, &webConfig, logger); err != nil {
		logger.Error("Error starting HTTP server", "error", err.Error())
		os.Exit(1)
	}
}
