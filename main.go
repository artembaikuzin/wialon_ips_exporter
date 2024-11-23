package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
)

var version = "dev"

func main() {
	var iface = flag.String("i", "eth0", "Interface")
	var pbfFilter = flag.String("filter", "tcp port 20332", "BPF filter")
	var metricsAddr = flag.String("metrics-listen-address", "0.0.0.0:9332", "Prometheus exporter metrics listen address")

	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	log.Info("Wialon IPS exporter", "version", version)

	prometheus := NewPrometheusMetrics(log)
	prometheus.StartMetricsExporting(*metricsAddr)

	streamParser := NewStreamParser(log, prometheus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamParser.StartPruningStaleStreams(ctx)

	pcapDump := NewPcapDump(log, prometheus, streamParser)
	pcapDump.Run(*iface, *pbfFilter)
}
