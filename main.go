package main

import (
	"context"
	"flag"
)

func main() {
	var iface = flag.String("i", "eth0", "Interface")
	var pbfFilter = flag.String("filter", "tcp port 20332", "BPF filter")
	var metricsAddr = flag.String("metrics-listen-address", "0.0.0.0:9332", "Prometheus exporter metrics listen address")

	flag.Parse()

	prometheus := NewPrometheusMetrics()
	prometheus.StartMetricsExporting(*metricsAddr)

	streamParser := NewStreamParser(prometheus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamParser.StartPruningStaleStreams(ctx)

	pcapDump := NewPcapDump(prometheus, streamParser)
	pcapDump.Run(*iface, *pbfFilter)
}
