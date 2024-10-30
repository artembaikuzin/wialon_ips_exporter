package main

import (
	"flag"

	"github.com/artembaikuzin/wialon_ips_exporter/ips"
	"github.com/artembaikuzin/wialon_ips_exporter/metrics"
	"github.com/artembaikuzin/wialon_ips_exporter/pcap"
)

func main() {
	var iface = flag.String("i", "eth0", "Interface")
	var pbfFilter = flag.String("filter", "tcp port 20332", "BPF filter")
	var metricsAddr = flag.String("metrics-listen-address", "0.0.0.0:9332", "Prometheus exporter metrics listen address")

	flag.Parse()

	prometheus := metrics.NewPrometheusMetrics()
	prometheus.StartMetricsExporting(*metricsAddr)

	streamParser := ips.NewStreamParser(prometheus)
	streamParser.StartPruningStaleStreams()

	pcapDump := pcap.NewPcapDump(prometheus, streamParser)
	pcapDump.Run(*iface, *pbfFilter)
}
