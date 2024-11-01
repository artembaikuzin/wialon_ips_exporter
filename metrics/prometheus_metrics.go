package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetricser interface {
	Metrics() *PrometheusMetrics
}

type PrometheusMetrics struct {
	PacketCounter      *prometheus.CounterVec
	ParseErrorsCounter *prometheus.CounterVec
	StreamsGauge       prometheus.Gauge
	TotalRawPackets    prometheus.Counter
}

func NewPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{
		PacketCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wialon_ips_packets_total",
			Help: "Total number of IPS packets",
		}, []string{"type", "src_ip", "dst_ip"}),

		ParseErrorsCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wialon_ips_parse_errors_total",
			Help: "Total number of parse errors",
		}, []string{"src_ip", "dst_ip"}),

		StreamsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wialon_ips_streams_size",
			Help: "Number of currently active streams",
		}),

		TotalRawPackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wialon_ips_raw_packets_total",
			Help: "Total number of packets handled",
		}),
	}
}

func (m PrometheusMetrics) Metrics() *PrometheusMetrics {
	return &m
}

func (m PrometheusMetrics) StartMetricsExporting(metricsAddr string) {
	log.Println("Serve prometheus metrics on", metricsAddr)

	prometheus.MustRegister(m.PacketCounter)
	prometheus.MustRegister(m.ParseErrorsCounter)
	prometheus.MustRegister(m.StreamsGauge)
	prometheus.MustRegister(m.TotalRawPackets)

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		err := http.ListenAndServe(metricsAddr, nil)

		if err != nil {
			panic(err)
		}
	}()
}
