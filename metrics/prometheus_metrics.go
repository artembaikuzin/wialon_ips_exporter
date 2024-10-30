package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetricser interface {
	GetMetrics() *PrometheusMetrics
}

type PrometheusMetrics struct {
	PacketCounter      *prometheus.CounterVec
	ParseErrorsCounter *prometheus.CounterVec
	StreamLiveSeconds  prometheus.Summary
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

		StreamLiveSeconds: prometheus.NewSummary(prometheus.SummaryOpts{
			Name:       "wialon_ips_stream_live_seconds",
			Help:       "Time stream lives",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001},
		}),

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

func (m PrometheusMetrics) GetMetrics() *PrometheusMetrics {
	return &m
}

func (m PrometheusMetrics) StartMetricsExporting(metricsAddr string) {
	log.Println("Serve prometheus metrics on", metricsAddr)

	prometheus.MustRegister(m.PacketCounter)
	prometheus.MustRegister(m.ParseErrorsCounter)
	prometheus.MustRegister(m.StreamLiveSeconds)
	prometheus.MustRegister(m.StreamsGauge)
	prometheus.MustRegister(m.TotalRawPackets)

	http.Handle("/metrics", promhttp.Handler())

	go http.ListenAndServe(metricsAddr, nil)
}
