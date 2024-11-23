package main

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	log                *slog.Logger
	PacketCounter      *prometheus.CounterVec
	ParseErrorsCounter *prometheus.CounterVec
	StreamsGauge       prometheus.Gauge
	StreamsBySrcIp     *prometheus.GaugeVec
	TotalRawPackets    prometheus.Counter
}

func NewPrometheusMetrics(log *slog.Logger) *PrometheusMetrics {
	return &PrometheusMetrics{
		log: log,

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

		StreamsBySrcIp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wialon_ips_streams_by_ip_size",
			Help: "Number of currently active streams by src_ip and dst_ip",
		}, []string{"src_ip", "dst_ip"}),

		TotalRawPackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wialon_ips_raw_packets_total",
			Help: "Total number of packets handled",
		}),
	}
}

func (m PrometheusMetrics) StartMetricsExporting(metricsAddr string) {
	m.log.Info("Serving prometheus metrics", "metricsAddr", metricsAddr)

	prometheus.MustRegister(m.PacketCounter)
	prometheus.MustRegister(m.ParseErrorsCounter)
	prometheus.MustRegister(m.StreamsGauge)
	prometheus.MustRegister(m.StreamsBySrcIp)
	prometheus.MustRegister(m.TotalRawPackets)

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		if err := http.ListenAndServe(metricsAddr, nil); err != http.ErrServerClosed {
			m.log.Error("Prometheus http server error", "err", err)
		}
	}()
}
