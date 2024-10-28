package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	StreamStart = iota
	StreamReadPacketType
	StreamSkipMessage
)

type StreamState struct {
	state      int
	packetType string

	createdAt    time.Time
	lastAccessAt time.Time
	mux          sync.Mutex

	ipv4 *layers.IPv4
	tcp  *layers.TCP
}

var streams sync.Map

var (
	packetCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wialon_ips_packets_total",
		Help: "Total number of IPS packets",
	}, []string{"type", "src_ip", "dst_ip"})

	parseErrorsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wialon_ips_parse_errors_total",
		Help: "Total number of parse errors",
	}, []string{"src_ip", "dst_ip"})

	streamLiveSeconds = prometheus.NewSummary(prometheus.SummaryOpts{
		Name:       "wialon_ips_stream_live_seconds",
		Help:       "Time stream lives",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001},
	})

	streamsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "wialon_ips_streams_size",
		Help: "Number of currently active streams",
	})

	totalRawPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "wialon_ips_raw_packets_total",
		Help: "Total number of packets handled",
	})
)

// Wialon IPS 1.0 packet types, https://extapi.wialon.com/hw/cfg/Wialon%20IPS_en.pdf
var clientPackets = []string{"L", "D", "P", "SD", "B", "I"}
var serverPackets = []string{"AL", "AD", "AP", "ASD", "AB", "AM", "AI", "US", "UC"}
var serverAndClientPackets = []string{"M"}

const packetTypeMaxLen = 3

const staleStreamTTLMinutes = 5.0

func packetTypeValid(value string) bool {
	return slices.Contains(clientPackets, value) ||
		slices.Contains(serverPackets, value) ||
		slices.Contains(serverAndClientPackets, value)
}

// Message format:
//
// #TP#msg\r\n
//
// # - start byte
// TP - type of packet
// # - separator
// msg - message
// \r\n - 0x0d0a
func parsePayload(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) {
	streamId := fmt.Sprintf("%v:%v-%v:%v", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)

	s, loaded := streams.LoadOrStore(
		streamId,
		&StreamState{createdAt: time.Now(), ipv4: ipv4, tcp: tcp})

	stream := s.(*StreamState)

	stream.mux.Lock()
	defer stream.mux.Unlock()

	stream.lastAccessAt = time.Now()
	if !loaded {
		streamsGauge.Inc()

		log.Println("Stream ADDED:", streamId)
	}

	for _, c := range string(payload) {
		switch stream.state {
		case StreamStart:
			if c == '#' {
				stream.state = StreamReadPacketType
				stream.packetType = ""
			}

		case StreamReadPacketType:
			if c == '#' {
				if !packetTypeValid(stream.packetType) {
					log.Println("(!) Invalid packet type:", stream.packetType)

					parseErrorsCounter.WithLabelValues(
						ipv4.SrcIP.String(),
						ipv4.DstIP.String(),
					).Inc()

					stream.state = StreamSkipMessage

					continue
				}

				packetCounter.WithLabelValues(
					stream.packetType,
					ipv4.SrcIP.String(),
					ipv4.DstIP.String(),
				).Inc()

				stream.state = StreamSkipMessage

				continue
			}

			stream.packetType = stream.packetType + string(c)

			if len(stream.packetType) > packetTypeMaxLen {
				log.Println("(!) Error parsing packet type:", stream.packetType)

				parseErrorsCounter.WithLabelValues(
					ipv4.SrcIP.String(),
					ipv4.DstIP.String(),
				).Inc()

				stream.state = StreamStart
			}

		case StreamSkipMessage:
			if c == '\r' || c == '\n' {
				stream.state = StreamStart
			}
		}
	}
}

func pruneStaleStreams() {
	log.Println("Prune stale streams")

	streams.Range(func(k any, v any) bool {
		stream := v.(*StreamState)

		stream.mux.Lock()

		if time.Now().Sub(stream.lastAccessAt).Minutes() > staleStreamTTLMinutes {
			livedSeconds := stream.lastAccessAt.Sub(stream.createdAt).Seconds()
			streamLiveSeconds.Observe(livedSeconds)

			streams.Delete(k)

			log.Printf("Stream DELETED: %s, lived for %fs", k.(string), livedSeconds)
			streamsGauge.Dec()
		}

		stream.mux.Unlock()

		return true
	})

	log.Println("Prune stale streams OK")
}

func startPruningStaleStreams() {
	ticker := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				pruneStaleStreams()
			}
		}
	}()
}

func startMetricsExporting(metricsAddr string) {
	log.Println("Serve prometheus metrics on", metricsAddr)

	prometheus.MustRegister(packetCounter)
	prometheus.MustRegister(parseErrorsCounter)
	prometheus.MustRegister(streamLiveSeconds)
	prometheus.MustRegister(streamsGauge)
	prometheus.MustRegister(totalRawPackets)

	http.Handle("/metrics", promhttp.Handler())

	go http.ListenAndServe(metricsAddr, nil)
}

func main() {
	var iface = flag.String("i", "eth0", "Interface")
	var pbfFilter = flag.String("filter", "tcp port 20332", "BPF filter")
	var metricsAddr = flag.String("metrics-listen-address", "0.0.0.0:9332", "Prometheus exporter metrics listen address")

	flag.Parse()

	startMetricsExporting(*metricsAddr)
	startPruningStaleStreams()

	log.Printf("Start PCAP OpenLive: interface=%s, filter=%s\n", *iface, *pbfFilter)

	pcapHandle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	defer pcapHandle.Close()

	err = pcapHandle.SetBPFFilter(*pbfFilter)

	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	for packet := range packetSource.Packets() {
		ip4 := packet.NetworkLayer().(*layers.IPv4)

		if ip4 == nil {
			continue
		}

		tcp := packet.TransportLayer().(*layers.TCP)

		if tcp == nil {
			continue
		}

		app := packet.ApplicationLayer()

		if app == nil {
			continue
		}

		parsePayload(ip4, tcp, app.Payload())
		totalRawPackets.Inc()
	}
}
