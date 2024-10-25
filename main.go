package main

import (
	"flag"
	"fmt"
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

type StreamData struct {
	id   string
	ipv4 *layers.IPv4
	tcp  *layers.TCP
}

type StreamState struct {
	state  int
	packet string

	createdAt    time.Time
	lastAccessAt time.Time
	mux          sync.Mutex
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

const packetMaxLen = 2

const staleStreamTTLMinutes = 5.0

func packetValid(value string) bool {
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
func parsePayload(streamData *StreamData, payload string) {
	s, loaded := streams.LoadOrStore(streamData.id, &StreamState{})
	stream := s.(*StreamState)

	stream.mux.Lock()
	defer stream.mux.Unlock()

	stream.lastAccessAt = time.Now()
	if !loaded {
		stream.createdAt = time.Now()
		streamsGauge.Inc()
	}

	for _, c := range payload {
		switch stream.state {
		case StreamStart:
			if c == '#' {
				stream.state = StreamReadPacketType
				stream.packet = ""
			}

		case StreamReadPacketType:
			if c == '#' {
				if !packetValid(stream.packet) {
					fmt.Printf("(!) Invalid packet: %s\n", stream.packet)

					parseErrorsCounter.WithLabelValues(
						streamData.ipv4.SrcIP.String(),
						streamData.ipv4.DstIP.String(),
					).Inc()

					stream.state = StreamSkipMessage

					continue
				}

				fmt.Printf("+%s\n", stream.packet)

				packetCounter.WithLabelValues(
					stream.packet,
					streamData.ipv4.SrcIP.String(),
					streamData.ipv4.DstIP.String(),
				).Inc()

				stream.state = StreamSkipMessage

				continue
			}

			stream.packet = stream.packet + string(c)

			if len(stream.packet) > packetMaxLen {
				fmt.Println("(!) Error parsing packet:", stream.packet)

				parseErrorsCounter.WithLabelValues(
					streamData.ipv4.SrcIP.String(),
					streamData.ipv4.DstIP.String(),
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
	fmt.Println("pruneStaleStreams")

	streams.Range(func(k any, v any) bool {
		stream := v.(*StreamState)

		stream.mux.Lock()

		if time.Now().Sub(stream.lastAccessAt).Minutes() > staleStreamTTLMinutes {
			streams.Delete(k)
			fmt.Printf("(!) Stream %s DELETED\n", k.(string))

			streamLiveSeconds.Observe(stream.lastAccessAt.Sub(stream.createdAt).Seconds())
			streamsGauge.Dec()
		}

		stream.mux.Unlock()

		return true
	})
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
	fmt.Println("Metrics served on", metricsAddr)

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

	fmt.Println("start OpenLive")

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

		fmt.Println("----------------------------------------------------------------------------------------------------")
		streamData := &StreamData{
			id:   fmt.Sprintf("%v:%v-%v:%v", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort),
			ipv4: ip4,
			tcp:  tcp,
		}

		payload := string(app.Payload())

		fmt.Println(streamData.id)
		fmt.Println(payload)

		parsePayload(streamData, payload)

		totalRawPackets.Inc()
	}
}
