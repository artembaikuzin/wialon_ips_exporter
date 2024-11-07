package ips

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/artembaikuzin/wialon_ips_exporter/metrics"
)

type StreamParser struct {
	metrics *metrics.PrometheusMetrics
	streams *sync.Map
}

type StreamParserer interface {
	ParsePayload(srcIp string, srcPort uint16, dstIp string, dstPort uint16, payload []byte)
}

func NewStreamParser(metrics metrics.PrometheusMetricser) *StreamParser {
	return &StreamParser{metrics: metrics.Metrics(), streams: &sync.Map{}}
}

type streamState int

const (
	streamStart streamState = iota
	streamReadPacketType
	streamSkipMessage
	streamInvalidPacketType
	streamErrorPacketType
)

type Stream struct {
	state      streamState
	packetType string

	createdAt    time.Time
	lastAccessAt time.Time
	mu           sync.Mutex
}

// Wialon IPS 1.0 packet types: https://extapi.wialon.com/hw/cfg/Wialon%20IPS_en.pdf
var clientPackets = []string{"L", "D", "P", "SD", "B", "I"}
var serverPackets = []string{"AL", "AD", "AP", "ASD", "AB", "AM", "AI", "US", "UC"}
var serverAndClientPackets = []string{"M"}

const packetTypeMaxLen = 3

const staleStreamTTLMinutes = 5.0

// Message format:
//
// #TP#msg\r\n
//
// # - start byte
// TP - type of packet
// # - separator
// msg - message
// \r\n - 0x0d0a
func (i StreamParser) ParsePayload(srcIp string, srcPort uint16, dstIp string, dstPort uint16, payload []byte) {
	streamId := i.streamId(srcIp, srcPort, dstIp, dstPort)

	s, loaded := i.streams.LoadOrStore(streamId, &Stream{createdAt: time.Now()})

	stream := s.(*Stream)

	stream.mu.Lock()
	defer stream.mu.Unlock()

	stream.lastAccessAt = time.Now()

	if !loaded {
		i.metrics.StreamsGauge.Inc()

		log.Println("Stream ADDED:", streamId)
	}

	for _, c := range string(payload) {
		switch stream.state {
		case streamStart, streamInvalidPacketType, streamErrorPacketType:
			if c == '#' {
				stream.state = streamReadPacketType
				stream.packetType = ""
			}

		case streamReadPacketType:
			if c == '#' {
				if !i.packetTypeValid(stream.packetType) {
					log.Println("(!) Invalid packet type:", stream.packetType)

					i.metrics.ParseErrorsCounter.WithLabelValues(srcIp, dstIp).Inc()
					stream.state = streamInvalidPacketType

					continue
				}

				i.metrics.PacketCounter.WithLabelValues(stream.packetType, srcIp, dstIp).Inc()
				stream.state = streamSkipMessage

				continue
			}

			stream.packetType = stream.packetType + string(c)

			if len(stream.packetType) > packetTypeMaxLen {
				log.Println("(!) Error parsing packet type:", stream.packetType)

				i.metrics.ParseErrorsCounter.WithLabelValues(srcIp, dstIp).Inc()
				stream.state = streamErrorPacketType
			}

		case streamSkipMessage:
			if c == '\r' || c == '\n' {
				stream.state = streamStart
			}
		}
	}
}

func (i StreamParser) StartPruningStaleStreams(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				i.pruneStaleStreams()
			}
		}
	}()
}

func (i StreamParser) streamId(srcIp string, srcPort uint16, dstIp string, dstPort uint16) string {
	return fmt.Sprintf("%v:%v-%v:%v", srcIp, srcPort, dstIp, dstPort)
}

func (i StreamParser) packetTypeValid(value string) bool {
	return slices.Contains(clientPackets, value) ||
		slices.Contains(serverPackets, value) ||
		slices.Contains(serverAndClientPackets, value)
}

func (i StreamParser) pruneStaleStreams() {
	log.Println("Prune stale streams")

	i.streams.Range(func(k any, v any) bool {
		stream := v.(*Stream)

		stream.mu.Lock()

		if time.Since(stream.lastAccessAt).Minutes() > staleStreamTTLMinutes {
			livedSeconds := stream.lastAccessAt.Sub(stream.createdAt).Seconds()

			i.streams.Delete(k)

			log.Printf("Stream DELETED: %s, lived for %fs", k.(string), livedSeconds)
			i.metrics.StreamsGauge.Dec()
		}

		stream.mu.Unlock()

		return true
	})

	log.Println("Prune stale streams OK")
}
