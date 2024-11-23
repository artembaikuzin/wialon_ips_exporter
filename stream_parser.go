package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

type StreamParser struct {
	log     *slog.Logger
	metrics *PrometheusMetrics
	streams *sync.Map
}

func NewStreamParser(log *slog.Logger, metrics *PrometheusMetrics) *StreamParser {
	return &StreamParser{log: log, metrics: metrics, streams: &sync.Map{}}
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

	srcIp string
	dstIp string

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

	s, loaded := i.streams.LoadOrStore(
		streamId,
		&Stream{srcIp: srcIp, dstIp: dstIp, createdAt: time.Now(), lastAccessAt: time.Now()})

	stream := s.(*Stream)

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if !loaded {
		i.metrics.StreamsGauge.Inc()
		i.metrics.StreamsBySrcIp.WithLabelValues(srcIp, dstIp).Inc()

		i.log.Debug("Stream ADDED", "streamId", streamId)
	} else {
		stream.lastAccessAt = time.Now()
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
					i.log.Error("Invalid packet type", "stream.packetType", stream.packetType, "streamId", streamId)

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
				i.log.Error("Error parsing packet type", "stream.packetType", stream.packetType, "streamId", streamId)

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
	i.log.Debug("Pruning stale streams")

	i.streams.Range(func(k any, v any) bool {
		stream := v.(*Stream)

		stream.mu.Lock()

		if time.Since(stream.lastAccessAt).Minutes() > staleStreamTTLMinutes {
			livedSeconds := stream.lastAccessAt.Sub(stream.createdAt).Seconds()

			i.streams.Delete(k)

			i.log.Debug("Stream DELETED", "streamId", k.(string), "livedSeconds", livedSeconds)

			i.metrics.StreamsBySrcIp.WithLabelValues(stream.srcIp, stream.dstIp).Dec()
			i.metrics.StreamsGauge.Dec()
		}

		stream.mu.Unlock()

		return true
	})

	i.log.Debug("Pruning stale streams OK")
}
