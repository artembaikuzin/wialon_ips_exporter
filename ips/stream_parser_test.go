package ips

import (
	"testing"

	"github.com/artembaikuzin/wialon_ips_exporter/metrics"
)

func TestParsePayload(t *testing.T) {
	streamParser := NewStreamParser(metrics.NewPrometheusMetrics())

	testPackets := []struct {
		srcIp        string
		srcPort      uint16
		dstIp        string
		dstPort      uint16
		payload      string
		expectState  int
		expectPacket string
	}{
		{"192.168.1.1", 20332, "77.74.56.123", 12345, "", streamStart, ""},
		{"192.168.1.1", 20332, "77.74.56.123", 12345, "#A", streamReadPacketType, "A"},
		{"192.168.1.1", 20332, "77.74.56.123", 12345, "D#", streamSkipMessage, "AD"},

		{"77.74.56.123", 12345, "192.168.1.1", 20332, "#SD#messag", streamSkipMessage, "SD"},

		{"192.168.1.1", 20332, "77.74.56.123", 12345, "no_message\r\n", streamStart, "AD"},

		{"12.34.56.123", 777, "192.168.1.1", 20332, "#D#track_message_body\r\n", streamStart, "D"},

		{"192.168.1.1", 20332, "77.74.56.123", 12345, "#WRONGPACKET\r\n", streamErrorPacketType, "WRON"},

		{"77.74.56.123", 12345, "192.168.1.1", 20332, "e_body\r\n", streamStart, "SD"},

		{"192.168.1.1", 20332, "77.74.56.123", 12345, "#Z#invalid packet\r\n", streamInvalidPacketType, "Z"},
	}

	for _, tt := range testPackets {
		streamParser.ParsePayload(tt.srcIp, tt.srcPort, tt.dstIp, tt.dstPort, []byte(tt.payload))

		streamId := streamParser.streamId(tt.srcIp, tt.srcPort, tt.dstIp, tt.dstPort)
		s, ok := streamParser.streams.Load(streamId)

		if !ok {
			t.Fatalf("Stream not found: %s", streamId)
		}

		stream := s.(*StreamState)

		if stream.state != tt.expectState {
			t.Fatalf("Invalid state for stream: %s, expected=%d, got=%d", streamId, tt.expectState, stream.state)
		}

		if stream.packetType != tt.expectPacket {
			t.Fatalf("Invalid packet type for stream: %s, expected=%s, got=%s", streamId, tt.expectPacket, stream.packetType)
		}
	}

	streamSize := 0
	streamParser.streams.Range(func(key, value any) bool {
		streamSize += 1
		return true
	})

	if streamSize != 3 {
		t.Fatalf("Invalid number of streams: expected=%d, got=%d", 3, streamSize)
	}
}
