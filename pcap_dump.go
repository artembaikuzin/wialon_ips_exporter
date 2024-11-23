package main

import (
	"log/slog"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type PcapDump struct {
	log          *slog.Logger
	metrics      *PrometheusMetrics
	streamParser *StreamParser
}

func NewPcapDump(log *slog.Logger, metrics *PrometheusMetrics, streamParser *StreamParser) *PcapDump {
	return &PcapDump{log: log, metrics: metrics, streamParser: streamParser}
}

func (p PcapDump) Run(iface string, pbfFilter string) {
	p.log.Info("Start PCAP OpenLive", "iface", iface, "pbfFilter", pbfFilter)

	pcapHandle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)

	if err != nil {
		p.log.Error("pcap.OpenLive error", "err", err)
		return
	}

	defer pcapHandle.Close()

	err = pcapHandle.SetBPFFilter(pbfFilter)

	if err != nil {
		p.log.Error("SetBPFFilter error", "err", err)
		return
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

		p.streamParser.ParsePayload(
			ip4.SrcIP.String(),
			uint16(tcp.SrcPort),
			ip4.DstIP.String(),
			uint16(tcp.DstPort),
			app.Payload())

		p.metrics.TotalRawPackets.Inc()
	}
}
