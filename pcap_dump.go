package main

import (
	"log"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type PcapDump struct {
	metrics      *PrometheusMetrics
	streamParser *StreamParser
}

func NewPcapDump(metrics *PrometheusMetrics, streamParser *StreamParser) *PcapDump {
	return &PcapDump{metrics: metrics, streamParser: streamParser}
}

func (p PcapDump) Run(iface string, pbfFilter string) {
	log.Printf("Start PCAP OpenLive: interface=%s, filter=%s\n", iface, pbfFilter)

	pcapHandle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	defer pcapHandle.Close()

	err = pcapHandle.SetBPFFilter(pbfFilter)

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

		p.streamParser.ParsePayload(
			ip4.SrcIP.String(),
			uint16(tcp.SrcPort),
			ip4.DstIP.String(),
			uint16(tcp.DstPort),
			app.Payload())

		p.metrics.TotalRawPackets.Inc()
	}
}