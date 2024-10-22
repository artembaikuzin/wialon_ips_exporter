package main

import (
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Packet format:
// #TP#msg\r\n
//
// # - start byte
// TP - type of packet
// # - separator
// msg - message
// \r\n - 0x0d0a
//
// Tracker packet types:
// L - Login
// D - Data packet
// P - Ping(heartbeat) packet
// SD - Short data packet
// B - Blackbox packet
// M - Message to driver
// I - Packet with photo

const (
	ParserInit = iota
	ParserStartByte
	ParserPacketType
	ParserSeparator
	ParserMessage
)

type State struct {
	currentState  int
	currentPacket string
	lastAccessAt  time.Time
}

var parserState = make(map[string]*State)
var parserStateLock = sync.Mutex{}

func parsePackets(stream string, payload string) {
	parserStateLock.Lock()
	state, streamExists := parserState[stream]

	if !streamExists {
		state = &State{}
		parserState[stream] = state
	}

	state.lastAccessAt = time.Now()

	parserStateLock.Unlock()

	for _, c := range payload {
		switch state.currentState {
		case ParserInit:
			if c == '#' {
				state.currentState = ParserPacketType
			}

		case ParserPacketType:
			if c == '#' {
				state.currentState = ParserMessage

				fmt.Printf("+%s\n", state.currentPacket)

				state.currentPacket = ""

				continue
			}

			// TODO: use builder here
			state.currentPacket = state.currentPacket + string(c)

		case ParserMessage:
			if c == '\r' || c == '\n' {
				state.currentState = ParserInit
			}
		}
	}
}

func pruneParserState() {
	fmt.Println("pruneParserState")

	parserStateLock.Lock()
	defer parserStateLock.Unlock()

	for stream, state := range parserState {
		if time.Now().Sub(state.lastAccessAt).Minutes() > 5.0 {
			delete(parserState, stream)
			fmt.Printf("(!) Stream %s disconnected\n", stream)
		}
	}
}

func startPruneParser() {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				pruneParserState()
			}
		}
	}()
}

func connectionStream(tcp *layers.TCP, ip4 *layers.IPv4) string {
	return fmt.Sprintf("%v:%v-%v:%v", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
}

func main() {
	var iface = flag.String("i", "eth0", "Interface")
	var pbfFilter = flag.String("f", "tcp port 20332", "BPF filter")
	flag.Parse()

	startPruneParser()

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
		payload := string(app.Payload())
		stream := connectionStream(tcp, ip4)

		fmt.Println(stream)
		fmt.Println(payload)

		parsePackets(stream, payload)
	}
}
