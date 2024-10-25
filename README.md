# wialon_ips_exporter

Wialon IPS 1.0 protocol [PCAP based](https://github.com/gopacket/gopacket) Prometheus metrics exporter.

Service traces raw packets using pcap library, parses packets, and then serves metrics:

```text
# HELP wialon_ips_packets_total Total number of IPS packets
# TYPE wialon_ips_packets_total counter
wialon_ips_packets_total{dst_ip="188.123.45.67",src_ip="192.168.1.1",type="AD"} 72
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="188.123.45.67",type="D"} 72
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="212.45.6.123",type="B"} 7
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="212.45.6.123",type="L"} 4
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="217.14.123.45",type="D"} 2172
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="217.14.123.45",type="L"} 12
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="77.12.12.34",type="D"} 1337
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="77.12.12.34",type="L"} 33
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="77.74.12.123",type="D"} 608
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="77.74.12.123",type="L"} 3
wialon_ips_packets_total{dst_ip="212.45.6.123",src_ip="192.168.1.1",type="AB"} 7
wialon_ips_packets_total{dst_ip="212.45.6.123",src_ip="192.168.1.1",type="AL"} 4
wialon_ips_packets_total{dst_ip="217.14.123.45",src_ip="192.168.1.1",type="AD"} 2170
wialon_ips_packets_total{dst_ip="217.14.123.45",src_ip="192.168.1.1",type="AL"} 12
wialon_ips_packets_total{dst_ip="77.12.12.34",src_ip="192.168.1.1",type="AD"} 1405
wialon_ips_packets_total{dst_ip="77.12.12.34",src_ip="192.168.1.1",type="AL"} 33
wialon_ips_packets_total{dst_ip="77.74.12.123",src_ip="192.168.1.1",type="AD"} 609
wialon_ips_packets_total{dst_ip="77.74.12.123",src_ip="192.168.1.1",type="AL"} 3
# HELP wialon_ips_raw_packets_total Total number of packets handled
# TYPE wialon_ips_raw_packets_total counter
wialon_ips_raw_packets_total 6125
# HELP wialon_ips_stream_live_seconds Time stream lives
# TYPE wialon_ips_stream_live_seconds summary
wialon_ips_stream_live_seconds{quantile="0.5"} 0.163256668
wialon_ips_stream_live_seconds{quantile="0.9"} 44.797984672
wialon_ips_stream_live_seconds{quantile="0.95"} 45.078907945
wialon_ips_stream_live_seconds{quantile="0.99"} 60.21588069
wialon_ips_stream_live_seconds_sum 459.7408658289999
wialon_ips_stream_live_seconds_count 27
# HELP wialon_ips_streams_size Number of currently active streams
# TYPE wialon_ips_streams_size gauge
wialon_ips_streams_size 298
```

## Install

```bash
apt-get update
apt-get install libpcap0.8 libc6 libpcap-dev gcc

git clone git@github.com:artembaikuzin/wialon_ips_exporter.git

cd wialon_ips_exporter

go build .

mv wialon_ips_exporter /usr/local/bin/wialon_ips_exporter

cp init/wialon_ips_exporter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wialon_ips_exporter.service

systemctl start wialon_ips_exporter.service
```
