# wialon_ips_exporter

![ci workflow](https://github.com/artembaikuzin/wialon_ips_exporter/actions/workflows/ci.yml/badge.svg?branch=main)

[Wialon IPS 1.0](https://wialon.com/en/gps-hardware/soft/wialon-ips) protocol [PCAP based](https://github.com/gopacket/gopacket) parser and Prometheus metrics exporter service

Grafana dashboard based on the metrics:

![Grafana dashboard](assets/grafana_dashboard1.png)

![Grafana dashboard](assets/grafana_dashboard2.png)

Exported metrics:

```text
# HELP wialon_ips_packets_total Total number of IPS packets
# TYPE wialon_ips_packets_total counter
wialon_ips_packets_total{dst_ip="188.123.45.67",src_ip="192.168.1.1",type="AD"} 72
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="188.123.45.67",type="D"} 72
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="212.45.6.123",type="B"} 7
wialon_ips_packets_total{dst_ip="192.168.1.1",src_ip="212.45.6.123",type="L"} 4

# HELP wialon_ips_raw_packets_total Total number of packets handled
# TYPE wialon_ips_raw_packets_total counter
wialon_ips_raw_packets_total 6125

# HELP wialon_ips_streams_size Number of currently active streams
# TYPE wialon_ips_streams_size gauge
wialon_ips_streams_size 298

# HELP wialon_ips_streams_by_ip_size Number of currently active streams by src_ip and dst_ip
# TYPE wialon_ips_streams_by_ip_size gauge
wialon_ips_streams_by_ip_size{dst_ip="192.168.1.1",src_ip="188.123.45.67"} 34

# HELP wialon_ips_parse_errors_total Total number of parse errors
# TYPE wialon_ips_parse_errors_total counter
wialon_ips_parse_errors_total{dst_ip="192.168.1.1",src_ip="188.123.45.67"} 1
```

## Install

Build locally on the target host:

```bash
apt-get update
apt-get install libpcap0.8 libc6 libpcap-dev gcc

git clone git@github.com:artembaikuzin/wialon_ips_exporter.git

cd wialon_ips_exporter

make build
```

Setup and run:

```bash
mv wialon_ips_exporter /usr/local/bin/wialon_ips_exporter

cp init/wialon_ips_exporter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wialon_ips_exporter.service

systemctl start wialon_ips_exporter.service
```

### Prometheus

Define prometheus scrape config:

```yml
scrape_configs:
  - job_name: wialon-ips
    static_configs:
      - targets: ['wialon-production-host:9332']
        labels:
          instance: 'production'
```

Reload configuration:

```bash
prometheus kill -HUP 1
```

### Grafana

1. Configure prometheus datasource
2. Import [grafana/Wialon IPS Exporter.json](grafana/Wialon%20IPS%20Exporter.json) dashboard
