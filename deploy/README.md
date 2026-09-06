# Prism observability stack

One command brings up Prism, Prometheus, and a provisioned Grafana dashboard.

```bash
cd deploy
docker compose up --build
```

| Service | URL | Notes |
|---------|-----|-------|
| Grafana | http://localhost:3000 | dashboard **Prism** (anonymous viewer, or admin / admin) |
| Prometheus | http://localhost:9090 | scrapes `prism:9109` every 5s |
| Prism `/metrics` | http://localhost:9109/metrics | raw exposition |

`prism` replays [`test_dpi.pcap`](../test_dpi.pcap) on a loop (`--loop`) so the
counters keep moving. To watch real traffic instead, edit `docker-compose.yml`:

```yaml
  prism:
    command: --iface eth0 -o /dev/null --metrics 0.0.0.0:9109 --log-json
    cap_add: [NET_RAW, NET_ADMIN]
```

## Metrics

| metric | type | labels | engines |
|--------|------|--------|---------|
| `prism_packets_total` `prism_bytes_total` | counter | | all |
| `prism_tcp_packets_total` `prism_udp_packets_total` | counter | | all |
| `prism_forwarded_total` `prism_dropped_total` | counter | | all |
| `prism_queue_depth` | gauge | | `prism` |
| `prism_app_packets_total` | counter | `app` | `prism` |
| `prism_signature_label_flows` `prism_ja4_flows` | counter | `label` / `ja4` | `prism` |
| `prism_active_connections` | gauge | | `prism-classic` |
| `prism_app_connections` | gauge | `app` | `prism-classic` |

## Logs

`--log-json` emits one JSON object per line (`ts`, `level`, `comp`, `msg`) —
ready for Loki / any line-based collector. `--log-level trace|debug|info|warn|error|off`.
