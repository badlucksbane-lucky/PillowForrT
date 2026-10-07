# Grafana dashboard

`stone-of-heimdall.json` reads `/metrics` through Prometheus (or VictoriaMetrics, Grafana Agent, anything that speaks the text format).

1. Scrape the box. `/metrics` needs no login and is served on the LAN at `http://192.168.1.254/metrics`, `http://192.168.1.1:3128/metrics` and on the HTTPS page:
   ```yaml
   scrape_configs:
     - job_name: stone-of-heimdall
       scrape_interval: 30s
       static_configs:
         - targets: ["192.168.1.254:80"]
   ```
2. In Grafana: Dashboards -> New -> Import -> upload the JSON, pick your Prometheus data source.

The metrics are aggregate only (no device names, MACs or addresses), so the dashboard is too. Counters reset when tinyfwd restarts, which `rate()` handles.
Per-device detail is behind the login; for events as they happen use the event stream or syslog (see "Feeding other tools" in `docs/INSTALL.md`).
