# Aegis 2.0.0 — Deployment

## Configuration reference

Copy `aegis.example.yml` to `aegis.yml` and edit. `AegisConfig`
(`aegis/config.py`) reads it.

| key | default | what it does |
|---|---|---|
| `brand_domain` | `"example.com"` | The domain the fleet protects (typo_watch, phish_kit, etc.) |
| `alert_threshold` | `40.0` | Adjusted score at or above which the alert stage notifies |
| `dry_run` | `true` | SOAR executes playbooks as simulations until set `false` with approvals |
| `state_dir` | `"state"` | Baselines, dedupe fingerprints, scan history |
| `engines.<id>.enabled` | `true` | Toggle each of the 12 engines |
| `engines.<id>.*` | — | Per-engine options (`fail_threshold`, `spray_users`, `max_candidates`, `min_score`, `alpha`, `allowlist`, …). Full list in `aegis.example.yml` |

`config.engine_enabled(name)` and `config.engine_options(name)` are how
engines read their section — engines never parse YAML themselves.

## Docker Compose

```yaml
# docker-compose.yml
services:
  aegis:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./aegis.yml:/app/aegis.yml:ro
      - aegis-state:/app/state
    command: uvicorn aegis.api.server:create_app --factory
             --host 0.0.0.0 --port 8000
    restart: unless-stopped

volumes:
  aegis-state:
```

```bash
docker compose up -d        # start
docker compose logs -f      # watch
```

Mount `aegis.yml` read-only; keep `state/` on a named volume so baselines
and dedupe fingerprints survive restarts.

## Kubernetes

Manifests live in `aegis-build/k8s/`:

- `deployment.yaml` — Deployment, 2 replicas, image
  `ghcr.io/rawmware/aegis:2.0.0`, container port 8000, environment from the
  `aegis-secrets` Secret (`envFrom.secretRef`), CPU/memory requests and limits.
- `service.yaml` — ClusterIP Service `aegis`, port 8000 → targetPort 8000.

Create the secret first (never commit it), then apply:

```bash
kubectl apply -f k8s/
kubectl get pods -l app=aegis
```

Put `aegis.yml` in the ConfigMap so config changes are a
`kubectl apply` away from rolling out. The API is stateless except for
`state/` — one replica per PVC, or share state via a ReadWriteMany volume.

## Scheduling scans

Scans don't self-schedule; the OS does. Two options:

**cron** — every 6 hours:

```cron
0 */6 * * * cd /opt/aegis && \
  ./venv/bin/python -m aegis.cli scan --config aegis.yml >> state/scan.log 2>&1
```

**systemd timer** — `aegis-scan.service` + `aegis-scan.timer`:

```ini
# /etc/systemd/system/aegis-scan.service
[Unit]
Description=Aegis scheduled scan

[Service]
Type=oneshot
WorkingDirectory=/opt/aegis
ExecStart=/opt/aegis/venv/bin/python -m aegis.cli scan --config aegis.yml
```

```ini
# /etc/systemd/system/aegis-scan.timer
[Unit]
Description=Run Aegis scan every 6 hours

[Timer]
OnCalendar=*:00/6:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now aegis-scan.timer
```

## State and reports

- `state/` — engine baselines (DNS, ports), dedupe fingerprints, scan
  history. Persistent; back it up. Point `state_dir` elsewhere if you
  want it on a different volume.
- `reports/` — per-run HTML/Markdown reports written after each scan:
  findings, adjusted scores, cases with narratives, playbook runs. This
  is the durable record — the API's in-memory stores are ephemeral.

## Checklist

1. Copy `aegis.example.yml` → `aegis.yml`; set `brand_domain`.
2. Tune `alert_threshold` (40.0 is a sane start; lower it if you're
   missing things, raise it if you're drowning).
3. Leave `dry_run: true` until you've reviewed a few simulated
   `PlaybookRun` records and are comfortable with live actions.
4. Bring up compose or k8s; hit `/health` and confirm 12 engines.
5. Schedule scans; verify `reports/` fills up after the first run.
