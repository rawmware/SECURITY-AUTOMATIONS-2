# Aegis 2.0.0 — API Reference

FastAPI application, built by `aegis.api.server.create_app()`. The router
(`aegis/api/routes.py`) is mounted with **no `/api` prefix** — routes are
exactly as listed below. OpenAPI docs are served by FastAPI at `/docs`
when the server runs.

Start it:

```bash
uvicorn aegis.api.server:create_app --factory --host 0.0.0.0 --port 8000
```

State is in-memory per process: `findings`, `cases`, `alerts`,
`playbook_runs`. Restarting the server clears them (persistent reports go
to `reports/` — see `DEPLOYMENT.md`).

## Routes

| method | path | what it does |
|---|---|---|
| GET | `/health` | Liveness: `{"status": "ok", "version", "engines"}` |
| GET | `/engines` | Engine fleet: name, version, description, enabled |
| POST | `/scan` | Run all enabled engines + pipeline on targets |
| GET | `/findings` | List stored findings; filter `?severity=` `?engine=` |
| GET | `/cases` | List correlated cases |
| GET | `/cases/{case_id}` | One case (404 if unknown) |
| GET | `/alerts` | List dispatched alerts |
| POST | `/soar/run` | Execute (or dry-run) a playbook |
| WS | `/stream` | Live findings as JSON; 30s heartbeat |

## Examples

```bash
# Fleet status
curl localhost:8000/health
# {"status":"ok","version":"2.0.0","engines":12}

# Which engines are on
curl localhost:8000/engines | python3 -m json.tool

# Run a scan
curl -X POST localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"targets": {"brand_domain": "example.com"}}'

# Findings from one engine, high severity and up
curl 'localhost:8000/findings?engine=auth_watch&severity=high'

# Cases, then one case in detail
curl localhost:8000/cases
curl localhost:8000/cases/case_9f3a2c

# Alerts that went out
curl localhost:8000/alerts

# Dry-run a playbook (default), or execute for real
curl -X POST localhost:8000/soar/run \
  -H 'Content-Type: application/json' \
  -d '{"playbook": "brute-force-block",
       "trigger": {"case_id": "case_9f3a2c"},
       "dry_run": true}'
```

## JSON shapes

`Finding.to_dict()`:

```json
{
  "id": "find_4b7e1a",
  "engine": "typo_watch",
  "title": "Registered lookalike domain: examp1e.com",
  "severity": "high",
  "score": 82.5,
  "entities": {"domain": "examp1e.com", "variant_of": "example.com"},
  "evidence": {"techniques": ["homoglyph"], "ct_logged": true},
  "recommendation": "File a takedown request with the registrar.",
  "tags": ["typosquat", "brand-abuse"],
  "ts": "2026-10-03T18:00:00+00:00"
}
```

`Case.to_dict()`:

```json
{
  "id": "case_9f3a2c",
  "title": "Phishing campaign impersonating example.com",
  "severity": "high",
  "score": 81.0,
  "status": "open",
  "entities": {"domain": "examp1e.com", "ip": "203.0.113.44"},
  "narrative": "typo_watch found a registered lookalike; url_intel scored
a phishing URL on it; phish_kit fingerprinted a credential harvester.",
  "finding_ids": ["find_4b7e1a", "find_9c02dd"],
  "ts": "2026-10-03T18:05:00+00:00"
}
```

After the scoring stage, findings also carry `adjusted_score`,
`adjusted_severity`, and `score_factors` (the `ScoredFinding` contract —
see `PIPELINE.md`). `PlaybookRun.to_dict()` carries `playbook`,
`dry_run`, `status`, `trigger`, `steps`, `id`, `ts`.

## Websocket stream

Connect to `/stream` to receive every finding the runner publishes on the
bus's `findings` topic, as JSON, plus a heartbeat every 30 seconds:

```python
import asyncio, websockets, json

async def watch():
    async with websockets.connect("ws://localhost:8000/stream") as ws:
        async for msg in ws:
            print(json.loads(msg)["title"])

asyncio.run(watch())
```

The websocket subscribes via `bus.subscribe("findings", ...)` and
unsubscribes on disconnect — no polling, no missed events while connected.
The web UI in `aegis-build/web/` is built on this stream.
