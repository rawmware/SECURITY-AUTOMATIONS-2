"""Aegis command-line interface.

Commands:
    aegis engines                          list the engine fleet
    aegis scan --config aegis.yml --out findings.json
    aegis serve --host 0.0.0.0 --port 8000 --config aegis.yml
    aegis version
"""

from __future__ import annotations

import argparse
import json
import sys

from aegis import __version__
from aegis.config import AegisConfig, load_config
from aegis.engines import engine_names, get_engine, load_engines
from aegis.runner import ScanRunner


def _load_config_or_default(path: str | None) -> AegisConfig:
    if path:
        return load_config(path)
    return AegisConfig()


def cmd_engines(args: argparse.Namespace) -> int:
    """List registered engines with descriptions."""
    try:
        load_engines()
    except ImportError:
        pass
    config = _load_config_or_default(args.config)
    for name in engine_names():
        cls = get_engine(name)
        desc = (getattr(cls, "description", "") or "").strip()
        ver = getattr(cls, "version", "?")
        state = "enabled" if config.engine_enabled(name) else "disabled"
        print(f"{name} v{ver} [{state}]")
        if desc:
            print(f"    {desc}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a scan and write findings JSON to --out (or stdout)."""
    config = _load_config_or_default(args.config)
    runner = ScanRunner(config)
    result = runner.run(targets=json.loads(args.targets or "{}"))
    payload = {
        "findings": [f.to_dict() for f in result["findings"]],
        "scored": [s.to_dict() for s in result["scored"]],
        "cases": [c.to_dict() for c in result["cases"]],
        "engines_run": result["engines_run"],
        "errors": result["errors"],
    }
    text = json.dumps(payload, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {len(result['findings'])} findings to {args.out}")
    else:
        print(text)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the Aegis API with uvicorn."""
    import uvicorn

    from aegis.api import create_app

    config = _load_config_or_default(args.config)
    uvicorn.run(
        create_app(config),
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


def cmd_version(args: argparse.Namespace) -> int:  # noqa: ARG001
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis security automation")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("engines", help="list the engine fleet")
    p.add_argument("--config", default=None, help="path to aegis.yml")
    p.set_defaults(func=cmd_engines)

    p = sub.add_parser("scan", help="run a scan and emit findings JSON")
    p.add_argument("--config", default=None, help="path to aegis.yml")
    p.add_argument("--targets", default="{}",
                   help='JSON object of scan targets, e.g. \'{"brand_domain":"acme.com"}\'')
    p.add_argument("--out", default=None, help="output file (default: stdout)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("serve", help="serve the Aegis HTTP API")
    p.add_argument("--config", default=None, help="path to aegis.yml")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("version", help="print the Aegis version")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Console-script entry point (``aegis=aegis.cli:main``)."""
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
