"""Configuration: one YAML file, sane defaults, per-engine toggles.

Example ``aegis.yml``::

    brand_domain: example.com
    alert_threshold: 40.0
    dry_run: true
    engines:
      typo_watch: {enabled: true}
      auth_watch: {enabled: true, fail_threshold: 8, window_minutes: 10}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a hard dependency
    yaml = None


@dataclass
class AegisConfig:
    brand_domain: str = "example.com"
    alert_threshold: float = 40.0
    dry_run: bool = True
    state_dir: str = "state"
    engines: dict = field(default_factory=dict)

    def engine_enabled(self, name: str) -> bool:
        cfg = self.engines.get(name, {})
        return bool(cfg.get("enabled", True))

    def engine_options(self, name: str) -> dict:
        cfg = dict(self.engines.get(name, {}))
        cfg.pop("enabled", None)
        return cfg


def load_config(path: str | Path) -> AegisConfig:
    """Load an AegisConfig from a YAML file. Missing file → defaults."""
    path = Path(path)
    if not path.exists():
        return AegisConfig()
    if yaml is None:
        raise RuntimeError("pyyaml is required to load config files")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AegisConfig(
        brand_domain=data.get("brand_domain", "example.com"),
        alert_threshold=float(data.get("alert_threshold", 40.0)),
        dry_run=bool(data.get("dry_run", True)),
        state_dir=data.get("state_dir", "state"),
        engines=data.get("engines", {}) or {},
    )
