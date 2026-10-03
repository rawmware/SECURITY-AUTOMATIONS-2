"""SOAR playbook engine: load YAML playbooks, match them against triggers,
and execute their steps with entity-templated parameters."""

from __future__ import annotations

from pathlib import Path
from string import Formatter

import yaml

from aegis.models import SEVERITIES, PlaybookRun
from aegis.soar.actions import ACTIONS


class _SafeDict(dict):
    """Format-mapping that leaves unknown ``{placeholders}`` untouched."""

    def __missing__(self, key: str) -> str:  # noqa: D102
        return "{" + key + "}"


def _render(value, context: dict):
    """Render ``{placeholders}`` in a param value from trigger context."""
    if isinstance(value, str) and "{" in value:
        return Formatter().vformat(value, (), _SafeDict(context))
    return value


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return -1


class PlaybookEngine:
    """Load a library of YAML playbooks and run them against triggers."""

    def __init__(self, library_dir: str | Path | None = None) -> None:
        self.library: list[dict] = []
        if library_dir is not None:
            self.load_library(library_dir)

    # -- library ---------------------------------------------------------
    def load_library(self, directory: str | Path) -> list[dict]:
        """Parse every ``*.yml``/``*.yaml`` in ``directory``, validate each
        playbook's schema, and store the library. Raises ``ValueError`` on
        any invalid playbook."""
        path = Path(directory)
        files = sorted(
            list(path.glob("*.yml")) + list(path.glob("*.yaml")),
            key=lambda p: p.name,
        )
        playbooks = []
        for file in files:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
            self._validate(data, file.name)
            playbooks.append(data)
        self.library = playbooks
        return playbooks

    @staticmethod
    def _validate(pb: object, filename: str) -> None:
        def err(msg: str) -> ValueError:
            return ValueError(f"invalid playbook {filename}: {msg}")

        if not isinstance(pb, dict):
            raise err("top level must be a mapping")
        for key in ("name", "description", "trigger", "steps"):
            if key not in pb:
                raise err(f"missing required key {key!r}")
        if not isinstance(pb["name"], str) or not pb["name"].strip():
            raise err("'name' must be a non-empty string")

        trigger = pb["trigger"]
        if not isinstance(trigger, dict):
            raise err("'trigger' must be a mapping")
        engines = trigger.get("engines")
        if (
            not isinstance(engines, list)
            or not engines
            or not all(isinstance(e, str) and e.strip() for e in engines)
        ):
            raise err("'trigger.engines' must be a non-empty list of strings")
        min_sev = trigger.get("min_severity")
        if min_sev not in SEVERITIES:
            raise err(f"'trigger.min_severity' must be one of {SEVERITIES}")

        steps = pb["steps"]
        if not isinstance(steps, list) or not steps:
            raise err("'steps' must be a non-empty list")
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise err(f"step {i} must be a mapping")
            if not isinstance(step.get("action"), str) or not step["action"].strip():
                raise err(f"step {i} needs a non-empty 'action'")
            params = step.get("params", {})
            if not isinstance(params, dict):
                raise err(f"step {i} 'params' must be a mapping")
            approval = step.get("approval_required", False)
            if not isinstance(approval, bool):
                raise err(f"step {i} 'approval_required' must be a boolean")

    # -- matching ---------------------------------------------------------
    def match(self, trigger: dict) -> dict | None:
        """Return the first playbook whose trigger matches: the trigger's
        engine is listed and its severity meets ``min_severity``."""
        engine = trigger.get("engine")
        severity = trigger.get("severity")
        rank = _severity_rank(severity)
        if rank < 0:
            return None
        for pb in self.library:
            trg = pb["trigger"]
            if engine in trg["engines"] and rank >= _severity_rank(trg["min_severity"]):
                return pb
        return None

    # -- execution --------------------------------------------------------
    def run(self, playbook: dict, trigger: dict, dry_run: bool = True) -> PlaybookRun:
        """Execute a playbook's steps in order via ``ACTIONS``.

        Params are templated from the trigger (``{ip}``-style placeholders
        filled from ``trigger["entities"]``). Each recorded step carries
        ``{action, params, result, approval_required, approved}`` where
        ``approved`` is False when the step needed human approval. Unknown
        actions and action errors become error steps; the run continues and
        finishes with status ``'partial'``.
        """
        entities = dict(trigger.get("entities") or {})
        context = {
            "engine": trigger.get("engine"),
            "severity": trigger.get("severity"),
            **entities,
        }
        steps_out: list[dict] = []
        status = "completed"
        for step in playbook["steps"]:
            name = step["action"]
            rendered = {
                k: _render(v, context) for k, v in (step.get("params") or {}).items()
            }
            approval_required = bool(step.get("approval_required", False))
            approved = not approval_required
            fn = ACTIONS.get(name)
            try:
                if fn is None:
                    raise KeyError(f"unknown action '{name}'")
                result = fn(**rendered, dry_run=dry_run)["result"]
            except Exception as exc:  # noqa: BLE001 - recorded, run continues
                result = f"error: {exc}"
                status = "partial"
            steps_out.append(
                {
                    "action": name,
                    "params": rendered,
                    "result": result,
                    "approval_required": approval_required,
                    "approved": approved,
                }
            )
        return PlaybookRun(
            playbook=playbook["name"],
            trigger=trigger,
            steps=steps_out,
            dry_run=dry_run,
            status=status,
        )
