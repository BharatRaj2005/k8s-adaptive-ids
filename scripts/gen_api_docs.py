"""Generate docs/API.md from the FastAPI OpenAPI schema (so it cannot drift from the code).

    .venv/bin/python scripts/gen_api_docs.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.backend.app import app  # noqa: E402

GROUPS = [("Health & metrics", ("/api/health", "/api/metrics", "/api/classes")),
          ("Detections", ("/api/detections", "/api/alerts", "/api/datasets", "/api/detection/")),
          ("Capture", ("/api/capture", "/api/captures")),
          ("Live security monitoring", ("/api/monitoring",)),
          ("Attack simulator", ("/api/simulations",)),
          ("Deception (MAPE-K)", ("/api/deception",)),
          ("Kubernetes & model", ("/api/kubernetes", "/api/model"))]


def schema_fields(spec: dict, ref: str) -> list[str]:
    comp = spec["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    req = set(comp.get("required", []))
    out = []
    for name, p in comp.get("properties", {}).items():
        typ = p.get("type") or " | ".join(x.get("type", "?") for x in p.get("anyOf", []))
        rng = ", ".join(f"{k} {p[k]}" for k in ("minimum", "maximum", "maxLength") if k in p)
        default = f", default `{json.dumps(p['default'])}`" if "default" in p else ""
        desc = f" — {p['description']}" if p.get("description") else ""
        out.append(f"  - `{name}` ({typ}{', required' if name in req else ''}{default}{', ' + rng if rng else ''}){desc}")
    return out


def main():
    spec = app.openapi()
    L = ["# API Reference", "",
         f"Generated from the FastAPI OpenAPI schema by `scripts/gen_api_docs.py` ({spec['info']['title']} "
         f"v{spec['info']['version']}). Interactive docs: `http://127.0.0.1:8000/docs` while the backend runs.", "",
         "Base URL: `http://127.0.0.1:8000`. All bodies are JSON. Errors return `{\"detail\": ...}` with 400 "
         "(invalid input), 404 (unknown file/model), 409 (conflict: capture already running, decoy already active), "
         "422 (schema validation), 503 (Kubernetes unavailable for a decoy operation) or 500 (logged internal error).",
         ""]
    done = set()
    for title, prefixes in GROUPS:
        L += [f"## {title}", ""]
        for path, ops in spec["paths"].items():
            if path in done or not path.startswith(prefixes):
                continue
            done.add(path)
            for method, op in ops.items():
                L.append(f"### `{method.upper()} {path}`")
                L.append("")
                doc = (op.get("description") or "").strip()
                if doc:
                    L += [doc, ""]
                params = op.get("parameters", [])
                if params:
                    L.append("Parameters:")
                    for p in params:
                        s = p.get("schema", {})
                        typ = s.get("type") or " | ".join(x.get("type", "?") for x in s.get("anyOf", []) if x.get("type") != "null")
                        enum = next((x.get("enum") for x in s.get("anyOf", []) if "enum" in x), s.get("enum"))
                        extra = ", ".join(f"{k} {s[k]}" for k in ("minimum", "maximum") if k in s)
                        L.append(f"  - `{p['name']}` ({p['in']}, {typ}{', one of ' + str(enum) if enum else ''}"
                                 f"{', default `' + json.dumps(s['default']) + '`' if 'default' in s else ''}"
                                 f"{', ' + extra if extra else ''})")
                body = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
                if "$ref" in body:
                    L.append("Body:")
                    L += schema_fields(spec, body["$ref"])
                L.append("")
    out = ROOT / "docs" / "API.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(L))
    print("wrote", out, f"({sum(len(v) for v in spec['paths'].values())} operations)")


if __name__ == "__main__":
    main()
