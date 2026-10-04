#!/usr/bin/env python3
"""Curate the security-category rules from a pinned opengrep-rules checkout into one bundle.

Usage: curate.py RULES_CHECKOUT OUTPUT_DIR [EXCLUDE_IDS_FILE]
Deterministic: same checkout + exclusions -> byte-identical rules.yml.
"""
import pathlib, sys, yaml

SKIP_TOP = {".github", "stats", "scripts", "problem-based-packs", "trusted_python", "ai", "libsonnet", "ocaml", "elixir", "clojure", "apex", "solidity"}
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
exclude = set()
if len(sys.argv) > 3:
    exclude = {l.split("#")[0].strip() for l in pathlib.Path(sys.argv[3]).read_text().splitlines() if l.split("#")[0].strip()}
rules, seen = [], set()
for path in sorted(src.rglob("*.y*ml")):
    rel = path.relative_to(src)
    if rel.parts[0] in SKIP_TOP or len(rel.parts) < 2 or ".test." in path.name or path.suffix not in (".yaml", ".yml"):
        continue
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        continue
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        continue
    for rule in doc["rules"]:
        meta = rule.get("metadata") or {}
        if meta.get("category") != "security" or meta.get("deprecated") or rule.get("options", {}).get("interfile"):
            continue
        rid = ".".join(rel.with_suffix("").parts[:-1] + (rule["id"],))
        if rid in seen or rid in exclude:
            continue
        seen.add(rid)
        rules.append({**rule, "id": rid})
rules.sort(key=lambda r: r["id"])
out.mkdir(parents=True, exist_ok=True)
(out / "rules.yml").write_text(yaml.safe_dump({"rules": rules}, sort_keys=True, allow_unicode=True, width=1_000_000))
print(f"{len(rules)} rules", file=sys.stderr)
