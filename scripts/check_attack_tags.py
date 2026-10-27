#!/usr/bin/env python3
#"""Refuse toute règle Sentinel Scheduled ou NRT sans tags MITRE ATT&CK valides."""
import json
import pathlib
import re
import sys

TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "CommandAndControl", "Exfiltration", "Impact",
    "ImpairProcessControl", "InhibitResponseFunction", "PreAttack",
}
TECH = re.compile(r"^T\d{4}$")
SUBTECH = re.compile(r"^T\d{4}\.\d{3}$")

errors = []
files = sorted(pathlib.Path("AnalyticsRules").rglob("*.json"))
if not files:
    errors.append(("AnalyticsRules", "aucun fichier de règle trouvé"))

for f in files:
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        errors.append((str(f), f"JSON invalide : {e}"))
        continue
    for res in doc.get("resources", []):
        if not res.get("type", "").lower().endswith("alertrules"):
            continue
        if res.get("kind") not in ("Scheduled", "NRT"):
            continue
        p = res.get("properties", {})
        name = p.get("displayName", "(sans nom)")
        tactics = p.get("tactics") or []
        techs = p.get("techniques") or []
        subs = p.get("subTechniques") or []
        if not tactics:
            errors.append((str(f), f"{name} : aucune tactique ATT&CK"))
        for t in tactics:
            if t not in TACTICS:
                errors.append((str(f), f"{name} : tactique inconnue '{t}'"))
        if not techs:
            errors.append((str(f), f"{name} : aucune technique ATT&CK"))
        for t in techs:
            if not TECH.match(t):
                errors.append((str(f), f"{name} : technique mal formée '{t}' (attendu Txxxx)"))
        for s in subs:
            if not SUBTECH.match(s):
                errors.append((str(f), f"{name} : sous-technique mal formée '{s}' (attendu Txxxx.xxx)"))
            elif s.split(".")[0] not in techs:
                errors.append((str(f), f"{name} : '{s}' n'a pas sa technique parente dans techniques"))

for path, msg in errors:
    print(f"::error file={path}::{msg}")
if errors:
    sys.exit(1)
print(f"OK : {len(files)} fichier(s) de règle contrôlé(s)")

