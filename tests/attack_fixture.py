"""Mini-bundle ATT&CK v20.0 (STIX valide, chargé par stix2.MemoryStore) pour les tests : quelques techniques, un groupe, des logiciels, des procédures, une révocation."""

import tempfile
from pathlib import Path

from backend.stix.attack import AttackKB, build_index, load_store


MITRE = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
STAMP = {"spec_version": "2.1", "created": "2020-01-01T00:00:00.000Z", "modified": "2026-05-01T00:00:00.000Z", "created_by_ref": MITRE}


def _ref(aid: str) -> list[dict]:
    return [{"source_name": "mitre-attack", "external_id": aid}]


def _tech(uid: str, aid: str, name: str, tactic: str, desc: str, **extra) -> dict:
    return {
        "type": "attack-pattern", "id": f"attack-pattern--{uid}", **STAMP, "name": name, "description": desc,
        "external_references": _ref(aid), "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
        "x_mitre_is_subtechnique": "." in aid, "x_mitre_platforms": ["Windows"], **extra,
    }  # fmt: skip


def _uses(n: int, src: str, dst: str, desc: str = "") -> dict:
    rel = {"type": "relationship", "id": f"relationship--{n:08d}-0000-4000-8000-000000000000", **STAMP, "relationship_type": "uses", "source_ref": src, "target_ref": dst}
    return {**rel, "description": desc} if desc else rel


U = "0000-4000-8000-000000000000"
OBJECTS = [
    {"type": "identity", "id": MITRE, "spec_version": "2.1", "created": "2017-06-01T00:00:00.000Z", "modified": "2017-06-01T00:00:00.000Z", "name": "The MITRE Corporation", "identity_class": "organization"},
    {"type": "x-mitre-collection", "id": f"x-mitre-collection--00000000-{U}", "name": "Enterprise ATT&CK", "x_mitre_version": "20.0"},
    {"type": "x-mitre-tactic", "id": f"x-mitre-tactic--00000001-{U}", "name": "Execution", "x_mitre_shortname": "execution", "external_references": _ref("TA0002")},
    {"type": "x-mitre-tactic", "id": f"x-mitre-tactic--00000002-{U}", "name": "Discovery", "x_mitre_shortname": "discovery", "external_references": _ref("TA0007")},
    _tech(f"00000010-{U}", "T1059", "Command and Scripting Interpreter", "execution", "Adversaries may abuse command and script interpreters to execute commands.(Citation: X)"),
    _tech(f"00000011-{U}", "T1059.001", "PowerShell", "execution", "Adversaries may abuse PowerShell commands and scripts for execution."),
    _tech(f"00000012-{U}", "T1059.003", "Windows Command Shell", "execution", "Adversaries may abuse the Windows command shell for execution."),
    _tech(f"00000013-{U}", "T1082", "System Information Discovery", "discovery", "An adversary may attempt to get detailed information about the operating system and hardware."),
    _tech(f"00000014-{U}", "T1086", "PowerShell", "execution", "Old PowerShell.", revoked=True),
    {"type": "intrusion-set", "id": f"intrusion-set--00000020-{U}", **STAMP, "name": "APT38", "aliases": ["APT38", "Stardust Chollima"], "external_references": _ref("G0082"), "description": "North Korean group."},
    {"type": "malware", "id": f"malware--00000030-{U}", **STAMP, "name": "Cobalt Strike", "is_family": True, "x_mitre_aliases": ["Cobalt Strike"], "external_references": _ref("S0154"), "description": "Commercial framework."},
    {"type": "tool", "id": f"tool--00000031-{U}", **STAMP, "name": "cmd", "x_mitre_aliases": ["cmd", "cmd.exe"], "external_references": _ref("S0106"), "description": "Windows command-line interpreter."},
    _uses(1, f"malware--00000030-{U}", f"attack-pattern--00000013-{U}", "[Cobalt Strike](https://attack.mitre.org/software/S0154) can run systeminfo to enumerate the host."),
    _uses(2, f"tool--00000031-{U}", f"attack-pattern--00000012-{U}", "[cmd](https://attack.mitre.org/software/S0106) is used to execute programs."),
    _uses(3, f"intrusion-set--00000020-{U}", f"malware--00000030-{U}"),
    {"type": "relationship", "id": f"relationship--00000009-{U}", **STAMP, "relationship_type": "revoked-by", "source_ref": f"attack-pattern--00000014-{U}", "target_ref": f"attack-pattern--00000011-{U}"},
    # Anciennes mitigations dépréciées qui reprennent l'identifiant de leur technique, comme dans le bundle officiel
    {"type": "course-of-action", "id": f"course-of-action--00000040-{U}", **STAMP, "name": "System Information Discovery Mitigation", "x_mitre_deprecated": True, "external_references": _ref("T1082")},
    {"type": "course-of-action", "id": f"course-of-action--00000041-{U}", **STAMP, "name": "Command and Scripting Interpreter Mitigation", "x_mitre_deprecated": True, "external_references": _ref("T1059")},
]


def mini_kb() -> AttackKB:
    """Index construit dans un dossier temporaire (supprimé à la fin du processus de test)."""
    tmp = Path(tempfile.mkdtemp(prefix="attack_kb_"))
    build_index(load_store(OBJECTS), tmp / "kb.sqlite")
    return AttackKB(tmp / "kb.sqlite")
