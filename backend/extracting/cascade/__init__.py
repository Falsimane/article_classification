"""Extraction en cascade (CTI_CASCADE=on) : graphe d'entités, grappes par porteur, techniques tactique par tactique.

Chaque appel au modèle est contraint par un schéma généré depuis le registre STIX (`stix/specs.py`) et ATT&CK v20 : le modèle
choisit dans des listes fermées, le code écrit les objets STIX. Plan : docs/superpowers/plans/2026-11-11-extraction-en-cascade.md
"""
