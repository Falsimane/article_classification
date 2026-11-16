"""Contrôles de déclaration : binaires natifs, noms de fichiers, nom de l'article face à un alias ATT&CK. Noms absents des
articles annotés (vérifiés dans Annotations/)."""
import pytest

from backend.extracting.graph.draft import DraftGraph
from backend.extracting.stix.attack import attack_id
from backend.extracting.stix.objects import ArticleContext
from backend.preprocessing.cleaning.text.segment import segment

TEXT = "# Report\n\nThe operators ran several utilities on the host.\n"


@pytest.fixture
def draft():
    return DraftGraph(segment(TEXT), ArticleContext(1, "test-source", None, "t"))


def test_native_binary_without_attack_id_refused(draft):
    sid, err = draft.declare("tool|odbcconf.exe")
    assert sid is None and "binaire natif" in err


def test_native_binary_with_attack_id_is_tool(draft):
    sid, _ = draft.declare("tool|bitsadmin")
    assert attack_id(draft.objects[sid]) == "S0190"


def test_tool_exe_suffix_resolves_to_attack(draft):
    sid, _ = draft.declare("tool|bitsadmin.exe")
    assert attack_id(draft.objects[sid]) == "S0190"


def test_file_name_refused_as_malware(draft):
    sid, err = draft.declare("malware|alpha_loader.dll")
    assert sid is None and "nom de fichier" in err


def test_article_name_kept_over_attack_alias(draft):
    sid, _ = draft.declare("intrusion-set|Fancy Bear")
    obj = draft.objects[sid]
    assert obj["name"] == "Fancy Bear" and "APT28" in obj["aliases"] and attack_id(obj) == "G0007"


def test_case_variant_gives_official_object(draft):
    sid, _ = draft.declare("intrusion-set|apt28")
    assert sid == draft.attack.stix_object("G0007")["id"]


def test_alias_then_primary_same_object(draft):
    first, _ = draft.declare("intrusion-set|Fancy Bear")
    second, _ = draft.declare("intrusion-set|APT28")
    assert first == second and draft.resolve("G0007")[0] == first


def test_file_name_with_label_alias_keeps_label(draft):
    sid, err = draft.declare("malware|alpha_loader.dll|Alpha stage loader")
    assert err is None and draft.objects[sid]["name"] == "Alpha stage loader"
    assert "alpha_loader.dll" not in (draft.objects[sid].get("aliases") or [])


def test_file_name_with_only_file_aliases_refused(draft):
    sid, err = draft.declare("malware|alpha_loader.dll|beta.log;gamma.dat")
    assert sid is None and "nom de fichier" in err


def test_promoted_label_keeps_the_file_as_a_term(draft):
    sid, _ = draft.declare("malware|alpha_loader.dll|Alpha stage loader")
    assert draft.resolve("alpha_loader.dll")[0] == sid and "alpha_loader.dll" in draft.terms[sid]
    assert "alpha_loader.dll" not in (draft.objects[sid].get("aliases") or [])
