"""Lieux : résoudre un nom (« Russia », « Russie », « Eastern Europe ») vers ce qu'exige un objet `location` STIX.

STIX demande au moins `region` (vocabulaire `region-ov`), `country` (ISO 3166-1 alpha-2) ou `latitude`+`longitude`.
Un nom qui ne se résout vers aucun des deux n'est pas inventé : l'agent reçoit un refus.
Données de référence figées dans ce module (les pays ne changent pas au rythme des articles).
"""

import re
import unicodedata

from stix2.v21.vocab import REGION

# nom anglais usuel -> code ISO 3166-1 alpha-2
_COUNTRIES = """
AF Afghanistan|AL Albania|DZ Algeria|AD Andorra|AO Angola|AG Antigua and Barbuda|AR Argentina|AM Armenia|AU Australia
AT Austria|AZ Azerbaijan|BS Bahamas|BH Bahrain|BD Bangladesh|BB Barbados|BY Belarus|BE Belgium|BZ Belize|BJ Benin
BT Bhutan|BO Bolivia|BA Bosnia and Herzegovina|BW Botswana|BR Brazil|BN Brunei|BG Bulgaria|BF Burkina Faso|BI Burundi
CV Cape Verde|KH Cambodia|CM Cameroon|CA Canada|CF Central African Republic|TD Chad|CL Chile|CN China|CO Colombia
KM Comoros|CG Republic of the Congo|CD Democratic Republic of the Congo|CR Costa Rica|CI Ivory Coast|HR Croatia|CU Cuba
CY Cyprus|CZ Czech Republic|DK Denmark|DJ Djibouti|DM Dominica|DO Dominican Republic|EC Ecuador|EG Egypt|SV El Salvador
GQ Equatorial Guinea|ER Eritrea|EE Estonia|SZ Eswatini|ET Ethiopia|FJ Fiji|FI Finland|FR France|GA Gabon|GM Gambia
GE Georgia|DE Germany|GH Ghana|GR Greece|GD Grenada|GT Guatemala|GN Guinea|GW Guinea-Bissau|GY Guyana|HT Haiti
HN Honduras|HK Hong Kong|HU Hungary|IS Iceland|IN India|ID Indonesia|IR Iran|IQ Iraq|IE Ireland|IL Israel|IT Italy
JM Jamaica|JP Japan|JO Jordan|KZ Kazakhstan|KE Kenya|KI Kiribati|KP North Korea|KR South Korea|XK Kosovo|KW Kuwait
KG Kyrgyzstan|LA Laos|LV Latvia|LB Lebanon|LS Lesotho|LR Liberia|LY Libya|LI Liechtenstein|LT Lithuania|LU Luxembourg
MO Macau|MG Madagascar|MW Malawi|MY Malaysia|MV Maldives|ML Mali|MT Malta|MH Marshall Islands|MR Mauritania
MU Mauritius|MX Mexico|FM Micronesia|MD Moldova|MC Monaco|MN Mongolia|ME Montenegro|MA Morocco|MZ Mozambique
MM Myanmar|NA Namibia|NR Nauru|NP Nepal|NL Netherlands|NZ New Zealand|NI Nicaragua|NE Niger|NG Nigeria
MK North Macedonia|NO Norway|OM Oman|PK Pakistan|PW Palau|PS Palestine|PA Panama|PG Papua New Guinea|PY Paraguay
PE Peru|PH Philippines|PL Poland|PT Portugal|PR Puerto Rico|QA Qatar|RO Romania|RU Russia|RW Rwanda
KN Saint Kitts and Nevis|LC Saint Lucia|VC Saint Vincent and the Grenadines|WS Samoa|SM San Marino
ST Sao Tome and Principe|SA Saudi Arabia|SN Senegal|RS Serbia|SC Seychelles|SL Sierra Leone|SG Singapore|SK Slovakia
SI Slovenia|SB Solomon Islands|SO Somalia|ZA South Africa|SS South Sudan|ES Spain|LK Sri Lanka|SD Sudan|SR Suriname
SE Sweden|CH Switzerland|SY Syria|TW Taiwan|TJ Tajikistan|TZ Tanzania|TH Thailand|TL East Timor|TG Togo|TO Tonga
TT Trinidad and Tobago|TN Tunisia|TR Turkey|TM Turkmenistan|TV Tuvalu|UG Uganda|UA Ukraine|AE United Arab Emirates
GB United Kingdom|US United States|UY Uruguay|UZ Uzbekistan|VU Vanuatu|VA Vatican City|VE Venezuela|VN Vietnam
YE Yemen|ZM Zambia|ZW Zimbabwe
"""

# autres graphies courantes (anglais usuel dans les articles + français) -> code
_ALIASES = {
    "AE": "UAE;Emirats arabes unis", "BY": "Bielorussie", "BR": "Bresil", "CA": "Canada", "CN": "People's Republic of China;PRC;Chine",
    "CZ": "Czechia;Tchequie;Republique tcheque", "DE": "Allemagne", "DK": "Danemark", "EG": "Egypte", "ES": "Espagne",
    "FR": "Francaise;Republique francaise", "GB": "UK;Great Britain;Britain;England;Royaume-Uni;Angleterre;Grande-Bretagne",
    "GR": "Grece", "IL": "Israël", "IN": "Inde", "IR": "Islamic Republic of Iran;Persia", "IT": "Italie", "JP": "Japon",
    "KP": "DPRK;Democratic People's Republic of Korea;Korea, North;Coree du Nord", "KR": "Republic of Korea;ROK;Korea, South;South Korea;Coree du Sud;Korea",
    "MM": "Burma", "MK": "Macedonia;Macedoine du Nord", "MX": "Mexique", "NL": "Holland;The Netherlands;Pays-Bas", "PS": "Gaza;West Bank;Cisjordanie",
    "RU": "Russian Federation;Russie;Federation de Russie", "SA": "KSA;Arabie saoudite", "SY": "Syrie", "TR": "Turkiye;Turquie",
    "TW": "Taiwan, Province of China;Republic of China;Taiwan", "UA": "Ukraine", "US": "USA;U.S.;U.S.A.;United States of America;America;Etats-Unis;Etats-Unis d'Amerique;Etats Unis",
    "VN": "Viet Nam", "CH": "Suisse", "SE": "Suede", "NO": "Norvege", "PL": "Pologne", "PT": "Portugal", "BE": "Belgique",
    "AT": "Autriche", "FI": "Finlande", "IE": "Irlande", "AU": "Australie", "NZ": "Nouvelle-Zelande", "CD": "DR Congo;DRC;Congo-Kinshasa",
    "CG": "Congo-Brazzaville;Congo", "LA": "Lao PDR", "MD": "Moldavie", "SK": "Slovaquie", "SI": "Slovenie", "HU": "Hongrie",
    "RO": "Roumanie", "BG": "Bulgarie", "HR": "Croatie", "RS": "Serbie", "LV": "Lettonie", "LT": "Lituanie", "EE": "Estonie",
    "IQ": "Irak", "JO": "Jordanie", "LB": "Liban", "MA": "Maroc", "DZ": "Algerie", "TN": "Tunisie", "ZA": "Afrique du Sud",
    "CO": "Colombie", "PE": "Perou", "CL": "Chili", "VE": "Venezuela", "AR": "Argentine", "KZ": "Kazakhstan", "AZ": "Azerbaidjan",
    "GE": "Georgie", "AM": "Armenie", "PK": "Pakistan", "TH": "Thailande", "PH": "Philippines", "ID": "Indonesie", "MY": "Malaisie",
    "SG": "Singapour", "KE": "Kenya", "NG": "Nigeria", "ET": "Ethiopie", "UG": "Ouganda", "TZ": "Tanzanie",
}

# autres noms de régions -> valeur de `region-ov`
_REGION_ALIASES = {
    "middle east": "western-asia", "moyen-orient": "western-asia", "west asia": "western-asia",
    "north america": "northern-america", "amerique du nord": "northern-america",
    "latin america": "latin-america-caribbean", "amerique latine": "latin-america-caribbean",
    "southeast asia": "south-eastern-asia", "south east asia": "south-eastern-asia", "asie du sud-est": "south-eastern-asia",
    "south asia": "southern-asia", "east asia": "eastern-asia", "asie de l'est": "eastern-asia", "central europe": "eastern-europe",
    "north africa": "northern-africa", "afrique du nord": "northern-africa", "sub-saharan africa": "africa",
    "asia pacific": "asia", "apac": "asia", "asia-pacific": "asia", "asie": "asia", "afrique": "africa", "amerique": "americas",
    "oceanie": "oceania", "emea": "europe", "balkans": "southern-europe", "the balkans": "southern-europe", "scandinavia": "northern-europe",
    "baltics": "northern-europe", "baltic states": "northern-europe", "caucasus": "western-asia", "gulf": "western-asia",
    "persian gulf": "western-asia", "europe de l'est": "eastern-europe", "europe de l'ouest": "western-europe",
    "western europe": "western-europe", "eastern europe": "eastern-europe", "europe": "europe",
}


def _key(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", re.sub(r"^the\s+", "", text.strip().lower().replace("’", "'")))


def _build_countries() -> dict[str, str]:
    table: dict[str, str] = {}
    for item in _COUNTRIES.replace("\n", "|").split("|"):
        item = item.strip()
        if item:
            code, name = item.split(" ", 1)
            table[_key(name)] = code
    for code, names in _ALIASES.items():
        for name in names.split(";"):
            table.setdefault(_key(name), code)
    return table


_COUNTRY_BY_NAME = _build_countries()
_COUNTRY_CODES = frozenset(_COUNTRY_BY_NAME.values())


def region_of(name: str) -> str | None:
    """Valeur `region-ov` pour un nom de région (« Eastern Europe », « Moyen-Orient »)."""
    key = _key(name)
    if key in _REGION_ALIASES:
        return _REGION_ALIASES[key]
    slug = key.replace(" ", "-")
    return slug if slug in REGION else None


def country_of(name: str) -> str | None:
    """Code ISO 3166-1 alpha-2 pour un nom de pays ou un code déjà valide."""
    text = name.strip()
    if re.fullmatch(r"[A-Za-z]{2}", text) and text.upper() in _COUNTRY_CODES:
        return text.upper()
    return _COUNTRY_BY_NAME.get(_key(text))


def place_names(country: str | None, region: str | None) -> set[str]:
    """Toutes les graphies connues d'un pays ou d'une région (anglaises et françaises) : un lieu nommé dans une langue
    est reconnu dans un texte écrit dans l'autre (« Asie de l'Est » dans « East Asia »)."""
    if country:
        return {name for name, code in _COUNTRY_BY_NAME.items() if code == country}
    if region:
        return {name for name, value in _REGION_ALIASES.items() if value == region} | {region.replace("-", " ")}
    return set()


def resolve_location(name: str, country: str = "", region: str = "") -> tuple[str | None, str | None]:
    """(country, region) pour un lieu ; (None, None) si rien n'est établi. Les valeurs fournies par le modèle sont vérifiées."""
    code = country_of(country) if country else None
    reg = region_of(region) if region else None
    if not code and not reg:
        code = country_of(name)
        reg = None if code else region_of(name)
    return code, reg
