"""Country codes for server locations (flags in the UI)."""
from markupsafe import Markup

COUNTRIES = {
    "AE": "United Arab Emirates", "AR": "Argentina", "AT": "Austria", "AU": "Australia", "BE": "Belgium",
    "BG": "Bulgaria", "BR": "Brazil", "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CO": "Colombia",
    "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "EE": "Estonia", "EG": "Egypt", "ES": "Spain",
    "FI": "Finland", "FR": "France", "GB": "United Kingdom", "GR": "Greece", "HK": "Hong Kong",
    "HR": "Croatia", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India",
    "IS": "Iceland", "IT": "Italy", "JP": "Japan", "KR": "South Korea", "LT": "Lithuania",
    "LU": "Luxembourg", "LV": "Latvia", "MD": "Moldova", "MX": "Mexico", "MY": "Malaysia",
    "NG": "Nigeria", "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand", "PE": "Peru",
    "PH": "Philippines", "PK": "Pakistan", "PL": "Poland", "PT": "Portugal", "RO": "Romania",
    "RS": "Serbia", "SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia",
    "SK": "Slovakia", "TH": "Thailand", "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine",
    "US": "United States", "VN": "Vietnam", "ZA": "South Africa",
}
_BY_NAME = {v.lower(): k for k, v in COUNTRIES.items()}
_BY_NAME.update({"usa": "US", "uk": "GB", "england": "GB", "holland": "NL", "korea": "KR"})


def normalize(value: str | None) -> str:
    """Accept 'de', 'DE', 'Germany' -> 'DE'; unknown -> ''."""
    v = (value or "").strip()
    if v.upper() in COUNTRIES:
        return v.upper()
    return _BY_NAME.get(v.lower(), "")


GLOBE_SVG = ('<svg class="flag-img flag-none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">'
             '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9'
             's1.3-6.4 3.8-9z"/></svg>')


def flag(code: str | None) -> Markup:
    """Flag image for an ISO code (bundled SVGs - Windows can't render flag emoji); a globe if unknown."""
    code = (code or "").upper()
    if code not in COUNTRIES:
        return Markup(GLOBE_SVG)
    return Markup(f'<img class="flag-img" src="/static/flags/{code.lower()}.svg" alt="{COUNTRIES[code]}" '
                  f'title="{COUNTRIES[code]}" width="32" height="24">')
