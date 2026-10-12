"""Destination country and network owner from the free iptoasn.com database (public domain).

Downloaded weekly into its own SQLite file next to the main database, looked up by range. Optional: if the
download fails or GEO_LOOKUP=false, destinations simply have no country/owner.
"""
import gzip
import ipaddress
import logging
import os
import sqlite3
import time
import urllib.request
from functools import lru_cache

from . import db

ENABLED = os.environ.get("GEO_LOOKUP", "true").lower() in ("1", "true", "yes")
URL = os.environ.get("GEO_URL", "https://iptoasn.com/data/ip2asn-v4.tsv.gz")
REFRESH = 7 * 86400
log = logging.getLogger("vnvpn.geo")


def _path():
    return os.path.join(os.path.dirname(db.DB_PATH) or ".", "geo.db")


def import_tsv(lines, path=None):
    """Load ip2asn TSV lines ("start end asn country description") into a fresh database."""
    path = path or _path()
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    conn = sqlite3.connect(tmp)
    conn.execute("CREATE TABLE ranges (start INTEGER PRIMARY KEY, end INTEGER, asn INTEGER, country TEXT, org TEXT)")
    rows = []
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5 or parts[2] == "0":
            continue  # "Not routed"
        try:
            rows.append((int(ipaddress.ip_address(parts[0])), int(ipaddress.ip_address(parts[1])),
                         int(parts[2]), parts[3].upper()[:2], parts[4][:120]))
        except ValueError:
            continue
        if len(rows) >= 50000:
            conn.executemany("INSERT OR REPLACE INTO ranges VALUES (?,?,?,?,?)", rows)
            rows = []
    conn.executemany("INSERT OR REPLACE INTO ranges VALUES (?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    os.replace(tmp, path)
    lookup.cache_clear()


def refresh_if_stale():
    """Download the database if missing or older than a week (runs in the background loop)."""
    if not ENABLED:
        return
    path = _path()
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < REFRESH:
        return
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "vnvpn-panel"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = gzip.decompress(resp.read()).decode("utf-8", "replace")
        import_tsv(data.splitlines())
        log.info("ip2asn database updated")
    except Exception as e:
        log.warning("ip2asn download failed: %s", e)
        if os.path.exists(path):
            os.utime(path)  # don't retry every loop; try again in a week


@lru_cache(maxsize=50000)
def lookup(ip: str) -> tuple[str, str]:
    """(country code, network owner) for an IPv4 address, or ('', '')."""
    path = _path()
    if not ENABLED or not os.path.exists(path):
        return "", ""
    try:
        n = int(ipaddress.ip_address(ip))
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            r = conn.execute("SELECT end, country, org FROM ranges WHERE start <= ? ORDER BY start DESC LIMIT 1",
                             (n,)).fetchone()
        finally:
            conn.close()
    except (ValueError, sqlite3.Error):
        return "", ""
    if not r or r[0] < n:
        return "", ""
    return (r[1] if r[1] not in ("NONE", "") else ""), r[2]
