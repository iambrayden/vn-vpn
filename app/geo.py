"""Destination country and network owner, from free IP-to-ASN databases.

Downloaded weekly into its own SQLite file next to the main database and looked up by range. Sources are tried
in order: iptoasn.com (public domain), then the ip-location-db mirror on jsDelivr (ASN + country, CC0/PDDL).
Optional: if every download fails or GEO_LOOKUP=false, destinations simply have no country/owner - the insights
page shows why and offers a retry.
"""
import csv
import gzip
import io
import ipaddress
import logging
import os
import sqlite3
import threading
import time
import urllib.request
from functools import lru_cache

from . import apps, db

ENABLED = os.environ.get("GEO_LOOKUP", "true").lower() in ("1", "true", "yes")
URL = os.environ.get("GEO_URL", "https://iptoasn.com/data/ip2asn-v4.tsv.gz")
MIRROR_ASN = "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv"
MIRROR_COUNTRY = "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv"
REFRESH = 7 * 86400
RETRY = 3600
log = logging.getLogger("vnvpn.geo")
_lock = threading.Lock()
state = {"error": "", "attempt": 0.0, "running": False}


def _path():
    return os.path.join(os.path.dirname(db.DB_PATH) or ".", "geo.db")


def _ip(v: str) -> int:
    v = v.strip()
    return int(v) if v.isdigit() else int(ipaddress.IPv4Address(v))


def _fresh(path):
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    conn = sqlite3.connect(tmp)
    conn.execute("CREATE TABLE ranges (start INTEGER PRIMARY KEY, end INTEGER, asn INTEGER, country TEXT, org TEXT)")
    conn.execute("CREATE TABLE countries (start INTEGER PRIMARY KEY, end INTEGER, country TEXT)")
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    return conn, tmp


def _finish(conn, tmp, path, source):
    n = conn.execute("SELECT COUNT(*) FROM ranges").fetchone()[0]
    if n < 1:
        conn.close()
        os.remove(tmp)
        raise ValueError(f"{source}: no usable rows")
    conn.executemany("INSERT INTO meta VALUES (?, ?)", [("source", source), ("updated", str(int(time.time()))),
                                                        ("ranges", str(n))])
    conn.commit()
    conn.close()
    os.replace(tmp, path)
    lookup.cache_clear()
    return n


def _insert(conn, table, rows):
    q = "INSERT OR REPLACE INTO ranges VALUES (?,?,?,?,?)" if table == "ranges" else \
        "INSERT OR REPLACE INTO countries VALUES (?,?,?)"
    conn.executemany(q, rows)


def import_tsv(lines, path=None, source="iptoasn.com"):
    """Load ip2asn TSV lines ("start end asn country description") into a fresh database."""
    path = path or _path()
    conn, tmp = _fresh(path)
    rows = []
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5 or parts[2] == "0":
            continue  # "Not routed"
        try:
            rows.append((_ip(parts[0]), _ip(parts[1]), int(parts[2]), parts[3].upper()[:2], parts[4][:120]))
        except ValueError:
            continue
        if len(rows) >= 50000:
            _insert(conn, "ranges", rows)
            rows = []
    _insert(conn, "ranges", rows)
    return _finish(conn, tmp, path, source)


def import_csv(asn_lines, country_lines, path=None, source="ip-location-db"):
    """Load ip-location-db CSVs: "start,end,asn,org" and "start,end,country"."""
    path = path or _path()
    conn, tmp = _fresh(path)
    for table, lines in (("ranges", asn_lines), ("countries", country_lines)):
        rows = []
        for r in csv.reader(lines):
            try:
                if table == "ranges":
                    rows.append((_ip(r[0]), _ip(r[1]), int(r[2] or 0), "", r[3][:120].upper()))
                else:
                    rows.append((_ip(r[0]), _ip(r[1]), r[2].upper()[:2]))
            except (ValueError, IndexError):
                continue  # header or junk
            if len(rows) >= 50000:
                _insert(conn, table, rows)
                rows = []
        _insert(conn, table, rows)
    return _finish(conn, tmp, path, source)


def _get(url) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (vnvpn-panel)"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = resp.read()
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data


def download():
    """Fetch the database from the first source that works; returns the number of ranges."""
    errors = []
    try:
        return import_tsv(_get(URL).decode("utf-8", "replace").splitlines())
    except Exception as e:  # noqa: BLE001 - any failure: try the mirror
        errors.append(f"iptoasn.com: {e}")
    try:
        asn = io.StringIO(_get(MIRROR_ASN).decode("utf-8", "replace"))
        country = io.StringIO(_get(MIRROR_COUNTRY).decode("utf-8", "replace"))
        return import_csv(asn, country)
    except Exception as e:  # noqa: BLE001
        errors.append(f"jsDelivr mirror: {e}")
    raise RuntimeError("; ".join(errors))


def refresh_if_stale(force=False):
    """Download the database if missing or older than a week (background loop, or the admin's retry button)."""
    if not ENABLED or not _lock.acquire(blocking=False):
        return
    try:
        path = _path()
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < REFRESH
        if not force and (fresh or time.time() - state["attempt"] < RETRY):
            return
        state.update(attempt=time.time(), running=True)
        try:
            n = download()
            state["error"] = ""
            log.info("IP owner database updated: %s ranges", n)
        except Exception as e:  # noqa: BLE001
            state["error"] = str(e)[:500]
            log.warning("IP owner database download failed: %s", e)
            if os.path.exists(path):
                os.utime(path)  # keep using the old copy; try again in a week
            return
        backfill()
    finally:
        state["running"] = False
        _lock.release()


def backfill(days=400):
    """Label destinations logged while the database was missing (they showed as Unknown)."""
    since = int(time.time()) - days * 86400
    total = 0
    with db.session() as conn:
        for table in ("flow_log", "flow_rollup"):
            rows = conn.execute(f"""SELECT rowid AS rid, host, dst, dport FROM {table}
                                    WHERE org = '' AND country = '' AND last_seen >= ?""", (since,)).fetchall()
            updates = []
            for r in rows:
                country, org = lookup(r["dst"])
                if country or org:
                    app, category = apps.classify(r["host"], org, r["dport"])
                    updates.append((country, org[:120], app, category, r["rid"]))
            conn.executemany(f"UPDATE {table} SET country = ?, org = ?, app = ?, category = ? WHERE rowid = ?",
                             updates)
            total += len(updates)
    if total:
        log.info("labelled %s earlier destinations", total)
    return total


def status() -> dict:
    """For the insights page: is the database loaded, from where, and why not."""
    info = {"enabled": ENABLED, "ranges": 0, "updated": 0, "source": "", "error": state["error"],
            "running": state["running"]}
    path = _path()
    if os.path.exists(path):
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
            except sqlite3.Error:  # database from before meta existed
                meta = {"ranges": str(conn.execute("SELECT COUNT(*) FROM ranges").fetchone()[0]),
                        "source": "iptoasn.com"}
            conn.close()
            info.update(ranges=int(meta.get("ranges", 0)), source=meta.get("source", ""),
                        updated=int(meta.get("updated") or os.path.getmtime(path)))
        except (sqlite3.Error, ValueError):
            pass
    return info


@lru_cache(maxsize=50000)
def lookup(ip: str) -> tuple[str, str]:
    """(country code, network owner) for an IPv4 address, or ('', '')."""
    path = _path()
    if not ENABLED or not os.path.exists(path):
        return "", ""
    try:
        n = _ip(ip)
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            r = conn.execute("SELECT end, country, org FROM ranges WHERE start <= ? ORDER BY start DESC LIMIT 1",
                             (n,)).fetchone()
            country, org = "", ""
            if r and r[0] >= n:
                country, org = (r[1] if r[1] not in ("NONE", "None", "") else ""), r[2]
            if not country:
                try:
                    c = conn.execute("SELECT end, country FROM countries WHERE start <= ? ORDER BY start DESC LIMIT 1",
                                     (n,)).fetchone()
                    if c and c[0] >= n:
                        country = c[1]
                except sqlite3.Error:
                    pass  # older database without the countries table
        finally:
            conn.close()
    except (ValueError, sqlite3.Error):
        return "", ""
    return country, org
