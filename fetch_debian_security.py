#!/usr/bin/env python3
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime
from html.parser import HTMLParser

HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prev_load.hash")


# ── helpers ───────────────────────────────────────────────────────────────────

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        return r.read().decode("utf-8")


def parse_date(s):
    """Parse '01 Apr 2026' -> datetime.date"""
    return datetime.strptime(s, "%d %b %Y").date()


def format_date(d):
    return d.strftime("%Y-%m-%d")


# ── front page fingerprint ────────────────────────────────────────────────────

def page_hash(html):
    return hashlib.sha256(html.encode()).hexdigest()


def load_prev_hash():
    try:
        with open(HASH_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def save_hash(h):
    with open(HASH_FILE, "w") as f:
        f.write(h)


# ── main security page ────────────────────────────────────────────────────────

def fetch_advisories(since=None, no_cache=False):
    html = fetch("https://www.debian.org/security/")

    current_hash = page_hash(html)
    prev_hash = load_prev_hash()
    if not no_cache and prev_hash and current_hash == prev_hash:
        print("Front page unchanged since last run. Exiting.", file=sys.stderr)
        sys.exit(0)
    save_hash(current_hash)

    pattern = re.compile(
        r"<tt>\[(\d{2}\s+\w+\s+\d{4})\]</tt>"
        r".*?"
        r'<a href="([^"]+)">\s*T\s*</a>'
        r".*?"
        r'<a href="([^"]+)">(DSA-[\d]+-\d+)\s+([^<]+)</a></strong>\s*(.*?)<br',
        re.DOTALL,
    )

    advisories = []
    for m in pattern.finditer(html):
        date_str, tracker_url, announce_url, dsa_id, package, suffix = m.groups()
        date = parse_date(date_str)
        if since and date < since:
            break  # list is newest-first; nothing older will match
        advisories.append({
            "date": format_date(date),
            "id": dsa_id,
            "package": package.strip(),
            "description": f"{dsa_id} {package.strip()} {suffix.strip()}".strip(),
            "tracker_url": tracker_url,
            "announce_url": announce_url,
        })

    return advisories


# ── tracker page ──────────────────────────────────────────────────────────────

class TableParser(HTMLParser):
    """Parse all <table> blocks into list-of-dicts using the first <tr> as header."""

    def __init__(self):
        super().__init__()
        self.tables = []
        self._in_table = False
        self._headers = []
        self._row = []
        self._cell = ""
        self._in_cell = False
        self._current_table = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._in_table = True
            self._headers = []
            self._current_table = []
        elif tag in ("th", "td") and self._in_table:
            self._in_cell = True
            self._cell = ""

    def handle_endtag(self, tag):
        if tag == "table":
            self._in_table = False
            self.tables.append(self._current_table)
        elif tag == "tr" and self._in_table:
            if self._row:
                if not self._headers:
                    self._headers = self._row[:]
                else:
                    self._current_table.append(dict(zip(self._headers, self._row)))
                self._row = []
        elif tag in ("th", "td") and self._in_cell:
            self._in_cell = False
            self._row.append(self._cell.strip())

    def handle_data(self, data):
        if self._in_cell:
            self._cell += data

    def handle_entityref(self, name):
        if self._in_cell:
            self._cell += {"ensp": " ", "nbsp": " ", "amp": "&",
                           "lt": "<", "gt": ">"}.get(name, "")

    def handle_charref(self, name):
        if self._in_cell:
            try:
                ch = chr(int(name[1:], 16) if name.startswith("x") else int(name))
                self._cell += ch
            except Exception:
                pass


def fetch_tracker_details(url):
    """
    Return list of {release, version, status} from the 'fixed versions' table.
    Status is cross-referenced from the 'source packages' table on the same page.
    """
    try:
        html = fetch(url)
    except Exception as e:
        return [], str(e)

    marker_src = "information on source packages"
    marker_fix = "based on the following data on fixed versions"

    idx_src = html.find(marker_src)
    idx_fix = html.find(marker_fix)

    if idx_src == -1 or idx_fix == -1:
        return [], "markers not found"

    # Source packages table comes first, fixed versions table comes second.
    src_html = html[idx_src:idx_fix]
    fix_html = html[idx_fix:]

    parser_src = TableParser()
    parser_src.feed(src_html)

    parser_fix = TableParser()
    parser_fix.feed(fix_html)

    if not parser_fix.tables:
        return [], "fixed versions table not found"

    fix_rows = parser_fix.tables[0]   # columns: Package, Type, Release, Fixed Version, ...
    src_rows = parser_src.tables[0] if parser_src.tables else []

    # Build release -> status from source packages table.
    # Strip "(security)" suffix when keying so it matches the fixed versions release name.
    status_map = {}
    for row in src_rows:
        release = row.get("Release", "").replace(" (security)", "").strip()
        status = row.get("Status", "").strip()
        if release and status:
            if release not in status_map or status == "fixed":
                status_map[release] = status

    results = []
    for row in fix_rows:
        release = row.get("Release", "").strip()
        version = row.get("Fixed Version", "").strip()
        if not release:
            continue
        results.append({
            "release": release,
            "version": version,
            "status": status_map.get(release, "fixed"),
        })

    return results, None


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    since = None
    output = None
    no_cache = False

    for arg in sys.argv[1:]:
        if arg.startswith("--since="):
            val = arg.split("=", 1)[1]
            try:
                since = datetime.strptime(val, "%Y-%m-%d").date()
            except ValueError:
                print(f"Error: --since must be in yyyy-mm-dd format, got '{val}'", file=sys.stderr)
                sys.exit(1)
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        elif arg == "--no-cache":
            no_cache = True

    if not output:
        print("Error: --output=/path/to/file is required", file=sys.stderr)
        sys.exit(1)

    print("Fetching advisory list...", file=sys.stderr)
    advisories = fetch_advisories(since=since, no_cache=no_cache)
    print(f"Found {len(advisories)} advisories. Fetching tracker details...", file=sys.stderr)

    results = []
    for i, adv in enumerate(advisories, 1):
        print(f"  [{i}/{len(advisories)}] {adv['id']} ...", file=sys.stderr, end="\r")
        details, err = fetch_tracker_details(adv["tracker_url"])
        if err:
            print(f"\n  Warning: {adv['id']}: {err}", file=sys.stderr)
        adv["fixed_versions"] = details
        results.append(adv)
        time.sleep(0.3)

    with open(output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nDone. Written to {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
