#!/usr/bin/env python3
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from io import BytesIO

ADVISORIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "advisories.json")
HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prev_load.hash")


# ── helpers ───────────────────────────────────────────────────────────────────

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        return r.read().decode("utf-8")


def fetch_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        return r.read()


def fetch_text(url):
    return fetch_bytes(url).decode("utf-8")


def parse_date(s):
    """Parse '01 Apr 2026' -> datetime.date"""
    return datetime.strptime(s, "%d %b %Y").date()


def format_date(d):
    return d.strftime("%Y-%m-%d")


def version_lt(v1, v2):
    """Return True if v1 < v2 using dpkg version comparison."""
    result = subprocess.run(
        ["dpkg", "--compare-versions", v1, "lt", v2],
        capture_output=True,
    )
    return result.returncode == 0


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


# ── fetch: main security page ─────────────────────────────────────────────────

def fetch_advisories(since=None, no_cache=False):
    html = fetch("https://www.debian.org/security/")

    current_hash = page_hash(html)
    prev_hash = load_prev_hash()
    if not no_cache and prev_hash and current_hash == prev_hash:
        print("Front page unchanged since last run. Loading cached advisories.", file=sys.stderr)
        try:
            with open(ADVISORIES_FILE) as f:
                return json.load(f), True  # (advisories, from_cache)
        except Exception:
            pass  # fall through and re-fetch
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

    return advisories, False  # (advisories, from_cache)


# ── fetch: tracker page ───────────────────────────────────────────────────────

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

    src_html = html[idx_src:idx_fix]
    fix_html = html[idx_fix:]

    parser_src = TableParser()
    parser_src.feed(src_html)

    parser_fix = TableParser()
    parser_fix.feed(fix_html)

    if not parser_fix.tables:
        return [], "fixed versions table not found"

    fix_rows = parser_fix.tables[0]
    src_rows = parser_src.tables[0] if parser_src.tables else []

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


# ── evaluate: repo discovery ──────────────────────────────────────────────────

def discover_dists(repo_url):
    """Parse HTML directory listing at {repo}/dists/ and return dist names."""
    url = repo_url.rstrip("/") + "/dists/"
    html = fetch_text(url)
    names = re.findall(r'href="([^"/][^"]*/)\"', html)
    return [n.rstrip("/") for n in names]


def fetch_release(repo_url, dist):
    """Return (codename, components list) from a Release file."""
    url = f"{repo_url.rstrip('/')}/dists/{dist}/Release"
    try:
        text = fetch_text(url)
    except Exception:
        return dist, []
    components = []
    for line in text.splitlines():
        if line.startswith("Components:"):
            components = line.split(":", 1)[1].strip().split()
            break
    return dist, components


def fetch_sources(repo_url, dist, component):
    """Fetch and parse Sources.gz; return dict of package -> version."""
    url = f"{repo_url.rstrip('/')}/dists/{dist}/{component}/source/Sources.gz"
    try:
        data = fetch_bytes(url)
    except Exception:
        return {}

    try:
        text = gzip.decompress(data).decode("utf-8")
    except Exception:
        return {}

    packages = {}
    current_pkg = None
    current_ver = None

    for line in text.splitlines():
        if line.startswith("Package:"):
            current_pkg = line.split(":", 1)[1].strip()
            current_ver = None
        elif line.startswith("Version:"):
            current_ver = line.split(":", 1)[1].strip()
            if current_pkg and current_ver:
                existing = packages.get(current_pkg)
                if existing is None or version_lt(existing, current_ver):
                    packages[current_pkg] = current_ver
    return packages


def build_package_index(repo_url):
    """
    Walk all dists and components in the repo and return a unified
    package -> highest_version map.
    """
    print(f"Discovering dists at {repo_url} ...", file=sys.stderr)
    dists = discover_dists(repo_url)
    if not dists:
        print("Error: no dists found.", file=sys.stderr)
        sys.exit(1)
    print(f"  Found dists: {', '.join(dists)}", file=sys.stderr)

    index = {}
    for dist in dists:
        _, components = fetch_release(repo_url, dist)
        for component in components:
            print(f"  Fetching {dist}/{component}/source/Sources.gz ...", file=sys.stderr)
            pkgs = fetch_sources(repo_url, dist, component)
            for pkg, ver in pkgs.items():
                existing = index.get(pkg)
                if existing is None or version_lt(existing, ver):
                    index[pkg] = ver

    print(f"  Indexed {len(index)} source packages.", file=sys.stderr)
    return index


# ── evaluate: check advisories against repo ──────────────────────────────────

def evaluate(advisories, package_index):
    """
    For each advisory, check whether the repo's version of the package
    is below any fixed version. Returns a list of findings.
    """
    findings = []

    for adv in advisories:
        pkg = adv["package"]
        repo_ver = package_index.get(pkg)

        if repo_ver is None:
            continue  # package not present in this repo

        vulnerable_in = []
        for fv in adv.get("fixed_versions", []):
            fixed_ver = fv.get("version", "").strip()
            if not fixed_ver:
                continue
            if version_lt(repo_ver, fixed_ver):
                vulnerable_in.append({
                    "release": fv["release"],
                    "fixed_version": fixed_ver,
                    "status": fv.get("status", ""),
                })

        if vulnerable_in:
            findings.append({
                "advisory_id": adv["id"],
                "date": adv["date"],
                "package": pkg,
                "repo_version": repo_ver,
                "description": adv["description"],
                "announce_url": adv["announce_url"],
                "vulnerable_against": vulnerable_in,
            })

    return findings


# ── html report ───────────────────────────────────────────────────────────────

def write_html_report(findings, html_dir, repo_url):
    import html as _html

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def e(s):
        return _html.escape(str(s))

    rows = []
    for f in findings:
        fixes = "".join(
            f"<tr><td>{e(v['release'])}</td><td>{e(v['fixed_version'])}</td><td>{e(v['status'])}</td></tr>"
            for v in f["vulnerable_against"]
        )
        rows.append(f"""
        <tr>
          <td>{e(f['date'])}</td>
          <td><a href="{e(f['announce_url'])}" target="_blank">{e(f['advisory_id'])}</a></td>
          <td>{e(f['package'])}</td>
          <td>{e(f['description'])}</td>
          <td>{e(f['repo_version'])}</td>
          <td>
            <table class="inner">
              <tr><th>Release</th><th>Fixed version</th><th>Status</th></tr>
              {fixes}
            </table>
          </td>
        </tr>""")

    rows_html = "\n".join(rows)
    count = len(findings)
    summary = f"{count} potentially vulnerable package(s) found." if count else "No vulnerable packages found."

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BlankOn Linux Security Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
    h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
    .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .summary {{ font-weight: bold; margin-bottom: 1rem;
                color: {"#c0392b" if count else "#27ae60"}; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
    th, td {{ border: 1px solid #ddd; padding: 0.45rem 0.65rem; vertical-align: top; }}
    th {{ background: #f4f4f4; text-align: left; white-space: nowrap; }}
    tr:hover > td {{ background: #fafafa; }}
    table.inner {{ font-size: 0.82rem; border: none; width: auto; }}
    table.inner th, table.inner td {{ border: 1px solid #e0e0e0; padding: 0.25rem 0.5rem; }}
    table.inner th {{ background: #f9f9f9; }}
    a {{ color: #1a73e8; }}
  </style>
</head>
<body>
  <h1>BlankOn Linux Security Report</h1>
  <div class="meta">
    Repository: <a href="{e(repo_url)}" target="_blank">{e(repo_url)}</a>
    &nbsp;|&nbsp; Generated: {e(generated_at)}
  </div>
  <div class="summary">{e(summary)}</div>
  {"" if not count else f"""
  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>Advisory</th>
        <th>Package</th>
        <th>Description</th>
        <th>Repo version</th>
        <th>Fixed Versions</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>"""}
</body>
</html>
"""

    os.makedirs(html_dir, exist_ok=True)
    out_path = os.path.join(html_dir, "index.html")
    with open(out_path, "w") as f:
        f.write(page)
    print(f"HTML report written to {out_path}", file=sys.stderr)


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    repo_url = None
    since = None
    output = ADVISORIES_FILE
    no_cache = False
    html_dir = None

    for arg in sys.argv[1:]:
        if arg.startswith("--repo=") or arg.startswith("--repository="):
            repo_url = arg.split("=", 1)[1]
        elif arg.startswith("--since="):
            val = arg.split("=", 1)[1]
            try:
                since = datetime.strptime(val, "%Y-%m-%d").date()
            except ValueError:
                print(f"Error: --since must be in yyyy-mm-dd format, got '{val}'", file=sys.stderr)
                sys.exit(1)
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        elif arg.startswith("--html="):
            html_dir = arg.split("=", 1)[1]
        elif arg == "--no-cache":
            no_cache = True

    if not repo_url:
        print("Error: --repo=/url or --repository=/url is required", file=sys.stderr)
        sys.exit(1)

    # Step 1: fetch advisories
    print("Fetching advisory list...", file=sys.stderr)
    advisories, from_cache = fetch_advisories(since=since, no_cache=no_cache)

    if not from_cache:
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
        print(f"\nAdvisories written to {output}", file=sys.stderr)
        advisories = results

    # Step 2: evaluate repo
    package_index = build_package_index(repo_url)

    print("Evaluating advisories ...", file=sys.stderr)
    findings = evaluate(advisories, package_index)

    if not findings:
        print("No vulnerable packages found.", file=sys.stderr)
        if html_dir:
            write_html_report(findings, html_dir, repo_url)
        sys.exit(0)

    print(f"Found {len(findings)} potentially vulnerable package(s):\n", file=sys.stderr)

    for f in findings:
        print(f"[{f['date']}] {f['advisory_id']}  {f['package']}")
        print(f"  Repo version : {f['repo_version']}")
        for v in f["vulnerable_against"]:
            print(f"  Below fix    : {v['fixed_version']}  (for {v['release']}, status: {v['status']})")
        print(f"  Description  : {f['description']}")
        print(f"  Announce     : {f['announce_url']}")
        print()

    if html_dir:
        write_html_report(findings, html_dir, repo_url)


if __name__ == "__main__":
    main()
