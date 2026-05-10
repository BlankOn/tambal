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
    """Fetch URL with retry logic for transient failures (503, timeouts)."""
    max_retries = 3
    retry_delay = 30

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < max_retries - 1:
                print(f"HTTP 503: Backend unavailable. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < max_retries - 1:
                print(f"Connection error: {e}. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            raise


def fetch_bytes(url):
    """Fetch URL bytes with retry logic for transient failures (503, timeouts)."""
    max_retries = 3
    retry_delay = 30

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < max_retries - 1:
                print(f"HTTP 503: Backend unavailable. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < max_retries - 1:
                print(f"Connection error: {e}. Retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            raise


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


# ── CVE helpers ───────────────────────────────────────────────────────────────

def extract_cves_from_tracker_page(html):
    """Return deduplicated CVE IDs found in /tracker/CVE-* links on the page."""
    cves = re.findall(r'/tracker/(CVE-\d{4}-\d+)', html)
    return list(dict.fromkeys(cves))


def extract_references_cves(html):
    """Extract CVE IDs only from the References row of a DSA tracker page."""
    m = re.search(
        r'<b>\s*References\s*</b>\s*</td>\s*<td[^>]*>(.*?)</td>',
        html, re.DOTALL | re.IGNORECASE
    )
    if not m:
        return []
    ref_cell = m.group(1)
    cves = re.findall(r'/tracker/(CVE-\d{4}-\d+)', ref_cell)
    return list(dict.fromkeys(cves))


# ── fetch: main security page ─────────────────────────────────────────────────

def fetch_advisories(since=None, no_cache=False):
    html = fetch("https://www.debian.org/security/")

    current_hash = page_hash(html)
    prev_hash = load_prev_hash()
    if not no_cache and prev_hash and current_hash == prev_hash:
        print("Front page unchanged since last run. Loading cached advisories.", file=sys.stderr)
        try:
            with open(ADVISORIES_FILE) as f:
                cached = json.load(f)
            # Schema check: older caches predate the multi_cve flag.
            if cached and any("multi_cve" not in a for a in cached):
                print("Cached advisories use an older schema; refetching.", file=sys.stderr)
            else:
                return cached, True  # (advisories, from_cache)
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


def _parse_fixed_versions(html):
    """
    Parse {release, version, status} entries from the 'fixed versions' table on
    a Debian security tracker page (DSA or CVE — both share the same structure).
    Status is cross-referenced from the 'source packages' table on the same page.
    """
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

    # CVE pages sometimes group several releases in one row (e.g.
    # "bullseye, bullseye (security)" or "forky, sid, trixie"). Split them so
    # each individual release gets its own status entry.
    status_map = {}
    for row in src_rows:
        release_str = row.get("Release", "").strip()
        status = row.get("Status", "").strip()
        if not release_str or not status:
            continue
        for release in release_str.split(","):
            release = release.replace(" (security)", "").strip()
            # Map "(unstable)" to "sid" for consistency
            if release == "(unstable)":
                release = "sid"
            if not release:
                continue
            if release not in status_map or status == "fixed":
                status_map[release] = status

    results = []
    for row in fix_rows:
        release = row.get("Release", "").strip()
        version = row.get("Fixed Version", "").strip()

        # Map "(unstable)" to "sid" for consistency
        if release == "(unstable)":
            release = "sid"
        elif not release or release.startswith("("):
            continue  # skip other placeholders

        if version.startswith("("):
            continue  # skip placeholders like "(unfixed)"

        results.append({
            "release": release,
            "version": version,
            "status": status_map.get(release, "fixed"),
        })

    return results, None


def fetch_tracker_details(url):
    """
    Return (entries, error, multi_cve) where entries is a list of
    {release, version, status} dicts.

    Inspects the References row of the DSA page:
      - multiple CVEs → caller marks the package as "Vulnerable - multiple CVEs"
        (returns ([], None, True))
      - single CVE → follows the CVE link and parses the (more complete)
        'Vulnerable and fixed packages' table on the CVE page
      - no CVE found → falls back to parsing the DSA page directly
    """
    try:
        html = fetch(url)
    except Exception as e:
        return [], str(e), False

    cves = extract_references_cves(html)

    if len(cves) > 1:
        return [], None, True

    if len(cves) == 1:
        cve_url = f"https://security-tracker.debian.org/tracker/{cves[0]}"
        try:
            cve_html = fetch(cve_url)
        except Exception as e:
            # Couldn't fetch the CVE page; fall back to the DSA page.
            results, err = _parse_fixed_versions(html)
            return results, err or str(e), False
        results, err = _parse_fixed_versions(cve_html)
        if err:
            # CVE page didn't parse; fall back to the DSA page.
            results, err2 = _parse_fixed_versions(html)
            return results, err2, False
        return results, None, False

    results, err = _parse_fixed_versions(html)
    return results, err, False


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


def build_sid_index(repo_url):
    """Fetch source package versions from the 'sid' dist of an upstream repo."""
    print(f"Fetching sid index from upstream {repo_url} ...", file=sys.stderr)
    _, components = fetch_release(repo_url, "sid")
    if not components:
        print("  Warning: sid release not found or has no components.", file=sys.stderr)
        return {}

    index = {}
    for component in components:
        print(f"  Fetching sid/{component}/source/Sources.gz ...", file=sys.stderr)
        pkgs = fetch_sources(repo_url, "sid", component)
        for pkg, ver in pkgs.items():
            existing = index.get(pkg)
            if existing is None or version_lt(existing, ver):
                index[pkg] = ver

    print(f"  Indexed {len(index)} source packages from sid.", file=sys.stderr)
    return index


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

        if adv.get("multi_cve"):
            findings.append({
                "advisory_id": adv["id"],
                "date": adv["date"],
                "package": pkg,
                "repo_version": repo_ver,
                "description": adv["description"],
                "announce_url": adv["announce_url"],
                "tracker_url": adv["tracker_url"],
                "vulnerable_against": [],
                "multi_cve": True,
            })
            continue

        fixed_versions = []
        is_vulnerable = False
        for fv in adv.get("fixed_versions", []):
            fixed_ver = fv.get("version", "").strip()
            status = fv.get("status", "").strip()
            if not fixed_ver:
                continue

            # Determine vulnerability based on status and version comparison
            below = False
            if status == "fixed":
                # For "fixed" status: vulnerable if our version < fixed version
                below = version_lt(repo_ver, fixed_ver)
            elif status == "vulnerable":
                # For "vulnerable" status: vulnerable if our version >= the vulnerable version
                below = not version_lt(repo_ver, fixed_ver)
            elif status == "unfixed":
                # For "unfixed" status: vulnerable if our version >= the unfixed version
                below = not version_lt(repo_ver, fixed_ver)
            # For other statuses, don't flag as vulnerable

            if below:
                is_vulnerable = True
            fixed_versions.append({
                "release": fv["release"],
                "fixed_version": fixed_ver,
                "status": status,
                "below": below,
            })

        if is_vulnerable:
            findings.append({
                "advisory_id": adv["id"],
                "date": adv["date"],
                "package": pkg,
                "repo_version": repo_ver,
                "description": adv["description"],
                "announce_url": adv["announce_url"],
                "tracker_url": adv["tracker_url"],
                "vulnerable_against": fixed_versions,
            })

    return findings


# ── html report ───────────────────────────────────────────────────────────────

def write_html_report(findings, html_dir, repo_url, upstream_repo=None):
    import html as _html

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def e(s):
        return _html.escape(str(s))

    rows = []
    for f in findings:
        if f.get("multi_cve"):
            ver_class = "ver-below"
            fixes = (
                '<tr><td colspan="3"><strong>Vulnerable - multiple CVEs</strong>'
                ' — see tracker for details.</td></tr>'
            )
        else:
            # Find the latest fixed version across all releases to compare repo version against
            all_fixed = [v["fixed_version"] for v in f["vulnerable_against"] if v["fixed_version"]]
            latest_fixed = None
            for fv in all_fixed:
                if latest_fixed is None or version_lt(latest_fixed, fv):
                    latest_fixed = fv
            repo_below_latest = latest_fixed is not None and version_lt(f["repo_version"], latest_fixed)
            ver_class = "ver-below" if repo_below_latest else "ver-above"

            import functools
            def _cmp_ver(a, b):
                if version_lt(a["fixed_version"], b["fixed_version"]):
                    return 1   # a < b → a comes after b (descending)
                if version_lt(b["fixed_version"], a["fixed_version"]):
                    return -1  # b < a → a comes before b
                return 0
            sorted_versions = sorted(
                f["vulnerable_against"],
                key=functools.cmp_to_key(_cmp_ver),
            )
            fixes = "".join(
                f'<tr>'
                f'<td>{e(v["release"])}</td>'
                f'<td>{e(v["fixed_version"])}</td>'
                f'<td>{e(v["status"])}</td>'
                f'</tr>'
                for v in sorted_versions
            )
        upstream_ver = f.get("upstream_version")
        upstream_cell = (
            f'<td>{e(upstream_ver)}</td>' if upstream_ver is not None else ""
        )

        rows.append(f"""
        <tr>
          <td>{e(f['date'])}</td>
          <td>{e(f['package'])}</td>
          <td><a href="{e(f['announce_url'])}" target="_blank">{e(f['advisory_id'])}</a> | <a href="{e(f['tracker_url'])}" target="_blank">Tracker</a></td>
          <td class="{ver_class}">{e(f['repo_version'])}</td>
          {upstream_cell}
          <td>
            <table class="inner">
              <tr><th>Release</th><th>Version</th><th>Status</th></tr>
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
    .ver-above {{ color: #27ae60; font-weight: bold; }}
    .ver-below {{ color: #c0392b; font-weight: bold; }}
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
        <th>Package</th>
        <th>Advisory</th>
        <th>Our version</th>
        {"<th>Upstream version (Sid)</th>" if upstream_repo else ""}
        <th>Fixed version in stable releases</th>
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
    upstream_repo = None
    since = None
    output = ADVISORIES_FILE
    no_cache = False
    html_dir = None

    for arg in sys.argv[1:]:
        if arg.startswith("--repo=") or arg.startswith("--repository="):
            repo_url = arg.split("=", 1)[1]
        elif arg.startswith("--upstream-repo="):
            upstream_repo = arg.split("=", 1)[1]
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
            details, err, multi_cve = fetch_tracker_details(adv["tracker_url"])
            if err:
                print(f"\n  Warning: {adv['id']}: {err}", file=sys.stderr)
            adv["fixed_versions"] = details
            adv["multi_cve"] = multi_cve
            results.append(adv)
            time.sleep(0.3)

        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nAdvisories written to {output}", file=sys.stderr)
        advisories = results

    # Step 2: evaluate repo
    package_index = build_package_index(repo_url)

    upstream_index = {}
    if upstream_repo:
        upstream_index = build_sid_index(upstream_repo)

    print("Evaluating advisories ...", file=sys.stderr)
    findings = evaluate(advisories, package_index)

    if upstream_index:
        for f in findings:
            f["upstream_version"] = upstream_index.get(f["package"])

    if not findings:
        print("No vulnerable packages found.", file=sys.stderr)
        if html_dir:
            write_html_report(findings, html_dir, repo_url, upstream_repo=upstream_repo)
        sys.exit(0)

    print(f"Found {len(findings)} potentially vulnerable package(s):\n", file=sys.stderr)

    for f in findings:
        print(f"[{f['date']}] {f['advisory_id']}  {f['package']}")
        print(f"  Our version : {f['repo_version']}")
        if f.get("multi_cve"):
            print(f"  Status       : Vulnerable - multiple CVEs")
        else:
            for v in f["vulnerable_against"]:
                print(f"  Below fix    : {v['fixed_version']}  (for {v['release']}, status: {v['status']})")
        print(f"  Description  : {f['description']}")
        print(f"  Announce     : {f['announce_url']}")
        print()

    if html_dir:
        write_html_report(findings, html_dir, repo_url, upstream_repo=upstream_repo)


if __name__ == "__main__":
    main()
