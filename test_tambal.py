import os
import re
import tempfile
import unittest
from unittest import mock

import tambal

LISTING = """<html><body><pre>
<a href="../">../</a>
<a href="sinambung/">sinambung/</a>
<a href="sinambung-security/">sinambung-security/</a>
</pre></body></html>"""


def finding(package):
    return {
        "package": package,
        "severity": "High",
        "our_version": "1.0-1",
        "fixed_version": "1.0-2",
        "cves": [{"id": "CVE-2026-0001", "description": "A flaw."}],
        "stable_releases": [{"release": "trixie", "version": "1.0-2"}],
    }


def render(reports, **kwargs):
    with tempfile.TemporaryDirectory() as out:
        tambal.write_html_report(reports, out, **kwargs)
        with open(os.path.join(out, "index.html"), encoding="utf-8") as fh:
            return fh.read()


class DiscoverDistsTest(unittest.TestCase):
    def test_parent_directory_link_is_not_a_dist(self):
        with mock.patch.object(tambal, "fetch_text", return_value=LISTING):
            dists = tambal.discover_dists("https://arsip.example/sinambung/")
        self.assertEqual(dists, ["sinambung", "sinambung-security"])


class RepoLabelTest(unittest.TestCase):
    def test_label_is_the_first_host_label(self):
        self.assertEqual(tambal.repo_label("http://arsip-dev.blankonlinux.id/sinambung/"), "arsip-dev")
        self.assertEqual(tambal.repo_label("https://arsip.blankonlinux.id/sinambung/"), "arsip")


class HtmlReportTest(unittest.TestCase):
    def test_single_repository_has_no_tabs(self):
        html = render([{"label": "arsip-dev", "repo_url": "http://arsip-dev.example/s/", "findings": [finding("foo")]}])
        self.assertNotIn('class="tabs"', html)
        self.assertEqual(len(re.findall(r'<section class="panel"', html)), 1)
        self.assertIn("Repository: <a href=\"http://arsip-dev.example/s/\"", html)

    def test_each_repository_gets_its_own_tab_and_panel(self):
        html = render([
            {"label": "arsip-dev", "repo_url": "http://arsip-dev.example/s/", "findings": [finding("foo"), finding("bar")]},
            {"label": "arsip", "repo_url": "https://arsip.example/s/", "findings": []},
        ])
        self.assertEqual(re.findall(r'data-panel="([^"]+)"', html), ["repo-arsip-dev", "repo-arsip"])
        self.assertEqual(re.findall(r'<section class="panel" id="([^"]+)"', html), ["repo-arsip-dev", "repo-arsip"])
        self.assertIn("arsip-dev (2)", html)
        self.assertIn("arsip (0)", html)
        self.assertEqual(len(re.findall(r"<tr data-pkg=", html)), 2)
        self.assertIn("All packages up to date.", html)

    def test_dsa_column_and_filter_follow_the_report(self):
        html = render(
            [{"label": "arsip", "repo_url": "https://arsip.example/s/", "findings": [finding("foo")]}],
            dsa_map={"CVE-2026-0001": "DSA-9999-1"},
            dsa_announce={"DSA-9999-1": "https://www.debian.org/security/2026/dsa-9999"},
            dsa_dates={"DSA-9999-1": "2026-10-01"},
        )
        self.assertIn('data-dsa="DSA-9999-1"', html)
        self.assertIn("DSA date: 2026-10-01", html)
        self.assertIn('<select class="filter-dsa">', html)


if __name__ == "__main__":
    unittest.main()
