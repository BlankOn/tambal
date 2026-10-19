#!/usr/bin/env python3
"""Tests for the `--image-packages` image-scoped report.

Run with:  python3 -m unittest test_tambal_image -v

The tests replace `tambal.version_lt` with a small pure-Python dpkg comparator
so they also run on macOS, where dpkg is not installed. The production code
still uses `dpkg --compare-versions`.
"""
import os
import tempfile
import unittest

import tambal


def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while ((i < len(a) and not a[i].isdigit())
               or (j < len(b) and not b[j].isdigit())):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    upstream, _, revision = v.rpartition("-")
    if not upstream:
        upstream, revision = v, ""
    return epoch, upstream, revision


def pure_version_lt(a, b):
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea < eb
    r = _verrevcmp(ua, ub)
    if r:
        return r < 0
    return _verrevcmp(ra, rb) < 0


def info(status, fixed=None, description=""):
    sid = {"status": status}
    if fixed is not None:
        sid["fixed_version"] = fixed
    return {"releases": {"sid": sid}, "description": description}


class ImageClassificationTest(unittest.TestCase):
    def setUp(self):
        self._real_version_lt = tambal.version_lt
        tambal.version_lt = pure_version_lt

    def tearDown(self):
        tambal.version_lt = self._real_version_lt

    def test_manifest_parsing_local_path_and_arch_suffix(self):
        with tempfile.NamedTemporaryFile("w", suffix=".packages", delete=False) as fh:
            fh.write("libcurl4t64:amd64\t8.22.0-1\n")
            fh.write("openssl\t3.6.4-1\n")
            path = fh.name
        try:
            manifest = tambal.load_image_manifest(path)
        finally:
            os.unlink(path)
        self.assertEqual(manifest, {"libcurl4t64": "8.22.0-1", "openssl": "3.6.4-1"})

    def test_binary_to_source_mapping_uses_sources_binary_list(self):
        manifest = {"libcurl4t64": "8.22.0-1"}
        binary_index = {
            "libcurl4t64": {
                "source": "curl",
                "source_version": None,
                "version": "8.22.0-1",
            },
        }
        index, unmapped = tambal.build_image_source_index(
            manifest, binary_index, {"curl": "8.23.0-1"})
        self.assertEqual(index, {"curl": "8.22.0-1"})
        self.assertEqual(unmapped, [])

    def test_unmapped_binary_is_kept_as_source_with_null_archive(self):
        index, unmapped = tambal.build_image_source_index(
            {"third-party": "1.0-1"}, {}, {})
        self.assertEqual(index, {"third-party": "1.0-1"})
        self.assertEqual(unmapped, ["third-party"])
        tracker = {"third-party": {"CVE-1": info("resolved", "1.1-1")}}
        findings = tambal.build_image_findings(index, {}, tracker)
        self.assertEqual(findings[0]["state"], "needs_sync")
        self.assertIsNone(findings[0]["archive_version"])

    def test_bin_nmu_is_stripped(self):
        index, _ = tambal.build_image_source_index(
            {"accountsservice": "23.13.9-8+b2"},
            {"accountsservice": {"source": "accountsservice",
                                 "source_version": None,
                                 "version": "23.13.9-8"}},
            {"accountsservice": "23.13.9-8"},
        )
        self.assertEqual(index, {"accountsservice": "23.13.9-8"})

    def test_epoch_is_respected(self):
        self.assertTrue(pure_version_lt("1:2.3.3-4.1", "1:2.3.3-5"))
        self.assertFalse(pure_version_lt("1:2.3.3-5", "1:2.3.3-4.1"))

    def test_linux_prefix_trap_is_neutralised(self):
        # `7.8.0+7.1.13-1` must not sort above the 7.1.13 source version.
        index, _ = tambal.build_image_source_index(
            {"linux-image-amd64-dbg": "7.8.0+7.1.13-1"},
            {"linux-image-amd64-dbg": {"source": "linux",
                                       "source_version": None,
                                       "version": "7.8.0+7.1.13-1"}},
            {"linux": "7.1.13-1"},
        )
        self.assertEqual(index, {"linux": "7.1.13-1"})

        tracker = {"linux": {"CVE-1": info("resolved", "7.2.6-1")}}
        findings = tambal.build_image_findings(index, {"linux": "7.1.13-1"}, tracker)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["state"], "needs_sync")

    def test_fixable_now_requires_archive_at_or_above_fix(self):
        tracker = {"pkg": {"CVE-1": info("resolved", "1.1-1")}}
        findings = tambal.build_image_findings(
            {"pkg": "1.0-1"}, {"pkg": "1.1-1"}, tracker)
        self.assertEqual(findings[0]["state"], "fixable_now")

    def test_newer_archive_below_sid_fix_is_not_fixable(self):
        # Kernel-style case: image 7.1.12, archive 7.1.13, sid fix 7.2.6.
        tracker = {"linux": {"CVE-1": info("resolved", "7.2.6-1")}}
        findings = tambal.build_image_findings(
            {"linux": "7.1.12-1"}, {"linux": "7.1.13-1"}, tracker)
        self.assertEqual(findings[0]["state"], "needs_sync")

    def test_manifest_older_than_archive_is_fixable(self):
        tracker = {"pkg": {"CVE-1": info("resolved", "2.0-1")}}
        findings = tambal.build_image_findings(
            {"pkg": "1.0-1"}, {"pkg": "2.0-1"}, tracker)
        self.assertEqual(findings[0]["state"], "fixable_now")

    def test_package_absent_from_archive_degrades_to_needs_sync(self):
        tracker = {"pkg": {"CVE-1": info("resolved", "1.1-1")}}
        findings = tambal.build_image_findings({"pkg": "1.0-1"}, {}, tracker)
        self.assertEqual(findings[0]["state"], "needs_sync")
        self.assertIsNone(findings[0]["archive_version"])
        self.assertIsNone(findings[0]["our_version"])

    def test_no_fix_is_reachable_from_open_status(self):
        tracker = {"pkg": {"CVE-1": info("open")}}
        findings = tambal.build_image_findings({"pkg": "1.0-1"}, {"pkg": "1.0-1"}, tracker)
        self.assertEqual(findings[0]["state"], "no_fix")
        self.assertIsNone(findings[0]["fixed_version"])

    def test_fixed_package_is_not_reported(self):
        tracker = {"pkg": {"CVE-1": info("resolved", "1.0-1")}}
        findings = tambal.build_image_findings({"pkg": "1.0-1"}, {"pkg": "1.0-1"}, tracker)
        self.assertEqual(findings, [])

    def test_html_report_has_state_column_and_counters(self):
        tracker = {"pkg": {"CVE-1": info("resolved", "1.1-1")}}
        findings = tambal.build_image_findings(
            {"pkg": "1.0-1"}, {"pkg": "1.1-1"}, tracker)
        with tempfile.TemporaryDirectory() as tmp:
            tambal.write_html_report(findings, tmp, "https://example.invalid/")
            with open(os.path.join(tmp, "index.html")) as fh:
                html = fh.read()
        self.assertIn("<th>Status</th>", html)
        self.assertIn("Upgrade available: 1", html)
        self.assertIn('id="filter-state"', html)
        self.assertIn('data-state="fixable_now"', html)


if __name__ == "__main__":
    unittest.main()
