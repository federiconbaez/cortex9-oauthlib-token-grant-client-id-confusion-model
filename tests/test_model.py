"""Tests for the OAuthLib client_id confusion model. "diff:N" is a line of
CVE-2026-118669_oauthlib_c951a1d09f99.diff (see SOURCES.md)."""
import csv
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oauthlib_model import run_case
from oauthlib_model.__main__ import results
from oauthlib_model.fixtures import args, load_cases
from oauthlib_model.sweep import sweep, sweep_csv

REPO = Path(__file__).resolve().parent.parent
CASES = load_cases(REPO / "fixtures" / "cases.tsv")
BY_ID = {c["id"]: c for c in CASES}


def _load_derive():
    spec = importlib.util.spec_from_file_location("derive", REPO / "scripts" / "derive_expected.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DERIVE = _load_derive()


def run(cid, v):
    return run_case(v, *args(BY_ID[cid]))


def row(o):
    return [o.label, o.auth_client, o.effective_client_id, o.grant_checked_as,
            o.scopes_checked_as, o.scopes, o.diff_lines]


class Fixtures(unittest.TestCase):
    def test_counts(self):
        kinds = [c["kind"] for c in CASES]
        self.assertGreaterEqual(kinds.count("pos"), 8)
        self.assertGreaterEqual(kinds.count("neg"), 9)
        self.assertGreaterEqual(kinds.count("adv"), 11)
        self.assertEqual(len(BY_ID), len(CASES))

    def test_model_matches_independent_expected(self):
        lines = (REPO / "fixtures" / "expected.tsv").read_text(encoding="utf-8").splitlines()
        exp = {(f[0], f[1]): f[2:] for f in (l.split("\t") for l in lines[1:])}
        self.assertEqual(len(exp), 2 * len(CASES))
        for c in CASES:
            for v in ("pre", "post"):
                with self.subTest(case=c["id"], version=v):
                    self.assertEqual(row(run_case(v, *args(c))), exp[(c["id"], v)])

    def test_hand_labels(self):
        for c in CASES:
            with self.subTest(case=c["id"]):
                self.assertEqual(run_case("pre", *args(c)).label, c["hand_pre"])
                self.assertEqual(run_case("post", *args(c)).label, c["hand_post"])

    def test_expected_tsv_is_what_derive_produces(self):
        out = subprocess.run([sys.executable, str(REPO / "scripts" / "derive_expected.py")],
                             check=True, capture_output=True, text=True, encoding="utf-8").stdout
        self.assertEqual(out, (REPO / "fixtures" / "expected.tsv").read_text(encoding="utf-8"))


class GhsaPoc(unittest.TestCase):
    """The four assertions of the GHSA PoC, client `low` authenticated."""

    def test_pre_control_rejected_and_spoof_succeeds(self):
        for grant, user in (("client_credentials", "-"), ("password", "ok")):
            with self.subTest(grant=grant):
                ctl = run_case("pre", grant, "confidential", "low", "auth", "low", "admin", user, "arg")
                self.assertEqual(ctl.label, "InvalidScopeError")
                spoof = run_case("pre", grant, "confidential", "low", "auth", "high", "admin", user, "arg")
                self.assertEqual((spoof.label, spoof.auth_client, spoof.effective_client_id, spoof.scopes),
                                 ("TOKEN_SPLIT", "low", "high", "admin"))
                self.assertEqual((spoof.grant_checked_as, spoof.scopes_checked_as), ("high", "high"))

    def test_post_spoof_rejected_at_binding(self):
        for grant, user, site in (("client_credentials", "-", "125"), ("password", "ok", "173")):
            with self.subTest(grant=grant):
                o = run_case("post", grant, "confidential", "low", "auth", "high", "admin", user, "arg")
                self.assertEqual((o.label, o.diff_lines), ("ServerError", site + ";58-61"))
                self.assertEqual(o.grant_checked_as, "-")


class UpstreamTests(unittest.TestCase):
    """New tests added by the fix (post only)."""

    def test_authcode_client_id_discrepancy(self):          # diff:296-304
        o = run_case("post", "authorization_code", "confidential", "low", "other:high", "low", "", "-", "arg")
        self.assertEqual(o.label, "ServerError")

    def test_public_client_id_missing(self):                # diff:306-313
        o = run_case("post", "authorization_code", "public", "-", "noattr", "low", "", "-", "arg")
        self.assertEqual((o.label, o.diff_lines), ("NotImplementedError", "21;72-76"))

    def test_public_client_id_discrepancy(self):            # diff:315-324
        o = run_case("post", "authorization_code", "public", "-", "other:high", "low", "", "-", "arg")
        self.assertEqual((o.label, o.diff_lines), ("ServerError", "21;78-81"))

    def test_refresh_client_id_discrepancy(self):           # diff:345-353
        o = run_case("post", "refresh_token", "confidential", "low", "other:high", "low", "", "-", "arg")
        self.assertEqual((o.label, o.diff_lines), ("ServerError", "148;58-61"))


class Differential(unittest.TestCase):
    def test_positives(self):
        for c in CASES:
            if c["kind"] == "pos":
                with self.subTest(case=c["id"]):
                    self.assertTrue(run_case("pre", *args(c)).label.endswith("_SPLIT"))
                    self.assertEqual(run_case("post", *args(c)).label, "ServerError")

    def test_negatives_unchanged(self):
        for c in CASES:
            if c["kind"] == "neg":
                with self.subTest(case=c["id"]):
                    pre, post = run_case("pre", *args(c)), run_case("post", *args(c))
                    self.assertEqual((pre.label, pre.effective_client_id), (post.label, post.effective_client_id))
                    self.assertNotIn("SPLIT", pre.label)


class Sweep(unittest.TestCase):
    def test_invariants(self):
        n = pre_split = 0
        for _sid, a in sweep():
            n += 1
            pre, post = run_case("pre", *a), run_case("post", *a)
            self.assertNotIn("SPLIT", post.label, a)
            if post.label in ("TOKEN", "STAGE_OK"):
                self.assertEqual(post.effective_client_id, post.auth_client, a)
            if "SPLIT" in pre.label:
                pre_split += 1
                self.assertIn(post.label, ("ServerError", "NotImplementedError"), a)
            grant, mode, au, sc, body, _scope, _user, _pol = a
            if mode == "confidential" and sc == "auth" and body == au:
                # Body client_id equals the authenticated client: the fix changes nothing.
                self.assertEqual(row(pre)[:6], row(post)[:6], a)
        self.assertEqual(n, 7200)                # 4 grants x 1200 + password 2400
        self.assertGreater(pre_split, 0)

    def test_derive_sweep_matches_committed(self):
        out = subprocess.run([sys.executable, str(REPO / "scripts" / "derive_expected.py"), "sweep"],
                             check=True, capture_output=True, text=True, encoding="utf-8").stdout
        self.assertEqual(out, (REPO / "results" / "sweep.csv").read_text(encoding="utf-8"))
        self.assertEqual(sweep_csv(), out)

    def test_results_regenerate_byte_identical(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            results(REPO / "fixtures" / "cases.tsv", d1)
            results(REPO / "fixtures" / "cases.tsv", d2)
            for name in ("cases.tsv", "sweep.csv", "SHA256SUMS"):
                a = (Path(d1) / name).read_bytes()
                self.assertEqual(a, (Path(d2) / name).read_bytes())
                self.assertEqual(a, (REPO / "results" / name).read_bytes())


class Adversarial(unittest.TestCase):
    def test_bad_input(self):
        good = ("client_credentials", "confidential", "low", "auth", "low", "read", "-", "arg")
        for i, bad in ((0, "implicit"), (1, "mtls"), (3, "weird"), (6, "maybe"), (7, "both")):
            a = list(good)
            a[i] = bad
            self.assertEqual(run_case("post", *a).label, "BAD_INPUT")
        self.assertEqual(run_case("PRE", *good).label, "BAD_INPUT")

    def test_exact_comparison(self):
        for body in ("LOW", "low ", " low", "l\u043ew", "low\x00"):
            with self.subTest(body=body):
                o = run_case("post", "client_credentials", "confidential", "low", "auth", body, "read", "-", "arg")
                self.assertEqual(o.label, "ServerError")

    def test_empty_body_id_is_filled(self):
        # diff:58-59: `not request.client_id` treats '' like missing.
        o = run("a10_empty_body_id", "post")
        self.assertEqual((o.label, o.effective_client_id), ("TOKEN", "low"))

    def test_pre_refresh_without_client_id_attribute_crashes(self):
        # diff:150-152 has no attribute check in pre; post raises NotImplementedError.
        a = ("refresh_token", "confidential", "low", "noattr", None, "", "-", "arg")
        self.assertEqual((run_case("pre", *a).label, run_case("pre", *a).diff_lines), ("AttributeError", "151-152"))
        self.assertEqual(run_case("post", *a).label, "NotImplementedError")

    def test_policy_client_still_records_spoofed_id(self):
        o = run("a03_policy_client_read", "pre")
        self.assertEqual((o.label, o.grant_checked_as, o.effective_client_id), ("TOKEN_SPLIT", "low", "high"))

    def test_sweep_csv_parses(self):
        rows = list(csv.DictReader((REPO / "results" / "sweep.csv").open(encoding="utf-8")))
        self.assertEqual(len(rows), 7200)


class Practice(unittest.TestCase):
    def test_practice_levels(self):
        cc = "client_credentials"
        # 1
        self.assertEqual(run_case("pre", cc, "confidential", "low", "auth", "low", "read", "-", "arg").label, "TOKEN")
        # 2
        self.assertEqual(run_case("pre", cc, "confidential", "low", "auth", "low", "admin", "-", "arg").label,
                         "InvalidScopeError")
        # 3
        o = run_case("pre", cc, "confidential", "low", "auth", "high", "admin", "-", "arg")
        self.assertEqual((o.label, o.auth_client, o.effective_client_id), ("TOKEN_SPLIT", "low", "high"))
        # 4
        self.assertEqual(run_case("post", cc, "confidential", "low", "auth", "high", "admin", "-", "arg").label,
                         "ServerError")
        # 5
        self.assertEqual(run_case("pre", cc, "confidential", "low", "auth", "high", "admin", "-", "client").label,
                         "InvalidScopeError")
        # 6
        self.assertEqual(run_case("pre", cc, "confidential", "low", "auth", None, "read", "-", "arg").label,
                         "UnauthorizedClientError")
        # 7
        self.assertEqual(run_case("post", "password", "public", "-", "other:low", "high", "read", "ok", "arg").label,
                         "ServerError")


if __name__ == "__main__":
    unittest.main()
