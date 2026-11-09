#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv and results/sweep.csv.

Written from the saved diff CVE-2026-118669_oauthlib_c951a1d09f99.diff and
the GHSA PoC validator, NOT from src/: it does not import the model. Each
(version, grant) is a flat list of step names read off the diff in order;
an interpreter walks the list over a plain dict state. The model in src/ is
instead a port of the grant handler methods, so a mistake in either one
shows up as a mismatch.

  derive_expected.py          -> fixtures/expected.tsv on stdout
  derive_expected.py sweep    -> results/sweep.csv on stdout
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
FIVE = {"client_credentials", "password", "authorization_code", "refresh_token", "device_code"}
GRANTS_OF = {"low": FIVE, "high": FIVE, "batch": {"client_credentials"}}
SCOPES_OF = {"low": {"read"}, "high": {"read", "admin"}, "batch": {"read"}}

# Step programs. "auth_conf" = authenticate_client, "auth_dispatch_pre" =
# pre validate_client_authentication (diff:87-103), "auth_dispatch_post" =
# post validate_client_authentication (diff:83-105) which runs
# auth_conf/auth_pub followed by "bind" (diff:52-61 / 72-81).
PROGRAMS = {
    ("pre", "client_credentials"): [("auth_conf", "117-120"), ("hasattr", "121-124"), ("grant", "127-128"),
                                    ("fill_or", None), ("scopes", "131-132"), ("done", "130-132")],
    ("post", "client_credentials"): [("auth_conf_bound", "125"), ("grant", "127-128"), ("scopes", "131-132"),
                                     ("done", "125;127-132")],
    ("pre", "password"): [("auth_dispatch_pre", "165"), ("user", "175-179"), ("hasattr", "180-184"),
                          ("grant", "187-188"), ("fill_or_if_client", None), ("scopes", "192"), ("done", "190-192")],
    ("post", "password"): [("auth_dispatch_post", "173"), ("user", "175-179"), ("grant", "187-188"),
                           ("scopes", "192"), ("done", "173;187-192")],
    ("pre", "authorization_code"): [("auth_dispatch_pre", "21"), ("hasattr", "23-26"), ("fill_or", None),
                                    ("grant", "30-31"), ("partial", "28;30-31")],
    ("post", "authorization_code"): [("auth_dispatch_post", "21"), ("grant", "30-31"), ("partial", "21;30-31")],
    ("pre", "refresh_token"): [("auth_dispatch_pre", "148"), ("fill_if_none", None), ("grant", "154-155"),
                               ("partial", "150-155")],
    ("post", "refresh_token"): [("auth_dispatch_post", "148"), ("grant", "154-155"), ("partial", "148;154-155")],
    ("pre", "device_code"): [("auth_dispatch_pre", "233"), ("hasattr", "235-238"), ("grant", "240-241"),
                             ("fill_or", None), ("scopes", "244"), ("partial", "243-244")],
    ("post", "device_code"): [("auth_dispatch_post", "233"), ("grant", "240-241"), ("scopes", "244"),
                              ("partial", "233;240-244")],
}

NOID = "<object without client_id>"


def client_after(set_client, who):
    if set_client == "auth":
        return who
    if set_client == "none":
        return None
    if set_client == "noattr":
        return NOID
    return set_client.split(":", 1)[1]


def has_id(c):
    return c is not None and c != NOID


def show(x):
    return "@none" if x is None else ("@empty" if x == "" else x)


def derive(version, grant, mode, authenticated, set_client, body, scope, user, policy):
    st = {"client": None, "client_id": body, "scopes": None, "g": "-", "s": "-"}

    def end(label, lines, scopes="-"):
        auth = st["client"] if has_id(st["client"]) else None
        return [label, show(auth), show(st["client_id"]), show(st["g"]) if st["g"] != "-" else "-",
                show(st["s"]) if st["s"] != "-" else "-", scopes, lines]

    def who():
        if policy == "arg":
            return st["client_id"]
        return st["client"] if has_id(st["client"]) else None

    def auth_conf():
        if authenticated not in GRANTS_OF:
            return False
        st["client"] = client_after(set_client, authenticated)
        return True

    def auth_pub():
        if st["client_id"] not in GRANTS_OF:
            return False
        st["client"] = client_after(set_client, st["client_id"])
        return True

    def bind(site, attr, mism):
        if not has_id(st["client"]):
            return ("NotImplementedError", site + ";" + attr)
        if not st["client_id"]:
            st["client_id"] = st["client"]
        elif st["client_id"] != st["client"]:
            return ("ServerError", site + ";" + mism)
        return None

    for step, lines in PROGRAMS[(version, grant)]:
        if step == "auth_conf":
            if not auth_conf():
                return end("InvalidClientError", lines)
        elif step == "auth_conf_bound":
            if not auth_conf():
                return end("InvalidClientError", lines + ";48-50")
            err = bind(lines, "52-56", "58-61")
            if err:
                return end(*err)
        elif step == "auth_dispatch_pre":
            if mode == "confidential":
                if not auth_conf():
                    return end("InvalidClientError", lines + ";92-94")
            elif not auth_pub():
                return end("InvalidClientError", lines + ";98-103")
        elif step == "auth_dispatch_post":
            if mode == "confidential":
                if not auth_conf():
                    return end("InvalidClientError", lines + ";48-50")
                err = bind(lines, "52-56", "58-61")
            else:
                if not auth_pub():
                    return end("InvalidClientError", lines + ";68-70")
                err = bind(lines, "72-76", "78-81")
            if err:
                return end(*err)
        elif step == "hasattr":
            if not has_id(st["client"]):
                return end("NotImplementedError", lines)
        elif step == "user":
            if user != "ok":
                return end("InvalidGrantError", lines)
        elif step == "fill_or":
            st["client_id"] = st["client_id"] or st["client"]
        elif step == "fill_or_if_client":
            if st["client"] is not None:
                st["client_id"] = st["client_id"] or st["client"]
        elif step == "fill_if_none":
            if st["client_id"] is None and st["client"] is not None:
                if st["client"] == NOID:
                    return end("AttributeError", "151-152")
                st["client_id"] = st["client"]
        elif step == "grant":
            w = who()
            st["g"] = w
            if not (w in GRANTS_OF and grant in GRANTS_OF[w]):
                return end("UnauthorizedClientError", lines)
        elif step == "scopes":
            st["scopes"] = scope.split() if scope else []
            w = who()
            st["s"] = w
            if not (w in SCOPES_OF and set(st["scopes"]) <= SCOPES_OF[w]):
                return end("InvalidScopeError", lines)
        elif step in ("done", "partial"):
            split = st["client_id"] != (st["client"] if has_id(st["client"]) else None)
            base = "TOKEN" if step == "done" else "STAGE_OK"
            sc = "-" if st["scopes"] is None else (" ".join(st["scopes"]) or "@empty")
            return end(base + ("_SPLIT" if split else ""), lines, sc)
    raise AssertionError("program without an end step")


def tok(s):
    return {"@missing": None, "@empty": ""}.get(s, s)


def fixtures(path):
    out = ["\t".join(["id", "version", "label", "auth_client", "effective_client_id",
                      "grant_checked_as", "scopes_checked_as", "scopes", "diff_lines"])]
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) != 12:
            sys.exit("bad fixture line: %r" % line)
        cid, _k, grant, mode, au, sc, body, scope, user, pol, hp, hq = f
        for version, hand in (("pre", hp), ("post", hq)):
            r = derive(version, grant, mode, au, sc, tok(body), tok(scope) or "", user, pol)
            if r[0] != hand:
                sys.exit("%s/%s: derived %s != hand label %s" % (cid, version, r[0], hand))
            out.append("\t".join([cid, version] + r))
    return "\n".join(out) + "\n"


def sweep():
    out = ["id,grant,client_auth,authenticated,set_client,body_client_id,scope,user,policy,"
           "pre_label,pre_effective,post_label,post_effective"]
    n = 0
    for grant in ("client_credentials", "password", "authorization_code", "refresh_token", "device_code"):
        for mode in ("confidential", "public"):
            for au in ("low", "high", "batch", "bad"):
                for sc in ("auth", "none", "noattr", "other:low", "other:high"):
                    for body in (None, "low", "high", "batch", "ghost"):
                        for scope in ("", "read", "admin"):
                            for user in (("ok", "bad") if grant == "password" else ("-",)):
                                for pol in ("arg", "client"):
                                    n += 1
                                    a = derive("pre", grant, mode, au, sc, body, scope, user, pol)
                                    b = derive("post", grant, mode, au, sc, body, scope, user, pol)
                                    out.append(",".join(["w%05d" % n, grant, mode, au, sc,
                                                         "@missing" if body is None else body,
                                                         scope or "@empty", user, pol, a[0], a[2], b[0], b[2]]))
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "sweep":
        sys.stdout.write(sweep())
    else:
        sys.stdout.write(fixtures(sys.argv[1] if len(sys.argv) > 1 else HERE / "fixtures" / "cases.tsv"))


if __name__ == "__main__":
    main()
