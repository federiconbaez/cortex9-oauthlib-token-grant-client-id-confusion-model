"""Reader for fixtures/cases.tsv. Tokens: @missing (None), @empty ('')."""
FIELDS = ("id", "kind", "grant", "client_auth", "authenticated", "set_client",
          "body_client_id", "scope", "user", "policy", "hand_pre", "hand_post")


def tok(s):
    return {"@missing": None, "@empty": ""}.get(s, s)


def load_cases(path):
    cases = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            f = line.split("\t")
            if len(f) != len(FIELDS):
                raise ValueError(f"bad fixture line: {line!r}")
            c = dict(zip(FIELDS, f))
            c["body_client_id"] = tok(c["body_client_id"])
            c["scope"] = tok(c["scope"]) or ""
            cases.append(c)
    return cases


def args(c):
    return (c["grant"], c["client_auth"], c["authenticated"], c["set_client"],
            c["body_client_id"], c["scope"], c["user"], c["policy"])
