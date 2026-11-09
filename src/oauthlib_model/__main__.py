"""CLI.

  python -m oauthlib_model case <pre|post> <grant> <confidential|public> <authenticated> <set_client> <body_client_id|@missing> <scope|@empty> <ok|bad|-> <arg|client>
  python -m oauthlib_model results <cases.tsv> <outdir>
"""
import hashlib
import sys
from pathlib import Path

from .fixtures import args, load_cases, tok
from .model import VERSIONS, run_case
from .sweep import sweep_csv

HEADER = ["id", "version", "label", "auth_client", "effective_client_id",
          "grant_checked_as", "scopes_checked_as", "scopes", "diff_lines"]


def row(cid, o):
    return "\t".join([cid, o.version, o.label, o.auth_client, o.effective_client_id,
                      o.grant_checked_as, o.scopes_checked_as, o.scopes, o.diff_lines])


def cases_tsv(cases):
    out = ["\t".join(HEADER)]
    for c in cases:
        for v in VERSIONS:
            out.append(row(c["id"], run_case(v, *args(c))))
    return "\n".join(out) + "\n"


def results(cases_path, outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    files = {"cases.tsv": cases_tsv(load_cases(cases_path)).encode(),
             "sweep.csv": sweep_csv().encode()}
    sums = []
    for name in sorted(files):
        (out / name).write_bytes(files[name])
        sums.append(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n")
    (out / "SHA256SUMS").write_text("".join(sums))


def main(argv):
    if len(argv) == 10 and argv[0] == "case":
        a = list(argv[1:])
        a[5] = tok(a[5])
        a[6] = tok(a[6]) or ""
        print("\t".join(HEADER[1:]))
        print(row("cli", run_case(*a)).split("\t", 1)[1])
        return 0
    if len(argv) == 3 and argv[0] == "results":
        results(argv[1], argv[2])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
