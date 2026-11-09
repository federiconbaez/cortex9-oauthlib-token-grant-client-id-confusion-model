"""Fixed sweep grid (order matters: results/sweep.csv depends on it)."""
from .model import GRANTS, run_case

AUTH = ("confidential", "public")
AUTHENTICATED = ("low", "high", "batch", "bad")
SET_CLIENT = ("auth", "none", "noattr", "other:low", "other:high")
BODY = (None, "low", "high", "batch", "ghost")
SCOPE = ("", "read", "admin")
POLICY = ("arg", "client")


def _s(x):
    return "@missing" if x is None else ("@empty" if x == "" else x)


def sweep():
    n = 0
    for grant in GRANTS:
        users = ("ok", "bad") if grant == "password" else ("-",)
        for ca in AUTH:
            for au in AUTHENTICATED:
                for sc in SET_CLIENT:
                    for body in BODY:
                        for scope in SCOPE:
                            for user in users:
                                for pol in POLICY:
                                    n += 1
                                    yield "w%05d" % n, (grant, ca, au, sc, body, scope, user, pol)


def sweep_csv():
    out = ["id,grant,client_auth,authenticated,set_client,body_client_id,scope,user,policy,"
           "pre_label,pre_effective,post_label,post_effective"]
    for sid, a in sweep():
        pre, post = run_case("pre", *a), run_case("post", *a)
        out.append(",".join([sid, a[0], a[1], a[2], a[3], _s(a[4]), _s(a[5]), a[6], a[7],
                             pre.label, pre.effective_client_id, post.label, post.effective_client_id]))
    return "\n".join(out) + "\n"
