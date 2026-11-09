"""Port-style model of the OAuthLib token grant client checks.

"diff:N" is line N of the saved fix diff
CVE-2026-118669_oauthlib_c951a1d09f99.diff. `pre` follows the removed lines
(and the pre-fix files fetched for verification, see SOURCES.md), `post`
the added lines. Only the client-identity steps, `validate_user`,
`validate_grant_type` and `validate_scopes` are modelled; nothing from
oauthlib is imported and no HTTP request is made.

The validator is the in-memory demo of the GHSA PoC (clients `low` and
`high`) plus a client `batch` that may only use client_credentials.
"""
from dataclasses import dataclass

VERSIONS = ("pre", "post")
GRANTS = ("client_credentials", "password", "authorization_code", "refresh_token", "device_code")
MISSING = None

ALL = {"client_credentials", "password", "authorization_code", "refresh_token", "device_code"}
CLIENTS = {
    "low": {"grants": ALL, "scopes": {"read"}},
    "high": {"grants": ALL, "scopes": {"read", "admin"}},
    "batch": {"grants": {"client_credentials"}, "scopes": {"read"}},
}
# Grants whose remaining checks (code, refresh token, device code) are not
# modelled: they stop at STAGE_OK after the last modelled check.
PARTIAL = {"authorization_code", "refresh_token", "device_code"}


class OAuthError(Exception):
    """Stands in for oauthlib.oauth2.rfc6749.errors.* (name kept)."""

    def __init__(self, name, lines):
        super().__init__(name)
        self.name, self.lines = name, lines


class NotImpl(Exception):
    """Stands in for NotImplementedError raised by oauthlib."""

    def __init__(self, lines):
        super().__init__("NotImplementedError")
        self.name, self.lines = "NotImplementedError", lines


class Crash(Exception):
    """An uncaught Python exception in the pre-fix code path."""

    def __init__(self, name, lines):
        super().__init__(name)
        self.name, self.lines = name, lines


class Client:
    def __init__(self, client_id):
        self.client_id = client_id


class NoIdClient:
    """A client object without a client_id attribute."""


@dataclass
class Request:
    grant: str
    authenticated: str          # credentials sent with Basic auth, or "-"
    client_id: object           # body client_id, None if absent
    scope: str
    user_ok: bool
    client: object = None
    scopes: object = None


class Validator:
    """In-memory validator. `confidential` -> client_authentication_required.
    `set_client`: auth | none | noattr | other:<id> (what authenticate_*
    puts on request.client). `policy`: arg (authorize by the client_id
    argument, as the GHSA PoC) or client (authorize by request.client)."""

    def __init__(self, confidential, set_client, policy):
        self.confidential, self.set_client, self.policy = confidential, set_client, policy
        self.calls = {}

    def _set(self, request, who):
        if self.set_client == "auth":
            request.client = Client(who)
        elif self.set_client == "noattr":
            request.client = NoIdClient()
        elif self.set_client.startswith("other:"):
            request.client = Client(self.set_client[6:])
        # "none": leaves request.client untouched (None)

    def client_authentication_required(self, request):
        return self.confidential

    def authenticate_client(self, request):
        if request.authenticated not in CLIENTS:
            return False
        self._set(request, request.authenticated)
        return True

    def authenticate_client_id(self, client_id, request):
        if client_id not in CLIENTS:
            return False
        self._set(request, client_id)
        return True

    def _who(self, client_id, client):
        return client_id if self.policy == "arg" else getattr(client, "client_id", None)

    def validate_grant_type(self, client_id, grant_type, client, request):
        who = self._who(client_id, client)
        self.calls["grant"] = who
        return who in CLIENTS and grant_type in CLIENTS[who]["grants"]

    def validate_scopes(self, client_id, scopes, client, request):
        who = self._who(client_id, client)
        self.calls["scopes"] = who
        return who in CLIENTS and set(scopes) <= CLIENTS[who]["scopes"]

    def validate_user(self, request):
        return request.user_ok


# Call-site lines of validate_client_authentication / validate_client_confidential.
SITE_POST = {"client_credentials": "125", "password": "173", "authorization_code": "21",
             "refresh_token": "148", "device_code": "233"}
SITE_PRE = {"password": "165", "authorization_code": "21", "refresh_token": "148",
            "device_code": "233"}
GRANT_LINES = {"client_credentials": "127-128", "password": "187-188", "authorization_code": "30-31",
               "refresh_token": "154-155", "device_code": "240-241"}
SCOPE_LINES = {"client_credentials": "131-132", "password": "192", "device_code": "244"}


class Grant:
    def __init__(self, version, validator):
        self.version, self.v = version, validator

    # --- shared helpers (base.py) ------------------------------------
    def validate_grant_type(self, r, grant):
        # base.py validate_grant_type (pre-fix file L152-162, unchanged).
        if not self.v.validate_grant_type(r.client_id, grant, r.client, r):
            raise OAuthError("UnauthorizedClientError", GRANT_LINES[grant])

    def validate_scopes(self, r, grant):
        # base.py validate_scopes (pre-fix file L164-176): request.scope split,
        # default scopes of the demo validator are [].
        if not r.scopes:
            r.scopes = r.scope.split() if r.scope else []
        if not self.v.validate_scopes(r.client_id, r.scopes, r.client, r):
            raise OAuthError("InvalidScopeError", SCOPE_LINES[grant])

    def _bind(self, r, attr_lines, bind_lines):
        # diff:52-61 / diff:72-81.
        if r.client is None or not hasattr(r.client, "client_id"):
            raise NotImpl(attr_lines)
        if not r.client_id:
            r.client_id = r.client.client_id
        elif r.client_id != r.client.client_id:
            raise OAuthError("ServerError", bind_lines)

    def validate_client_confidential(self, r, site):
        # diff:41-61.
        if not self.v.authenticate_client(r):
            raise OAuthError("InvalidClientError", site + ";48-50")
        self._bind(r, site + ";52-56", site + ";58-61")

    def validate_client_public(self, r, site):
        # diff:63-81.
        if not self.v.authenticate_client_id(r.client_id, r):
            raise OAuthError("InvalidClientError", site + ";68-70")
        self._bind(r, site + ";72-76", site + ";78-81")

    def validate_client_authentication(self, r, site):
        if self.version == "post":
            # diff:83-105.
            if self.v.client_authentication_required(r):
                self.validate_client_confidential(r, site)
            else:
                self.validate_client_public(r, site)
            return
        # pre: removed lines diff:87-103.
        if self.v.client_authentication_required(r):
            if not self.v.authenticate_client(r):
                raise OAuthError("InvalidClientError", site + ";92-94")
        elif not self.v.authenticate_client_id(r.client_id, r):
            raise OAuthError("InvalidClientError", site + ";98-103")

    # --- grant handlers ------------------------------------------------
    def client_credentials(self, r):
        g = "client_credentials"
        if self.version == "post":
            self.validate_client_confidential(r, "125")
            self.validate_grant_type(r, g)
        else:
            # diff:117-124 (removed): authenticate_client, then the attribute check.
            if not self.v.authenticate_client(r):
                raise OAuthError("InvalidClientError", "117-120")
            if not hasattr(r.client, "client_id"):
                raise NotImpl("121-124")
            self.validate_grant_type(r, g)
            r.client_id = r.client_id or r.client.client_id   # diff:130 (removed)
        self.validate_scopes(r, g)
        return "130-132" if self.version == "pre" else "125;127-132"

    def password(self, r):
        g = "password"
        if self.version == "pre":
            # create_token_response calls it first (diff:165, removed).
            self.validate_client_authentication(r, "165")
            if not self.v.validate_user(r):
                raise OAuthError("InvalidGrantError", "175-179")
            if not hasattr(r.client, "client_id"):
                raise NotImpl("180-184")
            self.validate_grant_type(r, g)
            if r.client:
                r.client_id = r.client_id or r.client.client_id   # diff:190-191
        else:
            self.validate_client_authentication(r, "173")      # diff:173 (added)
            if not self.v.validate_user(r):
                raise OAuthError("InvalidGrantError", "175-179")
            self.validate_grant_type(r, g)
        self.validate_scopes(r, g)
        return "190-192" if self.version == "pre" else "173;187-192"

    def authorization_code(self, r):
        g = "authorization_code"
        self.validate_client_authentication(r, "21")
        if self.version == "pre":
            if not hasattr(r.client, "client_id"):
                raise NotImpl("23-26")
            r.client_id = r.client_id or r.client.client_id   # diff:28
        self.validate_grant_type(r, g)
        return "28;30-31" if self.version == "pre" else "21;30-31"

    def refresh_token(self, r):
        g = "refresh_token"
        self.validate_client_authentication(r, "148")
        if self.version == "pre":
            if r.client_id is None and r.client is not None:   # diff:150-152
                try:
                    r.client_id = r.client.client_id
                except AttributeError:
                    # No attribute check in pre refresh_token: Python raises.
                    raise Crash("AttributeError", "151-152") from None
        self.validate_grant_type(r, g)
        return "150-155" if self.version == "pre" else "148;154-155"

    def device_code(self, r):
        g = "device_code"
        self.validate_client_authentication(r, "233")
        if self.version == "pre":
            if not hasattr(r.client, "client_id"):
                raise NotImpl("235-238")
            self.validate_grant_type(r, g)
            r.client_id = r.client_id or r.client.client_id   # diff:243
        else:
            self.validate_grant_type(r, g)
        self.validate_scopes(r, g)
        return "243-244" if self.version == "pre" else "233;240-244"


@dataclass
class Outcome:
    version: str
    label: str
    auth_client: str
    effective_client_id: str
    grant_checked_as: str
    scopes_checked_as: str
    scopes: str
    diff_lines: str


def _s(x):
    if x is None:
        return "@none"
    if x == "":
        return "@empty"
    return str(x)


def run_case(version, grant, client_auth, authenticated, set_client, body_client_id, scope, user, policy):
    if (version not in VERSIONS or grant not in GRANTS or client_auth not in ("confidential", "public")
            or policy not in ("arg", "client") or user not in ("ok", "bad", "-")
            or not (set_client in ("auth", "none", "noattr") or set_client.startswith("other:"))):
        return Outcome(version, "BAD_INPUT", "-", "-", "-", "-", "-", "-")
    v = Validator(client_auth == "confidential", set_client, policy)
    r = Request(grant, authenticated, body_client_id, scope, user == "ok")
    g = Grant(version, v)
    try:
        lines = getattr(g, grant)(r)
    except (OAuthError, NotImpl, Crash) as e:
        label, lines = e.name, e.lines
        scopes = "-"
    else:
        auth = getattr(r.client, "client_id", None)
        split = r.client_id != auth
        if grant in PARTIAL:
            label = "STAGE_OK_SPLIT" if split else "STAGE_OK"
        else:
            label = "TOKEN_SPLIT" if split else "TOKEN"
        scopes = " ".join(r.scopes) if r.scopes is not None else "-"
        scopes = scopes or "@empty"
    auth = getattr(r.client, "client_id", None) if r.client is not None else None
    return Outcome(version, label, _s(auth), _s(r.client_id), _s(v.calls.get("grant", "-")),
                   _s(v.calls.get("scopes", "-")), scopes, lines)
