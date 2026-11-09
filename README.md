# cortex9-oauthlib-token-grant-client-id-confusion-model

Offline model of **CVE-2026-118669** (GHSA-7984-qgvg-3j9c): in OAuthLib
before 4.0.0 the token grant handlers authenticate `request.client` as one
client but keep an attacker-supplied `client_id` from the request body and
pass it to `validate_grant_type()` and `validate_scopes()`. A client that
authenticates as `low` and sends `client_id=high` gets grant and scope
checks run as `high` when the application validator authorises by the
`client_id` argument. Fixed by commit
[c951a1d09f99](https://github.com/oauthlib/oauthlib/commit/c951a1d09f99f14e3240973fa83c4f4287d4753d)
(`pre` = before, `post` = after), released in 4.0.0.

Educational, offline, deterministic, Python stdlib only. oauthlib is not
installed or imported; no HTTP request is made. The validator is the
in-memory demo from the GHSA PoC (`low`: scopes `read`; `high`: `read
admin`) plus `batch`, allowed only `client_credentials`.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What the fix changes (lines of the saved diff)

| Diff lines | pre | post |
|---|---|---|
| 117-124, 130 (`client_credentials`) | `authenticate_client`, attribute check, `validate_grant_type` with the body `client_id`, *then* `client_id = client_id or client.client_id` | `validate_client_confidential` (125) before the grant check |
| 165, 180-184, 190-191 (`password`) | client auth in `create_token_response`; fill after `validate_grant_type` | `validate_client_authentication` inside `validate_token_request` (173) |
| 23-28 (`authorization_code`), 150-152 (`refresh_token`), 235-243 (`device_code`) | fill only if missing; refresh has no attribute check | removed; binding happens in base.py |
| 41-61 / 63-81 (base.py, added) | — | after authentication: `client` must have `client_id` (52-56 / 72-76); missing `client_id` is filled (58-59 / 78-79); a different one raises `ServerError` (60-61 / 80-81) |
| 83-105 (base.py) | inline confidential/public checks (87-103) | dispatch to the two helpers |
| 296-324, 345-353 (tests) | — | discrepancy → `ServerError`, missing attribute → `NotImplementedError` |

`base.py` `validate_grant_type` / `validate_scopes` (unchanged by the fix,
not in the diff) were read from the pre-fix file; see SOURCES.md.

## Differential evidence (`results/cases.tsv`)

| Case | pre | post |
|---|---|---|
| `p01` GHSA PoC, `client_credentials`, auth `low`, body `client_id=high`, `scope=admin` | `TOKEN_SPLIT`: authenticated `low`, grant and scopes checked as `high`, `admin` granted | `ServerError` (125; 58-61) |
| `p02` same with `password` | `TOKEN_SPLIT` | `ServerError` (173; 58-61) |
| `p03` `batch` (no password grant) sends `client_id=high` | `TOKEN_SPLIT` | `ServerError` |
| `p05` public client, validator sets a different client | `TOKEN_SPLIT` | `ServerError` (173; 78-81) |
| `p06`-`p08` device / authorization code / refresh | `STAGE_OK_SPLIT` | `ServerError` |
| `n01`, `n02` GHSA controls (`client_id=low`, `admin`) | `InvalidScopeError` | same |
| `a01` no `client_id` in the body, policy `arg` | `UnauthorizedClientError` (grant checked as `None`) | `TOKEN` |
| `a03` validator authorises by `request.client` | `TOKEN_SPLIT` (scopes of `low`, token recorded as `high`) | `ServerError` |

`*_SPLIT` means the request finished with `request.client_id` different
from `request.client.client_id`. `STAGE_OK` means the modelled steps passed
for a grant whose code / refresh-token / device-code checks are not modelled.

Sweep (`results/sweep.csv`, 7,200 cases): `post` never ends split; every
`post` success has `request.client_id == request.client.client_id`; every
`pre` split becomes `ServerError` or `NotImplementedError`; when the body
`client_id` equals the authenticated client the fix changes nothing.

**Model observations, not findings:** in `pre`, a `client_credentials`
request without `client_id` in the body calls `validate_grant_type(None,
…)` (the fill at diff:130 comes after the grant check), so a validator that
authorises by the argument rejects it (`a01`). `pre` `refresh_token` with a
client object lacking `client_id` raises a bare `AttributeError` at
diff:151-152. Both depend on the demo validator.

## Run

```sh
python3 tests/run.py                                    # any skip = failure
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
PYTHONPATH=src python3 -m oauthlib_model results fixtures/cases.tsv /tmp/r && diff -r results /tmp/r
PYTHONPATH=src python3 -m oauthlib_model case pre client_credentials confidential low auth high admin - arg
```

`fixtures/cases.tsv` holds hand labels; `scripts/derive_expected.py`
re-derives every row from flat step lists without importing the model; the
tests compare all three.

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
