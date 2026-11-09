# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only; the NVD response carries the timestamp
2026-11-09T11:34:04 (UTC). Each SHA-256 in the first table was checked
against `sources/cve2026/SHA256SUMS` before use. `diff:N` in this repo is
line N of the saved diff.

| Source | URL | Commit | Used for | SHA-256 of copy |
|---|---|---|---|---|
| Fix diff `diffs/CVE-2026-118669_oauthlib_c951a1d09f99.diff` (17 files, +119/-70) | https://github.com/oauthlib/oauthlib/commit/c951a1d09f99f14e3240973fa83c4f4287d4753d | c951a1d09f99f14e3240973fa83c4f4287d4753d ("Organized validate_client functions for all grant to avoid mistake in grnat implementation", author date 2026-07-11T16:25:12+02:00; parent 68b292affd4e45daeb5842c70e1092f025f234e1) | handlers diff:15-31, 109-132, 134-155, 157-192, 227-244; base.py helpers diff:41-105; new tests diff:296-324, 345-353 | fe71a440c0ad47dafcdf294039b3c80b0d291834b856e3e67878838980652a41 |
| GHSA record `ghsa_rec/CVE-2026-118669.json` (GHSA-7984-qgvg-3j9c, reviewed) | https://github.com/oauthlib/oauthlib/security/advisories/GHSA-7984-qgvg-3j9c | references c951a1d | mechanism, affected surface (`client_credentials`, `password`), PoC validator and expected output, suggested remediation, `< 4.0.0` → 4.0.0, CWE-863 | 3dc2a6214b5e31961e9c3f88b121ee26146e4d46fb94c473deb38ffa85f6bc95 |
| NVD record `nvd/CVE-2026-118669.json` (Awaiting Analysis, published 2026-10-28) | https://nvd.nist.gov/vuln/detail/CVE-2026-118669 | references c951a1d, PR #920, v4.0.0 | description, CVSS 4.0 8.4 | 207efa3b51135e6b79ef13a684a42029fdf51b44da0b3e1e31e918380673b1a9 |
| cve.org record `cveorg/CVE-2026-118669.json` (PUBLISHED) | https://www.cve.org/CVERecord?id=CVE-2026-118669 | references c951a1d | affected `< 4.0.0`, CWE-863 | 5fa02a5f5ef086c8a3c7d3947f2a9351487ad4e5a2bffbfe70a68325ca8b4d5a |

Supplementary files, fetched live on 2026-11-09 from
`https://raw.githubusercontent.com/oauthlib/oauthlib/<commit>/<path>` to
read code that the diff does not show. **They are not in
`sources/cve2026/SHA256SUMS`** and are not stored in this repo.

| Path | Commit | Used for | SHA-256 |
|---|---|---|---|
| `oauthlib/oauth2/rfc6749/grant_types/base.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | `validate_grant_type` (L152-162, `UnauthorizedClientError`), `validate_scopes` (L164-176, default scopes, `InvalidScopeError`) | f787045b4cb9c2f0de8cf919252eeee81fd205f16499ab1125ded23283017c79 |
| `oauthlib/oauth2/rfc6749/grant_types/client_credentials.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | pre order of checks (L106-119) | bc843de7a32ad881ce3f70cb3e774ffbe1d829e2c59a5e5d3c976381bde3c776 |
| `oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | pre `create_token_response` (L86-94) and `validate_token_request` (L168-188) | 33ba6804c8914a21cd5a07913ea672cd37914d3fb33b667b8c44a3363731f086 |
| `oauthlib/oauth2/rfc6749/grant_types/refresh_token.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | context of diff:138-155 | ac1777053f93440506f46c88c3d44fc89ac335a140635c124d6f8d70e1ca974c |
| `oauthlib/oauth2/rfc6749/grant_types/authorization_code.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | context of diff:19-31 | dc277bb9630735e7650072eb1a6702b00ed3276f494490371455ac8899b33354 |
| `oauthlib/oauth2/rfc8628/grant_types/device_code.py` | 68b292affd4e45daeb5842c70e1092f025f234e1 | context of diff:231-244 | 5062dd9adc68a100dcd72b1f71e16050581cd9ae55b19b0bd24d16bcc4f905c5 |

Other checks (live, 2026-11-09): the saved diff was re-downloaded from the
commit URL and is byte-identical; the GitHub compare
`c951a1d09f99...v4.0.0` reports `ahead` (68 commits), i.e. the fix is an
ancestor of the v4.0.0 tag.

Instructions addressed to a tool or agent: none found in these sources
(searched the diff, GHSA, NVD and cve.org records, including invisible
Unicode characters). The GHSA "Suggested Remediation" is ordinary advisory
text, and the model follows the actual fix, not that suggestion.
