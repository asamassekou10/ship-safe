## Hermes baseline drift

Pinned: **v0.21.0** (`v2026.8.31`, `29112bef0992`)

2 newer release(s):

| release | tag | commit | published |
| --- | --- | --- | --- |
| Hermes Agent v0.21.2 (v2026.9.11) | `v2026.9.11` | `` | 2026-09-11T19:20:31Z |
| Hermes Agent v0.21.1 (v2026.9.7) | `v2026.9.7` | `` | 2026-09-07T22:17:01Z |

### Surfaces with upstream changes

Each of these needs its detector re-checked against the new snapshot. **No status may move to covered without that.**

- **acp** — 12 file(s) changed
  - `acp_adapter/auth.py`
  - `acp_adapter/commands.py`
  - `acp_adapter/content.py`
  - `acp_adapter/edit_approval.py`
  - `acp_adapter/entry.py`
  - `acp_adapter/events.py`
  - `acp_adapter/model_catalog.py`
  - `acp_adapter/permissions.py`
  - `acp_adapter/provenance.py`
  - `acp_adapter/server.py`
  - ...and 2 more

### What this pull request does not do

Nothing is updated. The baseline JSON, the coverage matrix and every status are untouched. Moving the pin is a reviewed change that follows the procedure in `docs/hermes-coverage-matrix.md`, including re-checking the known-CVE record.
