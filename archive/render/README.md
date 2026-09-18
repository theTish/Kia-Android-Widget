# Retired: the Render / Replit deployment

This was the API's first home. It is kept for reference, not for running —
nothing deploys from this folder and nothing should.

## What it was

`main.py` is a standalone Flask app, a sibling of `api/index.py` rather than a
copy of it: same endpoints, different internals. `Procfile`, `render.yaml` and
`runtime.txt` ran it on Render; `.replit` ran it on Replit; `requirements.txt`
is the one Render installed from, which is why the repo had two of them.

## Why it stopped

Two reasons, and the second is the one that matters.

It **diverged**. `/status` in `api/index.py` grew charge limits, warnings,
service, climate readback and location; `main.py`'s did not. Every client reads
the newer contract.

It **cannot log in any more**. Kia Canada now requires an OTP on a new device,
and the OTP flow — the endpoints, the device-ID seeding that earns 90 days of
trust — only exists in `api/index.py`. `main.py` would fail at authentication
on its first cold start and there is no configuration that fixes that.

The Render service was already returning 404 before this was archived, so
nothing was switched off by moving these files.

## What runs instead

- **Primary:** `api/index.py` on the Oracle box, built from `deploy/Dockerfile`,
  deployed by `deploy/kia-deploy.sh`. See `deploy/README.md`.
- **Standby:** the same `api/index.py` on Vercel, via `vercel.json`. Cold, and
  slow because of it, but it is there when the box is not.

Both install from `api/requirements.txt`. Local development and the tests use
`pyproject.toml` with `uv sync`.

## If you ever want it back

`git log -- archive/render/main.py` has the history. But port the OTP flow from
`api/index.py` first, or it will not get past the front door.
