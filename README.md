# subs-watch (public, encrypted-state edition)

Cloud-hosted new-subdomain monitoring on GitHub Actions — **unlimited free
minutes**, because this repo is public. Everything identifying the monitored
scope lives inside **`state.tar.gz.enc`** (age-encrypted blob); plaintext
targets never touch the repo or the workflow logs.

> The private key lives in repo secrets (`AGE_PRIVATE_KEY`) and nowhere else.
> Without it, this repo is just a scanner script and a 1 MB blob.

## What it does (twice daily, 02:30 + 14:30 UTC)

1. 9 parallel jobs: 1 × active targets + 8 × long-tail shards (~3,700 domains total)
2. passive discovery (subfinder → CT logs, OTX, RapidDNS, …), liveness probe (httpx)
   on brand-new subs only
3. diff vs encrypted baselines; new subs → **one Telegram digest** (⚡ = priority)
4. shards' state artifacts merge → re-encrypt → commit back

## Files

- `state.tar.gz.enc` — the encrypted everything (scope, state, baselines)
- `age_pubkey.txt` — public half; used to re-encrypt state in CI
- `subs_watch.py` / `subdomain_delta.py` / `merge_state.py` — engine
- `.github/workflows/subs-watch.yml` — schedule + matrix + merge job

`targets.txt`, `longtail_*.txt`, and `targets/` are **gitignored on purpose** —
they exist only inside the encrypted blob, decrypted transiently at run time.
