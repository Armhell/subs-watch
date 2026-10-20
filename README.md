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

## Telegram feeds

- **Subdomains** — one digest from the merge job, twice daily, only when a
  run finds new subdomains (`TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`).
- **`.ai` BB matches** — `ai_bb_match.py` runs after the daily NRD fetch and
  sends only `.ai` domains that match a BB program scope or have explicit
  bug-bounty evidence. Raw `.ai` lists stay in the encrypted state.
- **Cert alerts** — `subs-certpoll` records state but does not send to the
  BB chat. Certstream cert matches use separate `CERT_TELEGRAM_*` creds.

## Files

- `state.tar.gz.enc` — the encrypted everything (scope, state, baselines)
- `age_pubkey.txt` — public half; used to re-encrypt state in CI
- `subs_watch.py` / `subdomain_delta.py` / `merge_state.py` — engine
- `ai_registrations_watch.py` — daily NRD `.ai` fetch/resolve/classify
- `ai_bb_match.py` — `.ai` → BB-scope matcher + Telegram digest
- `paid_ai_roots.json` — paid `.ai` scopes missing from the arkadiyt index
- `.github/workflows/subs-watch.yml` — schedule + matrix + merge job

`targets.txt`, `longtail_*.txt`, and `targets/` are **gitignored on purpose** —
they exist only inside the encrypted blob, decrypted transiently at run time.
