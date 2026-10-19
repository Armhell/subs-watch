#!/usr/bin/env python3
"""
ai_registrations_watch.py — Daily .ai newly-registered-domain feed.

Primary source: dontcrash/NRD GitHub repo — free, no key, daily commit of
newly-registered domains split per TLD (lists/ai.txt = yesterday's new .ai
registrations). Diffs against the known-set and Telegram-alerts the new
registrations. State: targets/.ai_watch/known.txt (inside the encrypted
blob in CI, committed back each run).

Optional enrichment: MERKLEMAP_KEY set → also pulls the full .ai zone index
(MerkleMap free API) for a wider diff.

Usage:
    python3 ai_registrations_watch.py run --state-root .
    python3 ai_registrations_watch.py status
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

REPO = Path(__file__).resolve().parent
AI_DIR_NAME = "targets/.ai_watch"
KNOWN_FILE = "known.txt"
NRD_URL = "https://raw.githubusercontent.com/dontcrash/NRD/main/lists/ai.txt"
MERKLEMAP_API = "https://www.merklemap.com/api/search"


def log(msg: str) -> None:
    print(msg, flush=True)


def load_tokens() -> None:
    env_file = Path.home() / ".config/bb-ass/tokens.env"
    if env_file.exists():
        for line in env_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                k = k.strip().removeprefix("export ").strip()
                os.environ.setdefault(k, v.strip().strip('"').strip("'"))


def pull_nrd_list() -> set[str]:
    """Yesterday's newly-registered .ai domains from dontcrash/NRD."""
    r = requests.get(NRD_URL, timeout=60)
    if r.status_code >= 300:
        raise RuntimeError(f"NRD fetch HTTP {r.status_code}")
    out: set[str] = set()
    for line in r.text.splitlines():
        dom = line.strip().lower()
        if dom.endswith(".ai") and "." in dom:
            out.add(dom)
    return out


def pull_merklemap(api_key: str) -> set[str]:
    """Optional: full .ai zone index from MerkleMap (free key, ~60 pages)."""
    headers = {"Authorization": f"Bearer {api_key}"}
    domains: set[str] = set()
    known_total = None
    page = 0
    while page <= 300:
        r = requests.get(MERKLEMAP_API,
                         params={"query": ".ai", "page": page,
                                 "api_key": api_key},
                         headers=headers, timeout=60)
        if r.status_code >= 300:
            log(f"[!] MerkleMap HTTP {r.status_code} — partial zone")
            break
        doc = r.json()
        results = doc.get("results") or []
        if known_total is None:
            known_total = doc.get("total")
            log(f"merklemap total .ai entries: {known_total}")
        for item in results:
            dom = (item.get("domain") or "").strip().lower()
            if dom:
                domains.add(dom)
        if not results or len(domains) >= (known_total or 0):
            break
        page += 1
    return domains


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="One .ai registration check")
    p_run.add_argument("--state-root", default=".",
                       help="Repo root holding targets/.ai_watch/")
    sub.add_parser("status", help="Show known-set size")
    args = ap.parse_args()

    load_tokens()
    watch_dir = Path(args.state_root if args.cmd == "run" else ".").resolve() \
        / AI_DIR_NAME
    known_path = watch_dir / KNOWN_FILE

    if args.cmd == "status":
        if known_path.exists():
            print(f"known .ai domains: "
                  f"{len(known_path.read_text().splitlines())}")
        else:
            print("no .ai known-set yet")
        return

    if requests is None:
        print("[!] requests library missing", file=sys.stderr)
        sys.exit(1)

    zone = pull_nrd_list()
    log(f"dontcrash/NRD daily .ai registrations: {len(zone)}")

    mk = os.environ.get("MERKLEMAP_KEY", "")
    if mk:
        zone |= pull_merklemap(mk)
        log(f"zone after merklemap enrichment: {len(zone)}")

    known: set[str] = set()
    if known_path.exists():
        known = {l.strip().lower() for l in known_path.read_text().splitlines()
                 if l.strip()}
    fresh = sorted(zone - known)
    log(f".ai zone: {len(zone)} | known: {len(known)} | new: {len(fresh)}")

    watch_dir.mkdir(parents=True, exist_ok=True)
    known_path.write_text("\n".join(sorted(zone)) + "\n")

    if not fresh:
        log("no new .ai registrations")
        return

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if token and chat:
        lines = [f"🆕 *New .ai registrations — "
                 f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}*",
                 f"count: *{len(fresh)}*", ""]
        lines += [f"  🆕 {d}" for d in fresh[:40]]
        if len(fresh) > 40:
            lines.append(f"  … +{len(fresh) - 40} more (full list in state)")
        text = "\n".join(lines)
        if len(text) > 4000:
            text = text[:3900] + "\n\n… (truncated)"
        from subdomain_delta import telegram_send  # noqa: E402
        ok = telegram_send(token, chat, text)
        log(f"telegram digest: {'OK' if ok else 'FAILED'}")
    else:
        log("[i] Telegram tokens missing — registrations recorded, no alert")


if __name__ == "__main__":
    main()
