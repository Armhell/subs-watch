#!/usr/bin/env python3
"""
ai_registrations_watch.py — Daily .ai newly-registered-domain feed.

Pulls the full .ai zone index from MerkleMap (free API key required —
sign up at merklemap.com), diffs against the known-set, and Telegram-alerts
the newly registered .ai domains. Runs in the GitHub Actions nightly
(state committed back) and locally.

Usage:
    python3 ai_registrations_watch.py run --state-root .
    python3 ai_registrations_watch.py status

Env:
    MERKLEMAP_KEY       free API key from merklemap.com (required)
    TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   from tokens.env / Actions secrets
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
API = "https://www.merklemap.com/api/search"


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


def pull_zone(api_key: str) -> set[str]:
    """Fetch all indexed .ai domains from MerkleMap (paginated)."""
    if requests is None:
        raise RuntimeError("requests library missing")
    headers = {"Authorization": f"Bearer {api_key}"}
    known_total = None
    page = 0
    domains: set[str] = set()
    while True:
        r = requests.get(API, params={"query": ".ai", "page": page,
                                      "api_key": api_key},
                         headers=headers, timeout=60)
        if r.status_code == 429:
            log("[!] MerkleMap rate limit hit — try again later")
            break
        if r.status_code >= 300:
            log(f"[!] MerkleMap API {r.status_code}: {r.text[:150]}")
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
        if page > 300:  # hard safety cap
            break
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
    watch_dir = Path(args.state_root if args.cmd == "run" else ".") \
        .resolve() / AI_DIR_NAME
    known_path = watch_dir / KNOWN_FILE

    if args.cmd == "status":
        if known_path.exists():
            print(f"known .ai domains: {len(known_path.read_text().splitlines())}")
        else:
            print("no .ai known-set yet")
        return

    key = os.environ.get("MERKLEMAP_KEY", "")
    if not key:
        log("[i] MERKLEMAP_KEY not set — .ai registration feed skipped "
            "(free key at merklemap.com)")
        return
    zone = pull_zone(key)
    if not zone:
        log("[!] empty zone pull — aborting without state change")
        return

    known: set[str] = set()
    if known_path.exists():
        known = {l.strip().lower() for l in known_path.read_text().splitlines()
                 if l.strip()}
    fresh = sorted(zone - known)
    log(f".ai zone: {len(zone)} indexed | known: {len(known)} | new: {len(fresh)}")

    # Commit the full zone as the new known-set (even on notify failure —
    # these domains are now 'seen')
    watch_dir.mkdir(parents=True, exist_ok=True)
    known_path.write_text("\n".join(sorted(zone)) + "\n")

    if not fresh:
        return

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if token and chat:
        lines = [f"🆕 *New .ai registrations — "
                 f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}*",
                 f"count: *{len(fresh)}*", ""]
        lines += [f"  🆕 {d}" for d in fresh[:40]]
        if len(fresh) > 40:
            lines.append(f"  … +{len(fresh) - 40} more")
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
