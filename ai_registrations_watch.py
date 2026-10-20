#!/usr/bin/env python3
"""
ai_registrations_watch.py — Daily .ai newly-registered-domain feed with
noise filtering.

Source: dontcrash/NRD GitHub repo — free, no key, daily commit of
newly-registered .ai domains (lists/ai.txt = yesterday's registrations).

Noise filter: most fresh registrations are parked/unclaimed with no DNS.
Every new domain is resolved (async DNS, pure python) — only domains that
actually RESOLVE are alerted; resolving ones are probed with httpx for
status/title when the binary is available.

Delivery: opt-in via AI_TELEGRAM_BOT_TOKEN / AI_TELEGRAM_CHAT_ID, kept
separate from the bug-bounty program chat. One summary + the FULL lists as
.txt attachments; without those vars, lists are written to state only.

State: targets/.ai_watch/known.txt (inside the encrypted blob in CI,
committed back each run).

Usage:
    python3 ai_registrations_watch.py run --state-root .
    python3 ai_registrations_watch.py status
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
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
RESOLVE_CONCURRENCY = 150
RESOLVE_TIMEOUT = 8
HTTPX_CAP = 3000


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


# ----- DNS resolution -----

async def _resolve_one(domain: str, loop, sem: asyncio.Semaphore) -> tuple[str, str] | None:
    async with sem:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET),
                timeout=RESOLVE_TIMEOUT)
            ip = infos[0][4][0] if infos else ""
            return (domain, ip) if ip else None
        except Exception:
            return None


async def resolve_many_py(domains: list[str]) -> dict[str, str]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(RESOLVE_CONCURRENCY)
    tasks = [_resolve_one(d, loop, sem) for d in domains]
    out: dict[str, str] = {}
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            out[res[0]] = res[1]
    return out


def resolve_domains(domains: list[str], state_root: Path) -> dict[str, str]:
    """Fast path: dnsx binary (massively parallel). Fallback: python async."""
    import shutil
    import subprocess
    if shutil.which("dnsx"):
        infile = Path(state_root) / AI_DIR_NAME / "resolve_in.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        infile.write_text("\n".join(domains) + "\n")
        try:
            r = subprocess.run(
                ["dnsx", "-l", str(infile), "-a", "-resp", "-silent",
                 "-no-color", "-json", "-r", "1.1.1.1,8.8.8.8"],
                capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            log("[!] dnsx timed out — falling back to python resolver")
            return asyncio.run(resolve_many_py(domains))
        out: dict[str, str] = {}
        for line in r.stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (j.get("host") or "").strip().lower()
            ips = j.get("a") or []
            if host and ips:
                out[host] = ips[0]
        log(f"dnsx resolved {len(out)} / {len(domains)}")
        return out
    log("[i] dnsx not found — using python resolver (slow)")
    return asyncio.run(resolve_many_py(domains))


# ----- httpx liveness probe (optional; binary if present) -----

def probe_httpx(domains: list[str], cap: int) -> list[dict]:
    import shutil
    import subprocess
    if not shutil.which("httpx") or not domains:
        return []
    probe = domains[:cap]
    tmp = Path("/tmp") / "ai_httpx_in.txt"
    tmp.write_text("\n".join(probe) + "\n")
    try:
        r = subprocess.run(
            ["httpx", "-l", str(tmp), "-silent", "-no-color", "-json",
             "-status-code", "-title", "-follow-redirects"],
            capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    out: list[dict] = []
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or j.get("url") or "").strip().lower()
        if host.startswith(("http://", "https://")):
            host = host.split("://", 1)[1].split("/", 1)[0]
        if not host:
            continue
        out.append({"host": host, "status": j.get("status_code") or "",
                    "title": (j.get("title") or "").strip()[:70]})
    return out


# ----- telegram delivery -----

def tg_send_text(token: str, chat: str, text: str) -> bool:
    r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat, "text": text,
                            "parse_mode": "Markdown",
                            "disable_web_page_preview": True},
                      timeout=15)
    return r.status_code < 300


def tg_send_file(token: str, chat: str, path: Path, caption: str) -> bool:
    with path.open("rb") as fh:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendDocument",
                          data={"chat_id": chat, "caption": caption[:1000]},
                          files={"document": fh}, timeout=60)
    return r.status_code < 300


def load_keywords() -> dict[str, str]:
    """Load curated keyword→category map from ai_keywords.txt (script dir,
    then cwd). Bracket-tagged comment lines set the category."""
    kw: dict[str, str] = {}
    for base in (REPO, Path.cwd()):
        f = base / "ai_keywords.txt"
        if not f.exists():
            continue
        category = "MISC"
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = re.search(r"\[([A-Z]+)\]", line)
                if m:
                    category = m.group(1)
                continue
            kw[line.lower()] = category
        break
    return kw


def classify(domains: set[str], kw: dict[str, str],
             live_hosts: set[str] | None = None) -> tuple[list[dict], list[str]]:
    """Classify fresh .ai domains by curated keyword categories.
    Returns (matched, unmatched): matched = [{domain, category, live}], 
    unmatched = sorted non-matching domains."""
    matched: list[dict] = []
    unmatched: list[str] = []
    for dom in sorted(domains):
        label = dom[:-3].rstrip(".") if dom.endswith(".ai") else dom
        label = label.split(".")[-1] if "." in label else label
        cats = sorted({cat for frag, cat in kw.items() if frag in label})
        if cats:
            matched.append({"domain": dom, "category": "/".join(cats),
                            "live": bool(live_hosts and dom in live_hosts)})
        else:
            unmatched.append(dom)
    return matched, unmatched


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="One .ai registration check")
    p_run.add_argument("--state-root", default=".",
                       help="Repo root holding targets/.ai_watch/")
    p_run.add_argument("--probe", action="store_true", default=True,
                       help="httpx-probe resolved domains (default on)")
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

    if not fresh:
        known_path.write_text("\n".join(sorted(zone)) + "\n")
        log("no new .ai registrations")
        return

    # ---- noise filter: DNS resolution ----
    log(f"resolving {len(fresh)} new domains "
        f"(concurrency {RESOLVE_CONCURRENCY})…")
    resolved = resolve_domains(fresh, watch_dir.parent.parent)
    log(f"resolved (valid): {len(resolved)} / {len(fresh)}")

    resolved_path = watch_dir / "resolved.txt"
    resolved_path.write_text(
        "\n".join(f"{d}\t{ip}" for d, ip in sorted(resolved.items())) + "\n")

    # ---- liveness probe ----
    live = probe_httpx(sorted(resolved), HTTPX_CAP) if args.probe else []
    live_map = {l["host"]: l for l in live}
    live_path = watch_dir / "live.txt"
    live_path.write_text("\n".join(
        f"{l['host']}\t{l['status']}\t{l['title']}" for l in live) + "\n")
    log(f"live (HTTP serving): {len(live)}")

    # update known-set
    known_path.write_text("\n".join(sorted(zone)) + "\n")

    # ---- curated keyword classification ----
    kw = load_keywords()
    live_hosts = {l["host"] for l in live}
    matched, unmatched = classify(set(fresh), kw, live_hosts)
    matched_live = [m for m in matched if m["live"]]
    matched_path = watch_dir / "matched.txt"
    if matched:
        matched_path.write_text("\n".join(
            f"{m['domain']}\t[{m['category']}]"
            + (f"\tlive [{live_map[m['domain']]['status']}] "
               f"{live_map[m['domain']]['title']}"
               if m["domain"] in live_map else "")
            for m in matched) + "\n")
    log(f"curated keyword matches: {len(matched)} "
        f"({len(matched_live)} live)")

    # ---- deliver ----
    # .ai alerts are opt-in on a SEPARATE chat. Never reuse the shared
    # TELEGRAM_* credentials, which belong to the bug-bounty program feed.
    token = os.environ.get("AI_TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("AI_TELEGRAM_CHAT_ID", "")
    if not (token and chat and requests):
        log("[i] .ai Telegram disabled (set AI_TELEGRAM_BOT_TOKEN / "
            "AI_TELEGRAM_CHAT_ID for a separate .ai chat) — lists written to state")
        return

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    summary = (
        f"🆕 *New .ai registrations — {day}*\n"
        f"registered: *{len(fresh)}* | resolved (valid): *{len(resolved)}* "
        f"| live website: *{len(live)}* | 🎯 curated: *{len(matched)}*\n\n"
    )
    if matched:
        summary += "🎯 *Curated matches:*\n"
        for m in matched[:20]:
            live_tag = (f" — [{live_map[m['domain']]['status']}] "
                        f"{live_map[m['domain']]['title']}"
                        if m["domain"] in live_map else "")
            summary += (f"  🆕 {m['domain']} — [{m['category']}]{live_tag}\n")
        if len(matched) > 20:
            summary += f"  … +{len(matched) - 20} more\n"
        summary += "\n"
    if live:
        summary += "*Live websites (sample):*\n"
        shown = 0
        for l in live:
            if l["host"] in {m["domain"] for m in matched}:
                continue
            summary += f"  • {l['host']} — [{l['status']}] {l['title']}\n"
            shown += 1
            if shown >= 10:
                break
    summary += f"\n(full lists attached: resolved {len(resolved)} / live {len(live)} / curated {len(matched)})"

    ok = tg_send_text(token, chat, summary)
    log(f"summary message: {'OK' if ok else 'FAILED'}")
    if matched:
        ok1 = tg_send_file(token, chat, matched_path,
                           f".ai curated matches — {day} — {len(matched)}")
        log(f"matched file: {'OK' if ok1 else 'FAILED'}")
    if resolved:
        ok2 = tg_send_file(token, chat, resolved_path,
                           f".ai resolved (valid DNS) — {day} — "
                           f"{len(resolved)} domains")
        log(f"resolved file: {'OK' if ok2 else 'FAILED'}")
    if live:
        ok3 = tg_send_file(token, chat, live_path,
                           f".ai live websites (HTTP) — {day} — {len(live)}")
        log(f"live file: {'OK' if ok3 else 'FAILED'}")


if __name__ == "__main__":
    main()
