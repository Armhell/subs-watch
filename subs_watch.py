#!/usr/bin/env python3
"""
subs_watch.py — Nightly new-subdomain monitor cycle (one run per day).

Per-target pipeline:
  1. subfinder -all -d {domain}         → today's passive discovery
  2. union into subdomains/monitor_subs.txt  (seeded from all_subs.txt if present)
  3. httpx the new subs (and pending retries) → alive ones appended to
     subdomains/monitor_live.txt (seeded from live_hosts.txt if present)
  4. delta vs per-tier baselines via subdomain_delta.py
     (discovered tier + alive tier, separate baseline dirs)
  5. ONE combined Telegram digest per run

State files live under targets/.subs_watch/ (pending retry queue, logs).
Baselines: targets/.subdomain_baselines/{disc,alive}/{target}.last

Usage:
    python3 tools/subs_watch.py run                     # nightly cycle, all targets
    python3 tools/subs_watch.py run --targets swisscom.ch,exodus.com
    python3 tools/subs_watch.py run --skip-enum         # delta+notify only
    python3 tools/subs_watch.py run --no-notify         # reports only
    python3 tools/subs_watch.py status                  # baselines/state overview

Secrets (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, CHAOS_KEY, ...) come from the
environment — the launchd wrapper sources ~/.config/bb-ass/tokens.env first.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from subdomain_delta import (  # noqa: E402
    DEFAULT_ALERT_KEYWORDS,
    high_priority_subs,
    read_set,
    telegram_send,
)

TARGETS_ROOT = REPO_ROOT / "targets"
STATE_DIR = TARGETS_ROOT / ".subs_watch"
PENDING_FILE = STATE_DIR / "pending.json"
LOG_FILE = STATE_DIR / "watch.log"
BASELINE_ROOT = TARGETS_ROOT / ".subdomain_baselines"

MONITOR_SUBS = "subdomains/monitor_subs.txt"     # discovered tier (union, grows)
MONITOR_LIVE = "subdomains/monitor_live.txt"     # alive tier (confirmed serving HTTP)

# Excluded targets — never scan, never alert (per AGENTS.md).
EXCLUDED_TARGETS = {"zebpay.com", "www.zebapi.com"}

RETRY_DAYS = 3          # re-httpx a discovered-but-dead sub for N days before dropping
HTTPX_CAP = 300         # max hosts probed with httpx in one run
SUBFINDER_TIMEOUT = 420  # seconds per target


REDACT: dict[str, str] = {}   # target name -> alias, applied to console output only


def log(msg: str) -> None:
    line = f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    console = line
    if REDACT:
        for name, alias in REDACT.items():
            console = console.replace(name, alias)
    print(console, flush=True)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as fh:
            fh.write(line + "\n")   # full detail stays in the encrypted state file
    except OSError:
        pass


def is_target_dir(d: Path) -> bool:
    return (d.is_dir()
            and not d.name.startswith(".")
            and not d.name.startswith("_")
            and "." in d.name
            and d.name not in EXCLUDED_TARGETS)


def list_targets(only: list[str] | None = None) -> list[Path]:
    if only:
        out = []
        for t in only:
            d = TARGETS_ROOT / t
            if d.is_dir():
                out.append(d)
            elif t not in EXCLUDED_TARGETS and "." in t and not t.startswith((".", "_")):
                # explicit target list (portable mode / targets-file): create it
                d.mkdir(parents=True, exist_ok=True)
                out.append(d)
        return out
    if not TARGETS_ROOT.is_dir():
        return []
    return sorted(d for d in TARGETS_ROOT.iterdir() if is_target_dir(d))


def seed_file(monitor_path: Path, seed_path: Path) -> None:
    """First run: give the monitor file the target's existing history."""
    if monitor_path.exists() or not seed_path.exists():
        return
    monitor_path.parent.mkdir(parents=True, exist_ok=True)
    monitor_path.write_text(seed_path.read_text(errors="replace"))


def run_subfinder(domain: str, timeout: int) -> tuple[str, set[str]]:
    cmd = ["subfinder", "-all", "-d", domain, "-silent"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return domain, read_set_lines(r.stdout)
    except subprocess.TimeoutExpired:
        log(f"[!] subfinder timeout ({timeout}s) for {domain}")
    except Exception as exc:
        log(f"[!] subfinder failed for {domain}: {exc}")
    return domain, set()


def read_set_lines(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if line.startswith(("http://", "https://")):
            line = line.split("://", 1)[1].split("/", 1)[0]
        line = line.split("/", 1)[0].split(":", 1)[0]
        if line and not line.startswith("#"):
            out.add(line)
    return out


def run_httpx(hosts: list[str], tdir: Path) -> list[dict]:
    """Probe hosts; return [{host, status, title, tech}] for alive ones."""
    if not hosts:
        return []
    tmp = STATE_DIR / "httpx_in.txt"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text("\n".join(hosts) + "\n")
    cmd = ["httpx", "-l", str(tmp), "-silent", "-no-color", "-json",
           "-status-code", "-title", "-tech-detect", "-follow-redirects"]
    results: list[dict] = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in r.stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (j.get("host") or j.get("url") or "").strip()
            if host.startswith(("http://", "https://")):
                host = host.split("://", 1)[1].split("/", 1)[0]
            if not host:
                continue
            results.append({
                "host": host.lower(),
                "status": j.get("status_code") or j.get("a", ""),
                "title": (j.get("title") or "").strip()[:80],
                "tech": ",".join(j.get("tech", [])[:4]),
            })
    except subprocess.TimeoutExpired:
        log(f"[!] httpx timeout probing {len(hosts)} hosts")
    except FileNotFoundError:
        log("[!] httpx binary not found in PATH")
    return results


def load_pending() -> list[dict]:
    if not PENDING_FILE.exists():
        return []
    try:
        return json.loads(PENDING_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_pending(entries: list[dict]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_FILE.write_text(json.dumps(entries, indent=1))


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def days_ago(iso_date: str) -> int:
    try:
        d = datetime.strptime(iso_date, "%Y-%m-%d")
        return (datetime.now(timezone.utc) - d).days
    except ValueError:
        return 999


def run_delta(source_rel: str, tier: str, no_update: bool,
              root: Path | None = None, no_md: bool = False) -> dict | None:
    """Invoke subdomain_delta.py for one tier; return its --json doc."""
    baseline_dir = BASELINE_ROOT / tier
    cmd = [sys.executable, str(Path(__file__).resolve().parent / "subdomain_delta.py"),
           "--source", source_rel, "--baseline-dir", str(baseline_dir),
           "--json", "--quiet"]
    if root is not None:
        cmd += ["--root", str(root)]
    if no_md:
        cmd += ["--no-md"]
    if no_update:
        cmd.append("--no-update-baseline")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            log(f"[!] subdomain_delta ({tier}) rc={r.returncode}: {r.stderr[:200]}")
            return None
        return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        log(f"[!] subdomain_delta ({tier}) timed out")
    except json.JSONDecodeError:
        log(f"[!] subdomain_delta ({tier}) produced non-JSON output")
    return None


def build_message(disc_doc: dict | None, alive_doc: dict | None,
                  keywords: list[str]) -> str:
    """One combined Telegram message for the whole run."""
    disc = [d for d in (disc_doc or {}).get("deltas", [])
            if d.get("status") == "ok" and d["added"]]
    alive = [d for d in (alive_doc or {}).get("deltas", [])
             if d.get("status") == "ok" and d["added"]]
    if not disc and not alive:
        return ""
    total_new = sum(len(d["added"]) for d in disc)
    total_alive = sum(len(d["added"]) for d in alive)
    lines = [
        f"🔎 *Subs Watch — {today()}*",
        f"New subs discovered: *{total_new}* | newly alive: *{total_alive}*",
        "",
    ]
    # High-priority first
    high_disc = high_priority_subs(disc, keywords)
    high_alive = high_priority_subs(alive, keywords)
    high_all: dict[str, set[str]] = {}
    for t, subs in high_disc.items():
        high_all.setdefault(t, set()).update(subs)
    for t, subs in high_alive.items():
        high_all.setdefault(t, set()).update(subs)
    if high_all:
        lines.append("⚡ *High-priority*")
        for t, subs in sorted(high_all.items()):
            for h in sorted(subs)[:10]:
                lines.append(f"  ⚡ {h}")
        lines.append("")
    lines.append("*New subs*")
    for d in sorted(disc, key=lambda x: -len(x["added"])):
        lines.append(f"• {d['target']} +{len(d['added'])}")
        for h in d["added"][:8]:
            mark = "⚡" if any(k in h.split(".")[0] for k in keywords) else "+"
            lines.append(f"   {mark} {h}")
        if len(d["added"]) > 8:
            lines.append(f"   … +{len(d['added']) - 8} more")
    if alive:
        lines.append("")
        lines.append("*Newly alive*")
        for d in alive:
            for h in d["added"][:8]:
                mark = "⚡" if any(k in h.split(".")[0] for k in keywords) else "•"
                lines.append(f"   {mark} {h}")
        if total_alive > sum(len(d['added'][:8]) for d in alive):
            lines.append("   … more in targets/.deltas-summary/")
    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:3900] + "\n\n… (truncated — see targets/.deltas-summary/)"
    return text


def cycle(only: list[str] | None, skip_enum: bool, no_notify: bool,
          no_update: bool, keywords: list[str], httpx_cap: int,
          root: Path | None = None, workers: int = 4, redact: bool = False,
          no_md: bool = False, job_name: str | None = None) -> None:
    global TARGETS_ROOT, STATE_DIR, PENDING_FILE, LOG_FILE, BASELINE_ROOT
    if root is not None:
        TARGETS_ROOT = root / "targets"
        STATE_DIR = TARGETS_ROOT / ".subs_watch"
        PENDING_FILE = STATE_DIR / "pending.json"
        LOG_FILE = STATE_DIR / "watch.log"
        BASELINE_ROOT = TARGETS_ROOT / ".subdomain_baselines"
    targets = list_targets(only)
    if not targets:
        log("[!] no targets found")
        return
    if redact:
        REDACT.clear()
        REDACT.update({t: f"t#{i}" for i, t in enumerate(t.name for t in targets)})
    if not skip_enum:
        import shutil
        if not shutil.which("subfinder"):
            log("[!] subfinder binary not found in PATH")
            return
    log(f"=== subs_watch cycle start: {len(targets)} targets ===")
    pending = load_pending()

    # Phase 1 — parallel passive discovery (enum is IO-bound)
    discoveries: dict[str, set[str]] = {}
    if not skip_enum:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(run_subfinder, t.name, SUBFINDER_TIMEOUT)
                    for t in targets]
            for fut in as_completed(futs):
                domain, subs = fut.result()
                discoveries[domain] = subs

    for tdir in targets:
        target = tdir.name
        subs_path = tdir / MONITOR_SUBS
        live_path = tdir / MONITOR_LIVE
        seed_file(subs_path, tdir / "subdomains/all_subs.txt")
        seed_file(live_path, tdir / "subdomains/live_hosts.txt")
        subs_path.parent.mkdir(parents=True, exist_ok=True)

        existing = read_set(subs_path)
        discovered = discoveries.get(target, set())
        if not skip_enum:
            log(f"{target}: subfinder → {len(discovered)} subs "
                f"({len(discovered - existing)} new)")
        fresh = sorted(discovered - existing)

        # Retry queue entries due for a re-probe
        due = [p for p in pending
               if p["target"] == target and days_ago(p["since"]) <= RETRY_DAYS]
        probe_set = list(dict.fromkeys(fresh + [p["sub"] for p in due]))[:httpx_cap]

        alive_hosts: set[str] = set()
        if probe_set:
            results = run_httpx(probe_set, tdir)
            alive_hosts = {r["host"] for r in results}
            log(f"{target}: httpx → {len(alive_hosts)}/{len(probe_set)} alive")

        if fresh:
            with subs_path.open("a") as fh:
                fh.write("\n".join(fresh) + "\n")
        if alive_hosts:
            live_path.parent.mkdir(parents=True, exist_ok=True)
            with live_path.open("a") as fh:
                fh.write("\n".join(sorted(alive_hosts)) + "\n")

        # pending bookkeeping: keep dead ones (if fresh/retried), drop expired
        still_pending = [p for p in pending
                         if not (p["target"] == target
                                 and p["sub"] in alive_hosts)
                         and (p["target"] != target
                              or days_ago(p["since"]) <= RETRY_DAYS)]
        for sub in fresh:
            if sub not in alive_hosts:
                still_pending.append({"target": target, "sub": sub,
                                      "since": today()})
        pending = still_pending

        time.sleep(1)  # be gentle between targets

    save_pending(pending)

    # Deltas + one combined Telegram message
    disc_doc = run_delta(MONITOR_SUBS, "disc", no_update, root, no_md)
    alive_doc = run_delta(MONITOR_LIVE, "alive", no_update, root, no_md)

    # Persist delta docs for the CI merge job (single combined digest)
    if job_name:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            for tier, doc in (("disc", disc_doc), ("alive", alive_doc)):
                (STATE_DIR / f"delta_{job_name}_{tier}.json").write_text(
                    json.dumps(doc, indent=1))
        except OSError as exc:
            log(f"[!] delta doc write failed: {exc}")

    if no_notify or no_update:
        log("notifications skipped (--no-notify or dry-run)")
        return

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        log("[!] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing — "
            "delta reports written, Telegram skipped. Add both to "
            "~/.config/bb-ass/tokens.env")
        return
    msg = build_message(disc_doc, alive_doc, keywords)
    if not msg:
        log("no changes — nothing sent")
        return
    ok = telegram_send(token, chat_id, msg)
    log(f"telegram send: {'OK' if ok else 'FAILED'}")


def status() -> None:
    for tier in ("disc", "alive"):
        bd = BASELINE_ROOT / tier
        n = len(list(bd.glob("*.last"))) if bd.is_dir() else 0
        print(f"{tier} baselines: {n} target(s)")
    if PENDING_FILE.exists():
        pend = load_pending()
        print(f"pending alive-retries: {len(pend)}")
    else:
        print("pending alive-retries: 0")
    print(f"log: {LOG_FILE}")
    print(f"org summaries: {TARGETS_ROOT / '.deltas-summary/'}")


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="Run one nightly cycle")
    p_run.add_argument("--targets", help="Comma-separated target list (default: all)")
    p_run.add_argument("--skip-enum", action="store_true",
                       help="Skip subfinder/httpx; only diff + notify")
    p_run.add_argument("--no-notify", action="store_true",
                       help="Write reports but don't send Telegram")
    p_run.add_argument("--no-update-baseline", action="store_true",
                       help="Dry-run: don't write baselines")
    p_run.add_argument("--httpx-cap", type=int, default=HTTPX_CAP,
                       help=f"Max httpx probes per target (default {HTTPX_CAP})")
    p_run.add_argument("--alert-keywords",
                       help="Comma-separated priority fragments "
                            "(default: built-in list)")
    p_run.add_argument("--root",
                       help="Portable-mode base dir: targets/, state and "
                            "baselines live under this dir instead of the "
                            "bb-ass repo (used by the GitHub Actions setup)")
    p_run.add_argument("--targets-file",
                       help="Plain-text domain list (one per line) instead "
                            "of iterating targets/ dirs")
    p_run.add_argument("--workers", type=int, default=4,
                       help="Parallel subfinder workers (default 4)")
    p_run.add_argument("--redact", action="store_true",
                       help="Public-CI mode: console logs hide target names "
                            "(full detail still goes to the encrypted state)")
    p_run.add_argument("--no-md", action="store_true",
                       help="Skip markdown delta/summary reports (matrix shards "
                            "merge later)")
    p_run.add_argument("--job-name",
                       help="Write delta JSON docs as delta_<name>_{tier}.json "
                            "into the state dir (used by the CI merge job)")

    sub.add_parser("status", help="Show monitor state")

    args = ap.parse_args()
    keywords = ([k.strip() for k in args.alert_keywords.split(",")]
                if getattr(args, "alert_keywords", None)
                else DEFAULT_ALERT_KEYWORDS)

    if args.cmd == "run":
        root = Path(args.root).resolve() if args.root else None
        only = args.targets.split(",") if args.targets else None
        if args.targets_file:
            tf = Path(args.targets_file)
            if not tf.exists():
                print(f"[!] targets file not found: {tf}", file=sys.stderr)
                sys.exit(1)
            only = [line.strip() for line in tf.read_text().splitlines()
                    if line.strip() and not line.startswith("#")
                    and line.strip() not in EXCLUDED_TARGETS]
        cycle(only, args.skip_enum, args.no_notify,
              args.no_update_baseline, keywords, args.httpx_cap,
              root=root, workers=args.workers, redact=args.redact,
              no_md=args.no_md, job_name=args.job_name)
    elif args.cmd == "status":
        status()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
