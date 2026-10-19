#!/usr/bin/env python3
"""
subdomain_delta.py — Continuous monitoring for new/removed subdomains across targets.

Diffs the current `subdomains/live_hosts.txt` (or chosen source file) against
the last-known set per target. Surfaces newly-appeared and removed hosts, then
updates the baseline so the next run only reports fresh deltas.

Common pattern: run nightly via cron after recon.sh, get a digest of new attack
surface to probe.

Outputs:
  targets/{target}/deltas/{ISO-date}.md   per-target delta detail (only on change)
  targets/.deltas-summary/{ISO-date}.md   org-wide summary (only on change)
  {baseline-dir}/{target}.last            running baseline (updated each run)

Usage:
    python3 tools/subdomain_delta.py                          # all targets
    python3 tools/subdomain_delta.py --target example.com     # one target
    python3 tools/subdomain_delta.py --baseline-dir .deltas
    python3 tools/subdomain_delta.py --notify-slack <webhook>
    python3 tools/subdomain_delta.py --source subdomains/all_subs.txt --quiet
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # only required if --notify-slack used

REPO_ROOT = Path(__file__).resolve().parent.parent


# ----- file helpers -----

def read_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return set()
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower()
        # strip schemes if present (so http://x.target.com and x.target.com match)
        if line.startswith(("http://", "https://")):
            line = line.split("://", 1)[1].split("/", 1)[0]
        if line and not line.startswith("#"):
            # keep only the host portion (drop ports, paths)
            line = line.split("/", 1)[0].split(":", 1)[0]
            out.add(line)
    return out


def write_baseline(path: Path, hosts: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(hosts)) + "\n")


# ----- diff per-target -----

def diff_target(target: str, target_dir: Path, source_rel: str,
                baseline_dir: Path) -> dict[str, Any]:
    src_path = target_dir / source_rel
    baseline_path = baseline_dir / f"{target}.last"
    if not src_path.exists():
        return {
            "target": target,
            "status": "source_missing",
            "source": str(src_path),
            "added": [],
            "removed": [],
            "current_count": 0,
            "baseline_count": 0,
        }
    current = read_set(src_path)
    baseline = read_set(baseline_path)
    added = sorted(current - baseline)
    removed = sorted(baseline - current)
    return {
        "target": target,
        "status": "ok",
        "source": str(src_path),
        "baseline_path": str(baseline_path),
        "current_count": len(current),
        "baseline_count": len(baseline),
        "added": added,
        "removed": removed,
        "first_run": not baseline_path.exists(),
    }


def write_target_delta_md(target: str, delta: dict, target_dir: Path) -> Path | None:
    if not (delta["added"] or delta["removed"]):
        return None
    deltas_dir = target_dir / "deltas"
    deltas_dir.mkdir(parents=True, exist_ok=True)
    date_label = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md_path = deltas_dir / f"{date_label}.md"
    lines = [
        f"### {target} — {date_label}",
        "",
        f"Source: `{delta['source']}`",
        f"Current host count: {delta['current_count']}",
        f"Baseline host count: {delta['baseline_count']}",
        "",
    ]
    if delta["added"]:
        lines.append(f"**Added: {len(delta['added'])} new live hosts since last run**")
        lines.append("")
        for h in delta["added"]:
            lines.append(f"  - {h}")
        lines.append("")
    if delta["removed"]:
        lines.append(f"**Removed: {len(delta['removed'])} (decommissioned or gone offline)**")
        lines.append("")
        for h in delta["removed"]:
            lines.append(f"  - {h}")
        lines.append("")
    # Append (not overwrite) — multiple runs on same day shouldn't clobber
    existing = md_path.read_text() if md_path.exists() else ""
    sep = "\n\n---\n\n" if existing else ""
    md_path.write_text(existing + sep + "\n".join(lines))
    return md_path


def write_summary_md(deltas: list[dict], targets_root: Path | None = None) -> Path | None:
    deltas_with_change = [d for d in deltas
                          if d.get("status") == "ok" and (d["added"] or d["removed"])]
    if not deltas_with_change:
        return None
    if targets_root is None:
        targets_root = REPO_ROOT / "targets"
    summary_dir = targets_root / ".deltas-summary"
    summary_dir.mkdir(parents=True, exist_ok=True)
    date_label = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md_path = summary_dir / f"{date_label}.md"
    total_added = sum(len(d["added"]) for d in deltas_with_change)
    total_removed = sum(len(d["removed"]) for d in deltas_with_change)
    lines = [
        f"# Subdomain Deltas — {date_label}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Targets with changes: {len(deltas_with_change)}",
        f"Total added: {total_added}",
        f"Total removed: {total_removed}",
        "",
        "## Changes by target",
        "",
        "| Target | Added | Removed | Current | Baseline |",
        "|---|---|---|---|---|",
    ]
    for d in sorted(deltas_with_change, key=lambda x: -len(x["added"])):
        lines.append(
            f"| {d['target']} | {len(d['added'])} | {len(d['removed'])} "
            f"| {d['current_count']} | {d['baseline_count']} |"
        )
    lines.append("")
    lines.append("## Detail")
    lines.append("")
    for d in deltas_with_change:
        lines.append(f"### {d['target']}")
        lines.append("")
        if d["added"]:
            lines.append(f"Added ({len(d['added'])}):")
            for h in d["added"][:50]:
                lines.append(f"  - {h}")
            if len(d["added"]) > 50:
                lines.append(f"  - ... +{len(d['added']) - 50} more")
            lines.append("")
        if d["removed"]:
            lines.append(f"Removed ({len(d['removed'])}):")
            for h in d["removed"][:50]:
                lines.append(f"  - {h}")
            if len(d["removed"]) > 50:
                lines.append(f"  - ... +{len(d['removed']) - 50} more")
            lines.append("")
    existing = md_path.read_text() if md_path.exists() else ""
    sep = "\n\n---\n\n" if existing else ""
    md_path.write_text(existing + sep + "\n".join(lines))
    return md_path


# ----- Slack notifier -----

# Sub-name fragments that make a new subdomain "high priority" (instant flag).
DEFAULT_ALERT_KEYWORDS = [
    "dev", "test", "stage", "stg", "uat", "preprod", "sandbox",
    "api", "admin", "vpn", "jenkins", "gitlab", "kibana", "grafana",
    "internal", "intranet", "sso", "auth", "panel", "debug",
]


def high_priority_subs(deltas: list[dict],
                       keywords: list[str] | None = None) -> dict[str, list[str]]:
    """Return {target: [subs]} whose names contain a priority keyword."""
    kws = keywords if keywords is not None else DEFAULT_ALERT_KEYWORDS
    out: dict[str, list[str]] = {}
    for d in deltas:
        if d.get("status") != "ok":
            continue
        hits = [h for h in d["added"]
                if any(k in h.split(".")[0] for k in kws)]
        if hits:
            out[d["target"]] = hits
    return out


def telegram_send(token: str, chat_id: str, text: str) -> bool:
    """Send one message via the Telegram Bot API. Returns success."""
    if requests is None:
        print("[!] requests library required for Telegram notify", file=sys.stderr)
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 300:
            print(f"[!] Telegram API returned {r.status_code}: {r.text[:200]}",
                  file=sys.stderr)
            return False
        return True
    except Exception as exc:
        print(f"[!] Telegram notify failed: {exc}", file=sys.stderr)
        return False


def build_delta_digest(deltas: list[dict],
                       keywords: list[str] | None = None) -> str:
    """Build the human-readable digest text (used by Telegram subs-watch)."""
    deltas_with_change = [d for d in deltas
                          if d.get("status") == "ok" and (d["added"] or d["removed"])]
    if not deltas_with_change:
        return ""
    high = high_priority_subs(deltas_with_change, keywords)
    total_added = sum(len(d["added"]) for d in deltas_with_change)
    total_removed = sum(len(d["removed"]) for d in deltas_with_change)
    text_lines = [
        f"🔎 *Subs Watch — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}*",
        f"Targets changed: {len(deltas_with_change)} | "
        f"+{total_added} added, -{total_removed} removed",
        "",
    ]
    if high:
        text_lines.append("⚡ *High-priority new subs*")
        for t, subs in high.items():
            text_lines.append(f"  *{t}*:")
            for h in subs[:10]:
                text_lines.append(f"    ⚡ {h}")
        text_lines.append("")
    for d in deltas_with_change:
        flag = " ⚡" if d["target"] in high else ""
        text_lines.append(f"• *{d['target']}*{flag} — +{len(d['added'])} / -{len(d['removed'])}")
        for h in d["added"][:5]:
            mark = "⚡" if any(k in h.split(".")[0] for k in (keywords or DEFAULT_ALERT_KEYWORDS)) else "+"
            text_lines.append(f"     {mark} {h}")
        if len(d["added"]) > 5:
            text_lines.append(f"     + ... +{len(d['added']) - 5} more")
    return "\n".join(text_lines)


def notify_telegram(deltas: list[dict], token: str, chat_id: str,
                    keywords: list[str] | None = None) -> bool:
    text = build_delta_digest(deltas, keywords)
    if not text:
        return True  # nothing changed — nothing to send
    # Telegram hard-caps messages at 4096 chars; truncate safely.
    if len(text) > 4000:
        text = text[:3900] + "\n\n… (truncated — see targets/.deltas-summary/)"
    return telegram_send(token, chat_id, text)


def notify_slack(webhook: str, deltas: list[dict]) -> bool:
    if requests is None:
        print("[!] requests library required for --notify-slack", file=sys.stderr)
        return False
    deltas_with_change = [d for d in deltas
                          if d.get("status") == "ok" and (d["added"] or d["removed"])]
    if not deltas_with_change:
        return True
    total_added = sum(len(d["added"]) for d in deltas_with_change)
    total_removed = sum(len(d["removed"]) for d in deltas_with_change)
    text_lines = [
        f"*Subdomain Deltas — "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        f"Targets with changes: {len(deltas_with_change)} | "
        f"+{total_added} added, -{total_removed} removed",
        "",
    ]
    for d in deltas_with_change:
        text_lines.append(
            f"• *{d['target']}* — +{len(d['added'])} / -{len(d['removed'])}"
        )
        for h in d["added"][:5]:
            text_lines.append(f"     + {h}")
        if len(d["added"]) > 5:
            text_lines.append(f"     + ... +{len(d['added']) - 5} more")
    payload = {"text": "\n".join(text_lines)}
    try:
        r = requests.post(webhook, json=payload, timeout=10)
        if r.status_code >= 300:
            print(f"[!] Slack webhook returned {r.status_code}: {r.text[:200]}",
                  file=sys.stderr)
            return False
        return True
    except Exception as exc:
        print(f"[!] Slack notify failed: {exc}", file=sys.stderr)
        return False


# ----- main -----

def list_target_dirs(targets_root: Path, single: str | None) -> list[Path]:
    if single:
        d = targets_root / single
        return [d] if d.is_dir() else []
    if not targets_root.is_dir():
        return []
    return sorted(
        d for d in targets_root.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target",
                    help="Single target name (matches targets/{target}/)")
    ap.add_argument("--baseline-dir",
                    help="Where to store running baselines "
                         "(default targets/.subdomain_baselines/)")
    ap.add_argument("--source", default="subdomains/live_hosts.txt",
                    help="Relative path under targets/{t}/ to compare "
                         "(default subdomains/live_hosts.txt)")
    ap.add_argument("--notify-slack", help="Slack incoming-webhook URL")
    ap.add_argument("--notify-telegram", action="store_true",
                    help="Send diff digest to Telegram (uses TELEGRAM_BOT_TOKEN "
                         "and TELEGRAM_CHAT_ID from env or tokens.env)")
    ap.add_argument("--alert-keywords",
                    help="Comma-separated sub-name fragments treated as "
                         "high-priority (default: built-in list)")
    ap.add_argument("--quiet", action="store_true",
                    help="Only print/output when there ARE deltas")
    ap.add_argument("--json", action="store_true",
                    help="Emit a JSON summary on stdout (machine-readable)")
    ap.add_argument("--no-update-baseline", action="store_true",
                    help="Don't write the new baseline (dry-run delta)")
    ap.add_argument("--root",
                    help="Portable-mode base dir: targets live under "
                         "<root>/targets instead of the bb-ass repo")
    ap.add_argument("--no-md", action="store_true",
                    help="Skip markdown delta/summary reports (used by CI "
                         "matrix shards; markdown is written by the merge job)")
    args = ap.parse_args()

    targets_root = Path(args.root).resolve() / "targets" if args.root \
        else REPO_ROOT / "targets"
    baseline_dir = Path(args.baseline_dir) if args.baseline_dir \
        else targets_root / ".subdomain_baselines"
    baseline_dir.mkdir(parents=True, exist_ok=True)

    target_dirs = list_target_dirs(targets_root, args.target)
    if not target_dirs:
        print(f"[!] No target dirs under {targets_root}"
              f"{' for ' + args.target if args.target else ''}",
              file=sys.stderr)
        sys.exit(1)

    deltas: list[dict] = []
    for tdir in target_dirs:
        d = diff_target(tdir.name, tdir, args.source, baseline_dir)
        deltas.append(d)

    # Flood guard: a target's very first run only seeds its baseline —
    # every host would otherwise be reported as "new". Silent seed, no report.
    seeding = [d for d in deltas if d.get("first_run")]
    reporting = [d for d in deltas if not d.get("first_run")]

    # Write per-target delta md files (never for first-run seeds)
    written: list[str] = []
    for d in ([] if args.no_md else reporting):
        if d.get("status") != "ok":
            continue
        tdir = targets_root / d["target"]
        path = write_target_delta_md(d["target"], d, tdir)
        if path:
            written.append(str(path))

    # Aggregate summary
    summary_path = None if args.no_md else write_summary_md(reporting, targets_root)

    # Slack
    if args.notify_slack:
        notify_slack(args.notify_slack, reporting)

    # Telegram (token/chat from env; tokens.env sourced by the wrapper)
    if args.notify_telegram:
        import os
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat_id:
            print("[!] --notify-telegram set but TELEGRAM_BOT_TOKEN / "
                  "TELEGRAM_CHAT_ID missing from env — skipping notify",
                  file=sys.stderr)
        else:
            keywords = ([k.strip() for k in args.alert_keywords.split(",")]
                        if args.alert_keywords else None)
            notify_telegram(reporting, token, chat_id, keywords)

    # Update baselines (last step so a crash mid-run doesn't lose state)
    if not args.no_update_baseline:
        for d in deltas:
            if d.get("status") != "ok":
                continue
            src_path = REPO_ROOT / d["source"] if not Path(d["source"]).is_absolute() \
                else Path(d["source"])
            if not src_path.exists():
                # source path stored as absolute already
                src_path = Path(d["source"])
            current = read_set(src_path)
            baseline_path = baseline_dir / f"{d['target']}.last"
            write_baseline(baseline_path, current)

    # ---- stdout ----
    changed = [d for d in reporting if d.get("status") == "ok"
               and (d["added"] or d["removed"])]
    if args.json:
        out_doc = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "targets_checked": len(deltas),
            "targets_with_deltas": len(changed),
            "seeded_targets": [d["target"] for d in seeding],
            "summary_md": str(summary_path) if summary_path else None,
            "deltas": reporting,
        }
        print(json.dumps(out_doc, indent=2))
        return

    if not args.quiet or changed:
        for d in changed:
            print(f"### {d['target']} — "
                  f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
            if d["added"]:
                print(f"Added: {len(d['added'])} new live hosts since last run")
                for h in d["added"][:10]:
                    print(f"  - {h}")
                if len(d["added"]) > 10:
                    print(f"  - ... +{len(d['added']) - 10} more")
            if d["removed"]:
                print(f"Removed: {len(d['removed'])} (decommissioned)")
                for h in d["removed"][:10]:
                    print(f"  - {h}")
                if len(d["removed"]) > 10:
                    print(f"  - ... +{len(d['removed']) - 10} more")
            print()

    total_new = sum(len(d["added"]) for d in changed)
    if not args.quiet or changed:
        print(f"{len(deltas)} targets checked, {len(changed)} had deltas "
              f"({total_new} new hosts total).")
    if summary_path:
        print(f"[+] Org summary: {summary_path}")
    if written and not args.quiet:
        print(f"[+] Per-target deltas: {len(written)} files written")
    # Tip on first-run
    first_runs = [d for d in deltas if d.get("first_run")]
    if first_runs:
        print(f"[i] {len(first_runs)} first-run baselines created — next run will diff.")


if __name__ == "__main__":
    main()
