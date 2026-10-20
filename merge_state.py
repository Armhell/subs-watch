#!/usr/bin/env python3
"""
merge_state.py — CI merge job for the public (encrypted-state) subs-watch.

Each matrix shard runs subs_watch.py --no-notify and uploads an artifact
containing its repo-root-relative state tree (targets/..., targets.txt,
longtail_*.txt) plus its delta docs (delta_<job>_{disc,alive}.json).

This script:
  1. merges every artifact's state tree into one (per-target files are
     disjoint across shards; same-named .md files are concatenated;
     pending.json is unioned)
  2. builds ONE combined Telegram digest from all delta docs and sends it
  3. regenerates the org-wide summary md from the merged deltas
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from subdomain_delta import telegram_send, write_summary_md  # noqa: E402
from subs_watch import build_message  # noqa: E402


def merge_tree(src: Path, dst: Path) -> None:
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        d = dst / rel
        if p.is_dir():
            d.mkdir(parents=True, exist_ok=True)
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.exists() and d.suffix == ".md":
            d.write_text(d.read_text(errors="replace") + "\n\n---\n\n"
                         + p.read_text(errors="replace"))
        elif d.name == "pending.json":
            try:
                a = json.loads(d.read_text())
                b = json.loads(p.read_text())
                seen = {(e.get("target"), e.get("sub")) for e in a}
                d.write_text(json.dumps(a + [e for e in b
                                             if (e.get("target"), e.get("sub")) not in seen],
                                        indent=1))
            except (json.JSONDecodeError, OSError):
                shutil.copy2(p, d)
        else:
            shutil.copy2(p, d)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifacts-root", required=True,
                    help="Dir with one subdir per extracted artifact")
    ap.add_argument("--state-root", default=".",
                    help="Repo root that receives the merged targets/ tree")
    args = ap.parse_args()

    root = Path(args.state_root).resolve()
    merged_disc: list[dict] = []
    merged_alive: list[dict] = []
    shards = 0

    for adir in sorted(Path(args.artifacts_root).iterdir()):
        if not adir.is_dir():
            continue
        src_targets = adir / "targets"
        if src_targets.is_dir():
            merge_tree(src_targets, root / "targets")
            shards += 1
        # root-level tier files (targets.txt / longtail_*.txt) are identical
        # across shards — take the first copy seen
        for tierfile in ("targets.txt", "longtail_0.txt", "longtail_1.txt",
                         "longtail_2.txt", "longtail_3.txt", "longtail_4.txt",
                         "longtail_5.txt", "longtail_6.txt", "longtail_7.txt"):
            src = adir / tierfile
            dst = root / tierfile
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)
        for tier in ("disc", "alive"):
            f = adir / f"delta_{tier}.json"
            if f.exists():
                try:
                    doc = json.loads(f.read_text())
                    (merged_disc if tier == "disc" else merged_alive).extend(
                        doc.get("deltas", []))
                except json.JSONDecodeError:
                    print(f"[!] bad delta doc: {f}", file=sys.stderr)

    # One Telegram digest for the whole run
    keywords = None  # build_message falls back to defaults via its own list
    msg = build_message({"deltas": merged_disc}, {"deltas": merged_alive},
                        __import__("subdomain_delta").DEFAULT_ALERT_KEYWORDS)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not msg:
        print("no deltas — no digest sent")
    elif not token or not chat:
        print("[!] TELEGRAM secrets missing — digest skipped")
    else:
        ok = telegram_send(token, chat, msg)
        print(f"digest sent: {ok}")

    # Org-wide summary md from merged deltas
    tr = root / "targets"
    write_summary_md(merged_disc, tr)
    print(f"merged {shards} shard state tree(s)")


if __name__ == "__main__":
    main()
