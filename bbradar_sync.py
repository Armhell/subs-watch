#!/usr/bin/env python3
"""
bbradar_sync.py — refresh bbradar Pro scopes for the BB feed.

What it does:
  1. Pulls all `.ai` targets from the Pro API and rewrites the matcher's
     paid_ai_roots.json with fresh program metadata.
  2. Polls target changes incrementally (`after_id` cursor), keeps only
     added/re-added domain/wildcard targets, extracts registrable roots, and
     optionally appends new roots to the scanner's targets.txt.
  3. Optionally sends a concise Telegram digest for new roots.

Designed to run after `ai_registrations_watch.py` in the daily `.ai` job:
  python3 bbradar_sync.py --state-root . --targets-file targets.txt \
    --matcher-file paid_ai_roots.json --append-targets --notify-changes

The first run bootstraps the change cursor without replaying old changes.
The API key is read from BBRADAR_API_KEY (env or tokens.env) and is never
printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://bbradar.io/api"
TOKENS_ENV = Path.home() / ".config" / "bb-ass" / "tokens.env"
UA = "bb-ass-bbradar-sync/1.0 (authorized research)"
MAX_NEW_ROOTS = 100
MAX_CHANGE_PAGES = 4
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.in", "com.br", "com.tr", "com.sg", "com.hk", "co.nz",
    "com.mx", "co.za", "com.cn", "com.tw", "co.kr", "com.ar", "com.co",
    "com.pe", "com.ph", "com.my", "com.vn", "co.id", "com.sa", "com.ae",
    "com.eg", "com.ng", "co.ke", "com.pk", "com.bd", "com.ua", "com.pl",
    "com.ru", "co.il", "com.es", "com.it", "co.th", "com.vn", "com.sg",
}


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def load_tokens() -> None:
    if not TOKENS_ENV.exists():
        return
    for line in TOKENS_ENV.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def api_get(path: str, key: str, params: dict | None = None,
            timeout: int = 30, retries: int = 2) -> dict:
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": UA,
    }
    last = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "ignore"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "ignore")[:300]
            last = f"HTTP {exc.code}: {body}"
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                retry = exc.headers.get("Retry-After", "")
                delay = int(retry) if retry.isdigit() else 2 ** (attempt + 1)
                log(f"{path}: {last}; retry in {delay}s")
                time.sleep(min(delay, 15))
                continue
            raise RuntimeError(f"{path}: {last}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            if attempt < retries - 1:
                time.sleep(2 ** (attempt + 1))
                continue
            raise RuntimeError(f"{path}: {last}") from exc
    raise RuntimeError(f"{path}: {last}")


def norm_host(value: object) -> str:
    if value is None:
        return ""
    s = str(value).strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            s = urllib.parse.urlparse(s).hostname or ""
        except ValueError:
            return ""
    else:
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0]
    s = s.strip("*.").strip(".")
    if not s or " " in s or "." not in s:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        return ""
    return s


def root_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) < 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def read_roots(path: Path | None) -> set[str]:
    out = set()
    if path and path.exists():
        for line in path.read_text(errors="replace").splitlines():
            d = line.strip().lower().rstrip(".")
            if d and not d.startswith("#"):
                out.add(d)
    return out


def fetch_ai_rows(key: str) -> list[dict]:
    rows = []
    page = 1
    total_pages = 1
    while page <= 4 and page <= total_pages:
        doc = api_get("/v1/pro/targets/search", key, {
            "q": ".ai",
            "match_mode": "contains",
            "page": page,
            "page_size": 500,
            "include_out_of_scope": "false",
            "include_ineligible": "false",
        })
        batch = doc.get("results") or []
        rows.extend(batch)
        meta = doc.get("meta") or {}
        total_pages = int(meta.get("total_pages") or page)
        if not batch:
            break
        page += 1
    return rows


def choose_ai_entries(rows: list[dict]) -> dict[str, dict]:
    best: dict[str, tuple[tuple, dict]] = {}
    for row in rows:
        target = row.get("target") or {}
        program = row.get("program") or {}
        host = norm_host(target.get("identifier"))
        if not host or not host.endswith(".ai"):
            continue
        root = root_domain(host)
        name = str(program.get("name") or "")
        link = str(program.get("link") or "")
        # Prefer real program pages over directory/aggregator rows.
        bad_name = name.lower() in {"saas browser", "disclosure policy"}
        bad_link = "saasbrowser.com" in link.lower() or "defcon.org" in link.lower()
        bounty = program.get("bounty_max")
        bounty_num = float(bounty) if isinstance(bounty, (int, float)) else 0.0
        score = (
            1 if program.get("reward_status") == "paid" else 0,
            1 if program.get("program_type") == "paid" else 0,
            1 if not bad_name else 0,
            1 if not bad_link else 0,
            bounty_num,
            1 if host == root else 0,
        )
        if root not in best or score > best[root][0]:
            best[root] = (score, {
                "host": root,
                "platform": program.get("platform") or "unknown",
                "name": name,
                "url": link,
                "bounty": f"up to ${int(bounty_num):,}" if bounty_num > 0 else "paid",
                "scope": target.get("identifier") or root,
            })
    return {root: item[1] for root, item in best.items()}


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text()) if path.exists() else default
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def domain_change_roots(doc: dict) -> tuple[list[dict], set[str]]:
    roots: dict[str, dict] = {}
    for row in doc.get("results") or []:
        if row.get("change_type") not in ("added", "readded"):
            continue
        target = row.get("target") or {}
        program = row.get("program") or {}
        ttype = str(target.get("type") or target.get("target_type") or "").lower()
        if ttype in {"smart contract", "source code", "mobile application", "android", "ios", "ip", "ip address"}:
            continue
        identifier = str(target.get("identifier") or "")
        if identifier.lower().startswith("0x"):
            continue
        host = norm_host(identifier)
        if not host:
            continue
        if target.get("in_scope") is False or target.get("eligible_for_bounty") is False:
            continue
        root = root_domain(host)
        if root not in roots:
            roots[root] = {
                "root": root,
                "host": host,
                "platform": program.get("platform") or "",
                "name": program.get("name") or "",
                "changed_at": row.get("changed_at") or "",
            }
    return list(roots.values()), set(roots)


def latest_change_cursor(key: str) -> tuple[int, dict]:
    doc = api_get("/v1/pro/targets/changes", key, {"page": 1, "page_size": 100})
    rows = doc.get("results") or []
    ids = [int(r.get("id")) for r in rows if str(r.get("id", "")).isdigit()]
    return (max(ids) if ids else 0), doc


def poll_changes(key: str, cursor: int) -> tuple[list[dict], int, bool]:
    """Return (domain root rows, new cursor, reset_needed)."""
    roots: dict[str, dict] = {}
    current = cursor
    for _ in range(MAX_CHANGE_PAGES):
        try:
            doc = api_get("/v1/pro/targets/changes", key, {
                "after_id": current,
                "page": 1,
                "page_size": 100,
            })
        except RuntimeError as exc:
            if "HTTP 410" in str(exc):
                return [], 0, True
            raise
        batch, batch_roots = domain_change_roots(doc)
        for row in batch:
            roots.setdefault(row["root"], row)
        meta = doc.get("meta") or {}
        next_id = meta.get("next_after_id")
        if next_id is None:
            ids = [int(r.get("id")) for r in doc.get("results") or []
                   if str(r.get("id", "")).isdigit()]
            next_id = max(ids) if ids else current
        next_id = int(next_id or current)
        if next_id <= current:
            break
        current = next_id
        if not meta.get("has_more"):
            break
    return list(roots.values()), current, False


def send_telegram(text: str, token: str, chat_id: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for offset in range(0, len(text), 3900):
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text[offset:offset + 3900],
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        if not data.get("ok"):
            raise RuntimeError(f"Telegram not ok: {data}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state-root", default=".", help="Repo root holding targets/")
    ap.add_argument("--targets-file", default=None,
                    help="Scanner targets.txt (default: <state-root>/targets.txt)")
    ap.add_argument("--matcher-file", default=None,
                    help="paid_ai_roots.json path")
    ap.add_argument("--cursor-file", default=None,
                    help="bbradar cursor JSON (default: <state-root>/targets/.ai_watch/bbradar_state.json)")
    ap.add_argument("--append-targets", action="store_true",
                    help="Append new roots to targets.txt")
    ap.add_argument("--notify-changes", action="store_true",
                    help="Send a Telegram digest for new roots")
    ap.add_argument("--no-ai", action="store_true", help="Skip .ai target refresh")
    ap.add_argument("--no-changes", action="store_true", help="Skip target-change polling")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    load_tokens()
    key = os.environ.get("BBRADAR_API_KEY", "").strip()
    if not key:
        log("BBRADAR_API_KEY missing — bbradar sync skipped")
        return 0

    state_root = Path(args.state_root).resolve()
    targets_file = Path(args.targets_file) if args.targets_file else state_root / "targets.txt"
    matcher_file = Path(args.matcher_file) if args.matcher_file else Path(__file__).with_name("paid_ai_roots.json")
    cursor_file = Path(args.cursor_file) if args.cursor_file else state_root / "targets/.ai_watch/bbradar_state.json"

    existing = read_roots(targets_file)
    for p in sorted(state_root.glob("longtail_*.txt")):
        existing |= read_roots(p)

    new_roots: dict[str, dict] = {}
    ai_entries: dict[str, dict] = {}

    # 1. Refresh .ai matcher scopes
    if not args.no_ai:
        try:
            rows = fetch_ai_rows(key)
            ai_entries = choose_ai_entries(rows)
            existing_entries = load_json(matcher_file, [])
            merged = {str(x.get("host")): x for x in existing_entries
                      if isinstance(x, dict) and x.get("host")}
            for root, item in ai_entries.items():
                merged[root] = item
                if root not in existing:
                    new_roots.setdefault(root, {
                        "root": root,
                        "host": root,
                        "platform": item.get("platform", ""),
                        "name": item.get("name", ""),
                        "changed_at": "",
                    })
            if merged and not args.dry_run:
                save_json(matcher_file, [merged[k] for k in sorted(merged)])
            log(f".ai targets: {len(rows)} rows, {len(ai_entries)} roots, matcher file {len(merged)} entries")
        except Exception as exc:  # noqa: BLE001
            log(f".ai refresh failed: {exc}")

    # 2. Poll target changes incrementally
    cursor = 0
    state = load_json(cursor_file, {})
    if isinstance(state, dict) and str(state.get("after_id", "")).isdigit():
        cursor = int(state["after_id"])

    if not args.no_changes:
        try:
            if cursor <= 0:
                cursor, _doc = latest_change_cursor(key)
                log(f"changes: bootstrap cursor={cursor} (no replay)")
            else:
                rows, new_cursor, reset = poll_changes(key, cursor)
                if reset:
                    cursor, _doc = latest_change_cursor(key)
                    log(f"changes: cursor expired, reset to {cursor}")
                else:
                    for row in rows:
                        root = row["root"]
                        if root not in existing:
                            new_roots.setdefault(root, row)
                    cursor = new_cursor
                    log(f"changes: {len(rows)} domain roots, cursor={cursor}")
        except Exception as exc:  # noqa: BLE001
            log(f"changes poll failed: {exc}")

    # 3. Append new roots to the scanner list
    roots = list(new_roots.values())[:MAX_NEW_ROOTS]
    if roots and args.append_targets and not args.dry_run:
        parent = targets_file.parent
        parent.mkdir(parents=True, exist_ok=True)
        with targets_file.open("a", encoding="utf-8") as fh:
            for row in roots:
                if row["root"] not in existing:
                    fh.write(row["root"] + "\n")
                    existing.add(row["root"])
        log(f"appended {len(roots)} new roots to {targets_file}")

    # 4. Persist cursor
    if not args.dry_run and not args.no_changes:
        save_json(cursor_file, {
            "after_id": cursor,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })

    # 5. Notify about new roots
    if roots and args.notify_changes and not args.dry_run:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        if token and chat:
            lines = [f"🆕 bbradar scope roots — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", ""]
            for row in roots[:40]:
                label = f"+ {row['root']}"
                if row.get("platform"):
                    label += f"  [{row['platform']}]"
                if row.get("name"):
                    label += f" {row['name']}"
                lines.append(label)
            if len(roots) > 40:
                lines.append(f"… +{len(roots) - 40} more")
            try:
                send_telegram("\n".join(lines), token, chat)
                log(f"telegram: sent {len(roots)} new scope roots")
            except Exception as exc:  # noqa: BLE001
                log(f"telegram failed: {exc}")
        else:
            log("telegram: credentials missing, notification skipped")

    summary = {
        "new_roots": [r["root"] for r in roots],
        "cursor": cursor,
        "ai_roots": len(ai_entries),
        "matcher_entries": len(load_json(matcher_file, [])),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"bbradar sync: new roots={len(roots)} cursor={cursor} ai_roots={len(ai_entries)}")
        for row in roots[:20]:
            print(f"  + {row['root']}  [{row.get('platform', '')}] {row.get('name', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
