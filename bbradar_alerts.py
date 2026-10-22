#!/usr/bin/env python3
"""
bbradar_alerts.py — new paid-program alerts from bbradar Pro into the
existing Telegram bot.

Policy:
  - paid / active only (no VDP, no paused)
  - one digest per run
  - dedupe against bbradar's own seen state and against the existing
    program-monitor URL set
  - no bbradar private Telegram DM

First run baselines the whole catalog silently. Later runs use
`updated_since`, plus a daily full sweep. State is plaintext because it only
contains public program URLs and cursors; the API key is never stored.
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
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE = "https://bbradar.io/api"
TOKENS_ENV = Path.home() / ".config" / "bb-ass" / "tokens.env"
UA = "bb-ass-bbradar-alerts/1.0 (authorized research)"
FULL_SWEEP_HOURS = 24


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


def norm_url(value: object) -> str:
    s = str(value or "").strip().lower().rstrip("/")
    if not s:
        return ""
    try:
        p = urllib.parse.urlparse(s if "://" in s else "https://" + s)
    except ValueError:
        return s
    host = (p.hostname or "").lower()
    for prefix in ("www.", "app."):
        if host.startswith(prefix):
            host = host[len(prefix):]
    return host + p.path.rstrip("/")


def paid_active(p: dict) -> bool:
    if p.get("is_active") is not True or p.get("program_status") != "active":
        return False
    if str(p.get("program_type") or "").lower() == "vdp":
        return False
    if str(p.get("program_type") or "").lower() == "paid":
        return True
    if str(p.get("reward_status") or "").lower() == "paid":
        return True
    if (p.get("bounty_max") or 0) > 0 and str(p.get("program_kind") or "").lower() != "vdp":
        return True
    return False


def fetch_programs(key: str, updated_since: str | None = None,
                   max_pages: int = 40) -> list[dict]:
    out = []
    page = 1
    total_pages = 1
    while page <= max_pages and page <= total_pages:
        params = {"page": page, "page_size": 100}
        if updated_since:
            params["updated_since"] = updated_since
        doc = api_get("/v1/pro/programs", key, params, timeout=60, retries=3)
        batch = doc.get("programs") or []
        out.extend(batch)
        meta = doc.get("meta") or {}
        total_pages = int(meta.get("total_pages") or page)
        if not batch:
            break
        page += 1
    return out


def load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text()) if path.exists() else {}
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(path)


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
    ap.add_argument("--state-file", default=str(Path(__file__).with_name("bbradar_alerts_state.json")))
    ap.add_argument("--known-programs-file",
                    default=str(Path(__file__).with_name("bbradar_known_programs.json")))
    ap.add_argument("--notify", action="store_true")
    ap.add_argument("--baseline", action="store_true", help="Rebuild the seen set without alerts")
    ap.add_argument("--full", action="store_true", help="Force a full catalog sweep")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-pages", type=int, default=40)
    args = ap.parse_args()

    load_tokens()
    key = os.environ.get("BBRADAR_API_KEY", "").strip()
    if not key:
        log("BBRADAR_API_KEY missing — alerts skipped")
        return 0

    state_path = Path(args.state_file)
    known_path = Path(args.known_programs_file)
    state = load_state(state_path)
    seen = set(str(x) for x in state.get("seen", []) if x)
    known = set()
    if known_path.exists():
        try:
            data = json.loads(known_path.read_text())
            known = set(str(x) for x in data) if isinstance(data, list) else set()
        except (json.JSONDecodeError, OSError):
            known = set()

    now = datetime.now(timezone.utc)
    baseline = args.baseline or not state.get("baseline_done")
    # Full catalog each run: the API's updated_since path proved flaky
    # (connection resets), while a full sweep is 29 bounded requests.
    full = True

    try:
        programs = fetch_programs(key, None, args.max_pages)
        log(f"programs: full sweep {len(programs)}")
    except Exception as exc:  # noqa: BLE001
        log(f"programs fetch failed: {exc}")
        return 1

    candidates = []
    for p in programs:
        url = norm_url(p.get("link") or p.get("url"))
        if not url:
            continue
        if url in seen or url in known:
            continue
        if not paid_active(p):
            continue
        candidates.append({
            "url": url,
            "link": p.get("link") or p.get("url"),
            "name": p.get("name") or "",
            "platform": p.get("platform") or "",
            "bounty_max": p.get("bounty_max"),
            "program_type": p.get("program_type") or "",
            "reward_status": p.get("reward_status") or "",
        })

    if baseline:
        for p in programs:
            url = norm_url(p.get("link") or p.get("url"))
            if url:
                seen.add(url)
        state.update({
            "seen": sorted(seen),
            "baseline_done": True,
            "last_program_sync": now.isoformat(timespec="seconds"),
            "last_full_sweep": now.isoformat(timespec="seconds"),
        })
        log(f"baseline: {len(seen)} program URLs recorded; no alerts")
        if not args.dry_run:
            save_state(state_path, state)
        candidates = []
    elif candidates:
        for c in candidates:
            seen.add(c["url"])
        state["seen"] = sorted(seen)
        state["last_program_sync"] = now.isoformat(timespec="seconds")
        if full:
            state["last_full_sweep"] = now.isoformat(timespec="seconds")
        log(f"new paid programs: {len(candidates)}")
        if not args.dry_run:
            save_state(state_path, state)
    else:
        # No new programs: leave the state untouched to avoid a commit
        # every 30 minutes. The next run repeats the bounded full sweep.
        log("new paid programs: 0 (full sweep)")

    if args.json:
        print(json.dumps({"new": candidates, "baseline": baseline,
                          "full_sweep": full, "seen": len(seen)}, indent=2))
    else:
        print(f"bbradar alerts: new={len(candidates)} baseline={baseline} "
              f"full_sweep={full} seen={len(seen)}")
        for c in candidates[:20]:
            bounty = f" up to ${int(c['bounty_max']):,}" if isinstance(c["bounty_max"], (int, float)) and c["bounty_max"] > 0 else ""
            print(f"  [{c['platform']}] {c['name']}{bounty}")
            print(f"    {c['link']}")

    if candidates and args.notify and not args.dry_run:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat:
            log("telegram: credentials missing")
            return 0
        lines = [f"🆕 bbradar — {len(candidates)} new paid program(s)", ""]
        for c in candidates[:30]:
            bounty = f" — up to ${int(c['bounty_max']):,}" if isinstance(c["bounty_max"], (int, float)) and c["bounty_max"] > 0 else ""
            lines.append(f"[{c['platform']}] {c['name']}{bounty}")
            lines.append(f"  {c['link']}")
            lines.append("")
        if len(candidates) > 30:
            lines.append(f"… +{len(candidates) - 30} more")
        try:
            send_telegram("\n".join(lines).strip(), token, chat)
            log(f"telegram: sent {len(candidates)} new program(s)")
        except Exception as exc:  # noqa: BLE001
            log(f"telegram failed: {exc}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
