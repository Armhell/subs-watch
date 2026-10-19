#!/usr/bin/env python3
"""
certspotter_poll.py — Incremental new-cert alerts for active targets.

For each target domain: one CertSpotter API call with an `after` cursor
returns ONLY issuances newer than the last seen cert id. New DNS names
(found in those issuances) become Telegram alerts. Free tier: ~1,000
requests/day without a key — sized for 79 targets every 2h (~950/day).

State (per-domain cursors + seen names) lives in sqlite under
<state-root>/targets/.certspotter/poll.db — persisted via the encrypted
state blob in CI, or locally at bb-ass/targets/.certspotter/.

First run per domain = silent seed (records latest cert ids + names).

Usage:
    python3 certspotter_poll.py run --state-root . --targets-file targets.txt
    python3 certspotter_poll.py status
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

try:
    import requests
except ImportError:
    requests = None

from subdomain_delta import DEFAULT_ALERT_KEYWORDS, telegram_send  # noqa: E402

API = "https://api.certspotter.com/v1/issuances"
EXCLUDED_TARGETS = {"zebpay.com", "www.zebapi.com"}
JUNK = {"example.com", "nonexistent-test-domain.test", "test.fixture"}
REQUEST_TIMEOUT = 60


class Redact:
    names: dict[str, str] = {}

    @classmethod
    def apply(cls, text: str) -> str:
        for name, alias in cls.names.items():
            text = text.replace(name, alias)
        return text


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] "
          f"{Redact.apply(msg)}", flush=True)


def load_domain_list(path: Path) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        d = line.strip().lower()
        if d and not d.startswith("#") and d not in EXCLUDED_TARGETS \
                and d not in JUNK and "." in d:
            out.append(d)
    return out


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS cursor (
        domain TEXT PRIMARY KEY, last_cert_id TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS names (
        domain TEXT NOT NULL, name TEXT NOT NULL,
        first_seen TEXT NOT NULL, PRIMARY KEY (domain, name))""")
    return conn


def fetch_issuances(domain: str, after: str | None) -> tuple[list[dict], bool]:
    """Returns (issuances, ok). ok=False → skip domain this run (quota/error)."""
    params = {"domain": domain, "include_subdomains": "true",
              "expand": "dns_names", "limit": "50"}
    if after:
        params["after"] = after
    try:
        r = requests.get(API, params=params, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        log(f"[!] {domain}: request failed: {exc}")
        return [], False
    if r.status_code == 429:
        log("[!] CertSpotter quota exhausted (429) — stopping this run")
        return [], False
    if r.status_code >= 300:
        log(f"[!] {domain}: HTTP {r.status_code} — skipping")
        return [], False
    try:
        return r.json(), True
    except json.JSONDecodeError:
        log(f"[!] {domain}: bad JSON — skipping")
        return [], False


def poll_domain(domain: str, conn: sqlite3.Connection,
                keywords: list[str]) -> list[str]:
    """Returns new DNS names first seen for this domain."""
    row = conn.execute("SELECT last_cert_id FROM cursor WHERE domain=?",
                       (domain,)).fetchone()
    issuances, ok = fetch_issuances(domain, row[0] if row else None)
    if not ok:
        return []

    # seed mode: first poll silently records the latest page
    seed = row is None
    new_names: list[str] = []
    max_id: str | None = row[0] if row else None
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for item in issuances:
        cert_id = str(item.get("id") or "")
        if max_id is None or int(cert_id) > int(max_id):
            max_id = cert_id
        for name in item.get("dns_names") or []:
            name = name.strip().lower().removeprefix("*.")
            if not name.endswith(domain):
                continue
            dup = conn.execute("SELECT 1 FROM names WHERE domain=? AND name=?",
                               (domain, name)).fetchone()
            if dup:
                continue
            conn.execute("INSERT INTO names (domain, name, first_seen) "
                         "VALUES (?,?,?)", (domain, name, now))
            if not seed:
                new_names.append(name)

    if max_id and (not row or row[0] != max_id):
        conn.execute("INSERT INTO cursor (domain, last_cert_id) VALUES (?,?) "
                     "ON CONFLICT(domain) DO UPDATE SET last_cert_id=excluded.last_cert_id",
                     (domain, max_id))
    conn.commit()

    tag = "seed" if seed else "poll"
    log(f"{tag} {domain}: issuances={len(issuances)} new_names={len(new_names)}")
    return new_names


def build_alert(new_by_domain: dict[str, list[str]],
                keywords: list[str]) -> str:
    total = sum(len(v) for v in new_by_domain.values())
    lines = [f"🪪 *New certs — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
             f"new names: *{total}* across {len(new_by_domain)} target(s)", ""]
    for domain in sorted(new_by_domain,
                         key=lambda d: -len(new_by_domain[d])):
        names = new_by_domain[domain]
        high = [n for n in names if any(k in n.split(".")[0] for k in keywords)]
        flag = " ⚡" if high else ""
        lines.append(f"• {domain}{flag} +{len(names)}")
        ordered = high + [n for n in names if n not in high]
        for n in ordered[:8]:
            mark = "⚡" if n in high else "+"
            lines.append(f"   {mark} {n}")
        if len(names) > 8:
            lines.append(f"   … +{len(names) - 8} more")
    text = "\n".join(lines)
    return text[:4000]


def run(state_root: Path, targets_file: Path, keywords: list[str],
        redact: bool, no_notify: bool) -> None:
    import os
    load_tokens()
    if requests is None:
        print("[!] requests library missing", file=sys.stderr)
        sys.exit(1)

    domains = load_domain_list(targets_file)
    if not domains:
        log("[!] no targets in list")
        return
    if redact:
        Redact.names.update({d: f"t#{i}" for i, d in enumerate(domains)})

    conn = init_db(Path(state_root) / "targets" / ".certspotter" / "poll.db")
    log(f"=== certspotter poll: {len(domains)} targets ===")

    new_by_domain: dict[str, list[str]] = {}
    for domain in domains:
        names = poll_domain(domain, conn, keywords)
        if names:
            new_by_domain[domain] = names

    if not new_by_domain:
        log("no new certs — nothing to send")
        return
    if no_notify:
        log("notifications skipped (--no-notify)")
        return
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        log("[!] Telegram tokens missing — alerts skipped")
        return
    ok = telegram_send(token, chat, build_alert(new_by_domain, keywords))
    log(f"telegram digest: {'OK' if ok else 'FAILED'}")


def status(state_root: Path) -> None:
    db = Path(state_root) / "targets" / ".certspotter" / "poll.db"
    if not db.exists():
        print("no state yet (never ran)")
        return
    conn = sqlite3.connect(db)
    cur = conn.execute("SELECT count(*) FROM cursor").fetchone()[0]
    names = conn.execute("SELECT count(*) FROM names").fetchone()[0]
    print(f"domains with cursors: {cur}")
    print(f"known dns names: {names}")


def load_tokens() -> None:
    env_file = Path.home() / ".config/bb-ass/tokens.env"
    if env_file.exists():
        for line in env_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                k = k.strip().removeprefix("export ").strip()
                os.environ.setdefault(k, v.strip().strip('"').strip("'"))


def main() -> None:
    import argparse
    import os

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="One incremental poll")
    p_run.add_argument("--state-root", default=".")
    p_run.add_argument("--targets-file", required=True)
    p_run.add_argument("--redact", action="store_true",
                       help="Public-CI mode: console hides target/domain names")
    p_run.add_argument("--no-notify", action="store_true")
    p_run.add_argument("--alert-keywords",
                       help="Comma-separated priority fragments")
    p_st = sub.add_parser("status", help="Show poll state")
    p_st.add_argument("--state-root", default=".")
    args = ap.parse_args()

    keywords = ([k.strip() for k in args.alert_keywords.split(",")]
                if getattr(args, "alert_keywords", None)
                else DEFAULT_ALERT_KEYWORDS)

    if args.cmd == "run":
        root = Path(args.state_root).resolve()
        tf = root / args.targets_file if not Path(args.targets_file).is_absolute() \
            else Path(args.targets_file)
        run(root, tf, keywords, args.redact, args.no_notify)
    elif args.cmd == "status":
        status(Path(args.state_root).resolve())


if __name__ == "__main__":
    main()
