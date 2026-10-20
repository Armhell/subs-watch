#!/usr/bin/env python3
"""
ai_bb_match.py — match newly registered .ai domains to public bug-bounty
program scopes.

Input: targets/.ai_watch/resolved.txt (and live.txt / matched.txt) written by
ai_registrations_watch.py.

Scope sources: arkadiyt/bounty-targets-data
  - domains.txt / wildcards.txt
  - hackerone_data.json / bugcrowd_data.json / intigriti_data.json /
    yeswehack_data.json

Output:
  - only matches (scope match, platform link, or explicit bug-bounty text)
  - Telegram digest to the BB-program chat
  - never the raw .ai domain list
  - full audit rows in targets/.ai_watch/bb_matches.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

DATA_BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"
TOKENS_ENV = Path.home() / ".config" / "bb-ass" / "tokens.env"
MAX_BODY = 600_000
PLATFORM_RE = re.compile(
    r"(hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|"
    r"hackenproof\.com|immunefi\.com)",
    re.I,
)
BB_TEXT_RE = re.compile(
    r"\b(bug[ -]?bounty|bounty program|vulnerability disclosure program|"
    r"responsible disclosure)\b",
    re.I,
)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


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


def fetch_text(url: str, *, timeout: int = 30, retries: int = 2,
               quiet: bool = False, max_body: int = MAX_BODY) -> str:
    headers = {"User-Agent": "bb-ass-ai-bb-match/1.0 (authorized research)"}
    last = ""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
            try:
                if resp.status >= 300:
                    return ""
                return resp.read(max_body).decode("utf-8", "ignore")
            finally:
                # Python 3.14 can otherwise emit a harmless
                # "Exception ignored while finalizing HTTPResponse" at exit.
                try:
                    resp.close()
                finally:
                    try:
                        resp.fp = None
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001 - network best effort
            last = f"{type(exc).__name__}: {exc}"
            if attempt < retries - 1:
                continue
    if not quiet:
        log(f"fetch failed: {url} ({last})")
    return ""


def read_source(scope_dir: str | None, name: str) -> str:
    if scope_dir:
        path = Path(scope_dir) / name
        return path.read_text(errors="replace") if path.exists() else ""
    # Scope JSON files are large (H1 alone is ~18 MB); do not use the
    # evidence-page body cap here.
    return fetch_text(DATA_BASE + name, timeout=120, max_body=50_000_000)


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
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        s = s.split(":", 1)[0]
    s = s.strip("*.").strip(".").strip()
    if not s or " " in s or "." not in s:
        return ""
    if IP_RE.match(s):
        return ""
    return s


def wildcard_suffix(raw: object) -> str:
    s = str(raw or "").strip().lower()
    if s.startswith("*.") and "*" not in s[2:]:
        return s[2:].strip(".")
    return ""


def parent_suffixes(host: str) -> list[str]:
    parts = host.split(".")
    out = []
    for i in range(1, len(parts) - 1):
        out.append(".".join(parts[i:]))
    return out


def all_suffixes(host: str) -> list[str]:
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts)) if len(parts) - i >= 2]


def program_ref(platform: str, p: dict) -> dict:
    name = p.get("name") or p.get("handle") or p.get("id") or ""
    url = p.get("url") or ""
    if platform == "yeswehack" and not url and p.get("id"):
        url = f"https://yeswehack.com/programs/{p['id']}"
    bounty = "unknown"
    if platform == "hackerone":
        bounty = "paid" if p.get("offers_bounties") else "VDP"
    elif platform == "bugcrowd":
        payout = p.get("max_payout")
        if isinstance(payout, (int, float)):
            bounty = f"up to ${int(payout):,}" if payout > 0 else "VDP"
    elif platform == "intigriti":
        mb = (p.get("max_bounty") or {}).get("value")
        cur = (p.get("max_bounty") or {}).get("currency") or ""
        if isinstance(mb, (int, float)):
            bounty = f"up to {int(mb):,} {cur}".strip() if mb > 0 else "VDP"
    elif platform == "yeswehack":
        mb = p.get("max_bounty")
        if isinstance(mb, (int, float)):
            bounty = f"up to {int(mb):,}" if mb > 0 else "VDP"
    return {
        "platform": platform,
        "name": str(name),
        "url": str(url),
        "bounty": bounty,
        "scope": "",
    }


def extract_scopes(platform: str, p: dict) -> list[tuple[str, str, str]]:
    """Return (host, wildcard_suffix_or_empty, raw_scope) tuples."""
    targets = ((p.get("targets") or {}).get("in_scope") or [])
    out: list[tuple[str, str, str]] = []
    for t in targets:
        if not isinstance(t, dict):
            continue
        raw = (
            t.get("asset_identifier")
            or t.get("target")
            or t.get("uri")
            or t.get("endpoint")
            or ""
        )
        raw = str(raw).strip()
        if not raw:
            continue
        atype = str(t.get("asset_type") or t.get("type") or "").lower()
        if atype in {
            "ip_address", "cidr", "mobile_application", "android", "ios",
            "apple_store_app_id", "google_play_app_id", "other", "hardware",
        }:
            continue
        host = norm_host(raw)
        if not host:
            continue
        wc = wildcard_suffix(raw)
        out.append((host, wc, raw))
    return out


def load_index(scope_dir: str | None) -> dict:
    domains_txt = read_source(scope_dir, "domains.txt")
    wildcards_txt = read_source(scope_dir, "wildcards.txt")
    domains = {norm_host(line) for line in domains_txt.splitlines() if line.strip()}
    domains.discard("")
    wildcards = [line.strip().lower() for line in wildcards_txt.splitlines() if line.strip()]

    scope_map: dict[str, list[dict]] = defaultdict(list)
    wildcard_map: dict[str, list[dict]] = defaultdict(list)
    parent_map: dict[str, list[dict]] = defaultdict(list)
    suffix_set: set[str] = set()
    for host in domains:
        suffix_set.update(all_suffixes(host))

    for platform, fname in (
        ("hackerone", "hackerone_data.json"),
        ("bugcrowd", "bugcrowd_data.json"),
        ("intigriti", "intigriti_data.json"),
        ("yeswehack", "yeswehack_data.json"),
    ):
        raw_json = read_source(scope_dir, fname)
        if not raw_json:
            continue
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            log(f"{fname}: bad JSON ({exc})")
            continue
        for p in data if isinstance(data, list) else []:
            if not isinstance(p, dict):
                continue
            ref = program_ref(platform, p)
            for host, wc, raw in extract_scopes(platform, p):
                item = dict(ref, scope=raw)
                if wc:
                    wildcard_map[wc].append(item)
                else:
                    scope_map[host].append(item)

    # wildcards.txt is broader than the JSON scope files; keep generic
    # wildcard entries when no platform metadata mapped the same suffix.
    for raw in wildcards:
        suffix = wildcard_suffix(raw)
        if suffix and not wildcard_map.get(suffix):
            wildcard_map[suffix].append({
                "platform": "unknown",
                "name": "BB wildcard scope",
                "url": "",
                "bounty": "unknown",
                "scope": raw,
            })

    for host, refs in scope_map.items():
        for parent in parent_suffixes(host):
            for ref in refs:
                parent_map[parent].append(dict(ref, scope=host))

    # Deduplicate map values.
    for mapping in (scope_map, wildcard_map, parent_map):
        for key, refs in list(mapping.items()):
            seen = set()
            unique = []
            for ref in refs:
                k = (ref.get("platform"), ref.get("url"), ref.get("scope"))
                if k in seen:
                    continue
                seen.add(k)
                unique.append(ref)
            mapping[key] = unique

    log(
        f"scope index: {len(domains):,} domains, {len(wildcards):,} wildcards, "
        f"{len(scope_map):,} mapped hosts, {len(wildcard_map):,} wildcard suffixes"
    )
    return {
        "domains": domains,
        "wildcards": wildcards,
        "scope_map": scope_map,
        "wildcard_map": wildcard_map,
        "parent_map": parent_map,
        "suffix_set": suffix_set,
    }


def match_domain(domain: str, idx: dict) -> list[dict]:
    matches: list[dict] = []
    for ref in idx["scope_map"].get(domain, []):
        matches.append({"kind": "scope-exact", "program": ref})
    # The domain is itself a subdomain of a mapped scope.
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        for ref in idx["scope_map"].get(parent, []):
            matches.append({"kind": "scope-subdomain", "program": ref})
    for ref in idx["parent_map"].get(domain, []):
        matches.append({"kind": "scope-parent", "program": ref})
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        suffix = ".".join(labels[i:])
        for ref in idx["wildcard_map"].get(suffix, []):
            kind = "wildcard-apex" if i == 0 else "wildcard-subdomain"
            matches.append({"kind": kind, "program": ref})
    if not matches and domain in idx["suffix_set"]:
        matches.append({
            "kind": "scope-unmapped",
            "program": {
                "platform": "unknown",
                "name": "BB scope match",
                "url": "",
                "bounty": "unknown",
                "scope": domain,
            },
        })
    if not matches:
        for parent in parent_suffixes(domain):
            if parent in idx["suffix_set"]:
                matches.append({
                    "kind": "scope-subdomain-unmapped",
                    "program": {
                        "platform": "unknown",
                        "name": "BB scope match",
                        "url": "",
                        "bounty": "unknown",
                        "scope": parent,
                    },
                })
                break
    # If a mapped program exists, drop generic wildcard/unmapped noise for
    # the same domain; the mapped program is the useful signal.
    if any((m["program"].get("platform") or "unknown") != "unknown" for m in matches):
        matches = [
            m for m in matches
            if (m["program"].get("platform") or "unknown") != "unknown"
        ]

    # Deduplicate, preferring the strongest evidence for the same program.
    priority = {
        "scope-exact": 0,
        "scope-subdomain": 1,
        "scope-parent": 2,
        "wildcard-apex": 3,
        "wildcard-subdomain": 4,
        "scope-unmapped": 5,
        "scope-subdomain-unmapped": 6,
    }
    best: dict[tuple, dict] = {}
    for m in matches:
        p = m["program"]
        key = (
            p.get("platform"),
            p.get("url"),
            p.get("scope") if (p.get("platform") or "unknown") == "unknown" else "",
        )
        if key not in best or priority.get(m["kind"], 9) < priority.get(best[key]["kind"], 9):
            best[key] = m
    return list(best.values())


def read_domains(path: Path, *, status_200: bool = False) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        domain = parts[0].strip().lower().rstrip(".")
        if not domain.endswith(".ai"):
            continue
        if status_200 and (len(parts) < 2 or parts[1].strip() != "200"):
            continue
        out.append(domain)
    return list(dict.fromkeys(out))


def scan_body(body: str) -> list[tuple[str, str]]:
    out = []
    m = PLATFORM_RE.search(body)
    if m:
        out.append(("platform", m.group(1).lower()))
    m = BB_TEXT_RE.search(body)
    if m:
        out.append(("bb-text", m.group(0).lower()))
    return out


def evidence_for(domain: str, *, timeout: int = 7) -> tuple[str, list[dict]]:
    ev: list[dict] = []
    sec = fetch_text(f"https://{domain}/.well-known/security.txt",
                     timeout=timeout, retries=1, quiet=True)
    policy_urls = []
    if sec:
        for line in sec.splitlines():
            low = line.lower()
            if low.startswith("policy:"):
                url = line.split(":", 1)[1].strip()
                if url.startswith("http"):
                    policy_urls.append(url)
        for kind, detail in scan_body(sec):
            ev.append({"kind": kind, "detail": detail, "where": "security.txt"})
    home = fetch_text(f"https://{domain}/", timeout=timeout, retries=1, quiet=True)
    for kind, detail in scan_body(home):
        ev.append({"kind": kind, "detail": detail, "where": "homepage"})
    for url in policy_urls[:2]:
        body = fetch_text(url, timeout=timeout, retries=1, quiet=True)
        for kind, detail in scan_body(body):
            ev.append({"kind": kind, "detail": detail, "where": "policy"})

    if any(e["kind"] == "platform" for e in ev):
        return "confirmed", ev
    if any(e["kind"] == "bb-text" for e in ev):
        return "probable", ev
    if sec:
        return "vdp", ev
    return "", ev


def match_key(m: dict) -> str:
    p = m.get("program") or {}
    return "|".join([
        m.get("domain", ""),
        m.get("kind", ""),
        str(p.get("platform", "")),
        str(p.get("url", "")),
        str(p.get("scope", "")),
    ])


def load_seen(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text())
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_seen(path: Path, seen: set[str]) -> None:
    path.write_text(json.dumps(sorted(seen), indent=0) + "\n")


def build_alert(matches: list[dict], day: str) -> str:
    lines = [f"🎯 New .ai domain with a BB program — {day}", ""]
    for m in matches:
        p = m.get("program") or {}
        domain = m["domain"]
        kind = m["kind"]
        if kind.startswith("scope"):
            label = f"[{p.get('platform') or 'scope'}] {domain}"
            if p.get("name") and p.get("name") != "BB scope match":
                label += f" — {p['name']}"
            lines.append(label)
            if p.get("url"):
                lines.append(f"  {p['url']}")
            if p.get("bounty"):
                lines.append(f"  Bounty: {p['bounty']}")
            scope = p.get("scope") or ""
            lines.append(f"  Evidence: {kind}" + (f" ({scope})" if scope else ""))
        else:
            lines.append(f"[{kind}] {domain}")
            for e in (m.get("evidence") or [])[:4]:
                lines.append(f"  {e['kind']}: {e['detail']} ({e['where']})")
        lines.append("")
    return "\n".join(lines).strip()


def chunks(text: str, size: int = 3900) -> list[str]:
    out = []
    while text:
        if len(text) <= size:
            out.append(text)
            break
        cut = text.rfind("\n", 0, size)
        if cut < size // 2:
            cut = size
        out.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return out


def send_telegram(text: str, token: str, chat_id: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for chunk in chunks(text):
        payload = json.dumps({
            "chat_id": chat_id,
            "text": chunk,
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Telegram HTTP {exc.code}: {exc.read()[:200]!r}") from exc
        if not data.get("ok"):
            raise RuntimeError(f"Telegram not ok: {data}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state-root", default=".", help="Repo root holding targets/.ai_watch")
    ap.add_argument("--scope-dir", help="Local scope files instead of downloading arkadiyt data")
    ap.add_argument("--notify", action="store_true", help="Send matches to Telegram")
    ap.add_argument("--dry-run", action="store_true", help="Print matches without writing/sending")
    ap.add_argument("--json", action="store_true", help="Print new matches as JSON")
    ap.add_argument("--evidence", action="store_true", help="Check security.txt/homepage/policy pages")
    ap.add_argument("--evidence-source", choices=("matched", "live", "none"), default="matched")
    ap.add_argument("--max-evidence", type=int, default=800)
    ap.add_argument("--include-vdp", action="store_true", help="Include security.txt-only VDPs")
    ap.add_argument("--telegram", help="BOT_TOKEN:CHAT_ID override")
    args = ap.parse_args()

    load_tokens()
    state_root = Path(args.state_root).resolve()
    watch = state_root / "targets" / ".ai_watch"
    resolved = read_domains(watch / "resolved.txt")
    if not resolved:
        log(f"no resolved .ai domains at {watch / 'resolved.txt'} — nothing to do")
        return 0

    idx = load_index(args.scope_dir)
    scope_matches: list[dict] = []
    for domain in resolved:
        for m in match_domain(domain, idx):
            scope_matches.append({"domain": domain, **m})
    log(f"resolved .ai: {len(resolved):,} | scope matches: {len(scope_matches)}")

    evidence_matches: list[dict] = []
    if args.evidence and args.evidence_source != "none":
        if args.evidence_source == "live":
            candidates = read_domains(watch / "live.txt", status_200=True)
        else:
            candidates = read_domains(watch / "matched.txt")
        candidates = candidates[: max(0, args.max_evidence)]
        already = {m["domain"] for m in scope_matches}
        candidates = [d for d in candidates if d not in already]
        results: list[tuple[str, str, list[dict]]] = []

        def check(domain: str) -> tuple[str, str, list[dict]]:
            try:
                conf, ev = evidence_for(domain)
                return domain, conf, ev
            except Exception as exc:  # noqa: BLE001 - one bad host must not stop the run
                log(f"evidence error {domain}: {exc}")
                return domain, "", []

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(check, candidates))
        for domain, conf, ev in results:
            if conf == "confirmed" or conf == "probable" or (conf == "vdp" and args.include_vdp):
                evidence_matches.append({
                    "domain": domain,
                    "kind": f"evidence-{conf}",
                    "program": {
                        "platform": "unknown",
                        "name": "",
                        "url": "",
                        "bounty": "unknown",
                        "scope": domain,
                    },
                    "evidence": ev,
                })
        log(f"evidence checked: {len(candidates):,} | evidence matches: {len(evidence_matches)}")

    all_matches = scope_matches + evidence_matches
    # Deduplicate within this run.
    deduped = {}
    for m in all_matches:
        deduped[match_key(m)] = m
    all_matches = list(deduped.values())

    seen_path = watch / "bb_seen.json"
    seen = load_seen(seen_path)
    new = [m for m in all_matches if match_key(m) not in seen]
    log(f"total matches: {len(all_matches)} | new (unseen): {len(new)}")

    if args.json:
        print(json.dumps(new, indent=2))
    else:
        for m in new:
            p = m.get("program") or {}
            print(f"{m['domain']}  {m['kind']}  {p.get('platform', '')}  {p.get('name', '')}")

    if not args.notify:
        return 0
    if not new:
        log("no new matches — no Telegram message")
        return 0

    if args.telegram and ":" in args.telegram:
        token, chat_id = args.telegram.rsplit(":", 1)
    else:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        log("matches found but TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are missing")
        return 2

    text = build_alert(new, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    try:
        send_telegram(text, token, chat_id)
    except Exception as exc:  # noqa: BLE001
        log(f"Telegram send failed: {exc}")
        return 3

    if args.dry_run:
        log("dry-run: would send the above; not writing state")
        return 0

    for m in new:
        seen.add(match_key(m))
    save_seen(seen_path, seen)
    with (watch / "bb_matches.jsonl").open("a", encoding="utf-8") as fh:
        for m in new:
            fh.write(json.dumps(m, sort_keys=True) + "\n")
    log(f"sent {len(new)} match(es); state saved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
