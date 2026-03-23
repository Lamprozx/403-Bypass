"""
Module: host_header_test
Menguji Host header injection, SSRF via Host, dan cache poisoning via Host.
"""
from __future__ import annotations
import requests
import urllib3
from payloads.all_payloads import (
    HOST_HEADER_PAYLOADS, HOST_HEADER_INJECTION_VARIANTS, CACHE_POISON_HEADERS
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _request(url: str, method: str = "GET", headers: dict = None,
             timeout: int = 7) -> dict:
    try:
        r = requests.request(
            method, url,
            headers=headers or {},
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        location = r.headers.get("Location", "")
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        return {
            "status": r.status_code,
            "length": len(r.text),
            "location": location,
            "acao": acao,
            "snippet": r.text[:300],
        }
    except requests.exceptions.Timeout:
        return {"status": "TIMEOUT", "length": 0, "location": "", "acao": "", "snippet": ""}
    except Exception as e:
        return {"status": "ERR", "length": 0, "location": "", "acao": "", "snippet": str(e)}


def _fmt(res: dict) -> str:
    extra = ""
    if res.get("location"):
        extra += f" → Location: {res['location']}"
    if res.get("acao"):
        extra += f" → ACAO: {res['acao']}"
    return f"[{res['status']}] {res['length']} bytes{extra}"


def _check_reflection(res: dict, injected_host: str) -> bool:
    """Cek apakah host yang disuntik muncul di response."""
    return injected_host.lower() in (res.get("snippet") or "").lower()


def host_header_test(base_url: str, verbose: bool = False) -> list[dict]:
    """
    Uji Host header injection, SSRF, dan cache poisoning.
    Returns list of result dicts.
    """
    results = []
    print("\n" + "="*60)
    print("  MODULE: HOST HEADER INJECTION TEST")
    print("="*60)

    # ── 1. Direct Host header substitution ────────────────────
    print("\n[1] Direct Host Header Substitution")
    for host in HOST_HEADER_PAYLOADS:
        headers = {"Host": host}
        res = _request(base_url, headers=headers)
        reflected = "⚠ REFLECTED" if _check_reflection(res, host) else ""
        print(f"  Host: {host:<40} -> {_fmt(res)} {reflected}")
        results.append({"type": "host_direct", "host": host, **res})

    # ── 2. Composite injection variants ───────────────────────
    print("\n[2] Composite Injection Variants")
    for h_dict in HOST_HEADER_INJECTION_VARIANTS:
        display = ", ".join(f"{k}: {v}" for k, v in h_dict.items())
        res = _request(base_url, headers=h_dict)
        for val in h_dict.values():
            reflected = "⚠ REFLECTED" if _check_reflection(res, str(val)) else ""
        print(f"  {display[:60]:<60} -> {_fmt(res)} {reflected}")
        results.append({"type": "host_variant", "headers": h_dict, **res})

    # ── 3. Host CRLF injection attempt ────────────────────────
    print("\n[3] Host CRLF Injection")
    crlf_hosts = [
        "localhost\r\nX-Injected: pwned",
        "localhost\nX-Injected: pwned",
        "localhost%0d%0aX-Injected: pwned",
        "localhost%0aX-Injected: pwned",
    ]
    for host in crlf_hosts:
        try:
            headers = {"Host": host}
            res = _request(base_url, headers=headers)
            print(f"  Host: {repr(host)[:60]:<60} -> {_fmt(res)}")
            results.append({"type": "host_crlf", "host": host, **res})
        except Exception as e:
            print(f"  Host: {repr(host)[:60]:<60} -> [BLOCKED by requests: {e}]")
            results.append({"type": "host_crlf", "host": host, "status": "BLOCKED", **{}})

    # ── 4. X-Forwarded-Host combinations ──────────────────────
    print("\n[4] X-Forwarded-Host Combinations")
    for host in ["attacker.com", "localhost", "127.0.0.1", "evil.com"]:
        for extra_key in ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host"]:
            headers = {extra_key: host}
            res = _request(base_url, headers=headers)
            reflected = "⚠ REFLECTED" if _check_reflection(res, host) else ""
            print(f"  {extra_key}: {host:<20} -> {_fmt(res)} {reflected}")
            results.append({"type": "xfh", "header": extra_key, "host": host, **res})

    # ── 5. Cache poisoning via Host ────────────────────────────
    print("\n[5] Cache Poisoning Headers")
    for hdr in CACHE_POISON_HEADERS:
        display = ", ".join(f"{k}: {v}" for k, v in hdr.items())
        res = _request(base_url, headers=hdr)
        print(f"  {display[:60]:<60} -> {_fmt(res)}")
        results.append({"type": "cache_poison", "headers": hdr, **res})

    # ── Summary ────────────────────────────────────────────────
    reflected_count = sum(1 for r in results if "⚠" in str(r.get("snippet", "")))
    interesting = [r for r in results if r.get("status") not in (404, "ERR", "TIMEOUT", "BLOCKED")]
    print(f"\n[✓] Host Header Test Done — {len(results)} requests, "
          f"{len(interesting)} interesting responses")
    return results
