"""
Module: rate_limit_test
Menguji bypass rate limiting menggunakan rotasi IP header, path variasi, dan timing.
"""
from __future__ import annotations
import requests
import urllib3
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from payloads.all_payloads import RATE_LIMIT_HEADERS, RATE_LIMIT_PATHS

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
        retry_after = r.headers.get("Retry-After", "")
        rl_remaining = r.headers.get("X-RateLimit-Remaining", "")
        rl_limit = r.headers.get("X-RateLimit-Limit", "")
        return {
            "status": r.status_code,
            "length": len(r.text),
            "retry_after": retry_after,
            "rl_remaining": rl_remaining,
            "rl_limit": rl_limit,
            "snippet": r.text[:200],
        }
    except requests.exceptions.Timeout:
        return {"status": "TIMEOUT", "length": 0, "retry_after": "",
                "rl_remaining": "", "rl_limit": "", "snippet": ""}
    except Exception as e:
        return {"status": "ERR", "length": 0, "retry_after": "",
                "rl_remaining": "", "rl_limit": "", "snippet": str(e)}


def _fmt(res: dict) -> str:
    extra = ""
    if res.get("rl_remaining"):
        extra += f" RLRemaining={res['rl_remaining']}"
    if res.get("retry_after"):
        extra += f" RetryAfter={res['retry_after']}"
    return f"[{res['status']}] {res['length']} bytes{extra}"


def _is_rate_limited(res: dict) -> bool:
    return res["status"] in (429, 503, 403)


def rate_limit_test(base_url: str, burst: int = 15,
                    verbose: bool = False) -> list[dict]:
    """
    Uji rate limit bypass:
    - Header-based IP rotation
    - Path variation per request
    - Concurrent burst requests
    - Delay-based probing
    Returns list of result dicts.
    """
    results = []
    print("\n" + "="*60)
    print("  MODULE: RATE LIMIT BYPASS TEST")
    print("="*60)

    # ── 1. Baseline — cek rate limit tanpa manipulasi ──────────
    print("\n[1] Baseline Probe (no bypass)")
    for i in range(5):
        res = _request(base_url)
        print(f"  req #{i+1:<3} -> {_fmt(res)}")
        results.append({"type": "baseline", "req": i+1, **res})
        if _is_rate_limited(res):
            print("  ⚠ Rate limit triggered on baseline!")
            break

    # ── 2. Header-based IP rotation ───────────────────────────
    print("\n[2] IP Header Rotation")
    for hdr in RATE_LIMIT_HEADERS:
        res = _request(base_url, headers=hdr)
        key = list(hdr.keys())[0]
        val = list(hdr.values())[0]
        bypassed = "✅ OK" if not _is_rate_limited(res) else "❌ BLOCKED"
        print(f"  {key}: {val:<20} -> {_fmt(res)} {bypassed}")
        results.append({"type": "header_rotation", "headers": hdr, **res})

    # ── 3. Path variation per request ─────────────────────────
    print("\n[3] Path / Cache-Buster Variation")
    for i, suffix in enumerate(RATE_LIMIT_PATHS):
        if "{}" in suffix:
            suffix = suffix.format(i)
        url = base_url.rstrip("/") + suffix
        res = _request(url)
        bypassed = "✅ OK" if not _is_rate_limited(res) else "❌ BLOCKED"
        print(f"  {suffix or '<bare>':<30} -> {_fmt(res)} {bypassed}")
        results.append({"type": "path_variation", "url": url, **res})

    # ── 4. Random X-Forwarded-For burst ───────────────────────
    print(f"\n[4] Random IP Burst ({burst} concurrent requests)")

    def _burst_req(i: int):
        fake_ip = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        headers = {"X-Forwarded-For": fake_ip}
        res = _request(base_url, headers=headers)
        return i, fake_ip, res

    with ThreadPoolExecutor(max_workers=burst) as executor:
        futures = [executor.submit(_burst_req, i) for i in range(burst)]
        for fut in as_completed(futures):
            i, ip, res = fut.result()
            bypassed = "✅ OK" if not _is_rate_limited(res) else "❌ BLOCKED"
            print(f"  #{i:<3} XFF={ip:<18} -> {_fmt(res)} {bypassed}")
            results.append({"type": "burst", "ip": ip, **res})

    # ── 5. Slow drip — bypass time-window rate limits ─────────
    print("\n[5] Slow Drip (1 req / 2s × 5)")
    for i in range(5):
        res = _request(base_url)
        bypassed = "✅ OK" if not _is_rate_limited(res) else "❌ BLOCKED"
        print(f"  drip #{i+1} -> {_fmt(res)} {bypassed}")
        results.append({"type": "slow_drip", "req": i+1, **res})
        time.sleep(2)

    # ── Summary ────────────────────────────────────────────────
    blocked = sum(1 for r in results if _is_rate_limited(r))
    ok_count = len(results) - blocked
    print(f"\n[✓] Rate Limit Test Done — {len(results)} requests, "
          f"{ok_count} passed, {blocked} blocked")
    return results
