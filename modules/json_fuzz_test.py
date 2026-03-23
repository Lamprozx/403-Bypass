"""
Module: json_fuzz_test
Menguji JSON body fuzzing: type confusion, proto pollution, key injection, nested abuse.
"""
from __future__ import annotations
import requests
import urllib3
import json
from payloads.all_payloads import JSON_INJECTION, JSON_FUZZ_STRINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _request(url: str, method: str = "POST", headers: dict = None,
             body=None, raw_body: str = None, timeout: int = 7) -> dict:
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        if raw_body is not None:
            r = requests.request(
                method, url,
                headers=h,
                data=raw_body,
                timeout=timeout,
                verify=False,
                allow_redirects=False
            )
        else:
            r = requests.request(
                method, url,
                headers=h,
                json=body,
                timeout=timeout,
                verify=False,
                allow_redirects=False
            )
        ct = r.headers.get("Content-Type", "")
        return {
            "status": r.status_code,
            "length": len(r.text),
            "content_type": ct,
            "snippet": r.text[:300],
        }
    except requests.exceptions.Timeout:
        return {"status": "TIMEOUT", "length": 0, "content_type": "", "snippet": ""}
    except Exception as e:
        return {"status": "ERR", "length": 0, "content_type": "", "snippet": str(e)}


def _fmt(res: dict) -> str:
    return f"[{res['status']}] {res['length']} bytes"


def _interesting(res: dict) -> str:
    """Tandai response menarik."""
    s = res["status"]
    flags = []
    if s == 200:
        flags.append("✅ 200")
    elif s == 500:
        flags.append("💥 500")
    elif s == 400:
        flags.append("⚠ 400")
    elif s not in (404, "ERR", "TIMEOUT"):
        flags.append(f"👀 {s}")
    return " ".join(flags)


def json_fuzz_test(base_url: str, method: str = "POST",
                   verbose: bool = False) -> list[dict]:
    """
    Jalankan semua variasi JSON fuzzing.
    Returns list of result dicts.
    """
    results = []
    print("\n" + "="*60)
    print("  MODULE: JSON FUZZ TEST")
    print("="*60)

    # ── 1. Structured payload injection ───────────────────────
    print(f"\n[1] Structured JSON Payloads ({method})")
    for payload in JSON_INJECTION:
        res = _request(base_url, method=method, body=payload)
        safe = json.dumps(payload)[:60]
        flag = _interesting(res)
        print(f"  {safe:<60} -> {_fmt(res)} {flag}")
        results.append({"type": "json_structured", "payload": payload, **res})

    # ── 2. Fuzz string values ──────────────────────────────────
    print(f"\n[2] Fuzz String Values in id= field ({method})")
    for fuzz in JSON_FUZZ_STRINGS:
        payload = {"id": fuzz}
        res = _request(base_url, method=method, body=payload)
        safe = repr(fuzz)[:50]
        flag = _interesting(res)
        print(f"  id={safe:<50} -> {_fmt(res)} {flag}")
        results.append({"type": "fuzz_string", "payload": fuzz, **res})

    # ── 3. Malformed JSON ──────────────────────────────────────
    print(f"\n[3] Malformed / Raw JSON Strings ({method})")
    malformed = [
        "",
        "{}",
        "[]",
        "null",
        "true",
        "1",
        "{id: 1}",                     # unquoted key
        '{"id": 1,}',                  # trailing comma
        '{"id": 1' ,                   # unclosed
        '{"id": 1}{"id": 2}',          # double JSON
        '{"id": \x00}',                # null byte
        '{"id": 1, "__proto__": {}}',
        '{"id": 1, "constructor": {}}',
        'undefined',
        'NaN',
        '{"id": Infinity}',
        '{"id": -Infinity}',
        "[" * 100 + "]" * 100,         # deep nesting
        '{"a":' * 50 + '"x"' + "}" * 50,
    ]
    for raw in malformed:
        res = _request(base_url, method=method, raw_body=raw)
        display = repr(raw)[:60]
        flag = _interesting(res)
        print(f"  RAW {display:<60} -> {_fmt(res)} {flag}")
        results.append({"type": "malformed_json", "raw": raw, **res})

    # ── 4. Content-Type confusion ──────────────────────────────
    print(f"\n[4] Content-Type Confusion")
    ct_variants = [
        ("application/json", '{"id": 1}'),
        ("application/x-www-form-urlencoded", "id=1"),
        ("text/plain", '{"id": 1}'),
        ("text/xml", '<id>1</id>'),
        ("application/xml", '<?xml version="1.0"?><id>1</id>'),
        ("application/json; charset=utf-8", '{"id": 1}'),
        ("application/json; charset=UTF-8", '{"id": 1}'),
        ("", '{"id": 1}'),
    ]
    for ct, body in ct_variants:
        try:
            r = requests.request(
                method, base_url,
                headers={"Content-Type": ct} if ct else {},
                data=body,
                timeout=7,
                verify=False,
                allow_redirects=False
            )
            res = {
                "status": r.status_code,
                "length": len(r.text),
                "content_type": r.headers.get("Content-Type", ""),
                "snippet": r.text[:200],
            }
        except Exception as e:
            res = {"status": "ERR", "length": 0, "content_type": "", "snippet": str(e)}
        ct_label = ct or "(empty)"
        flag = _interesting(res)
        print(f"  CT={ct_label[:40]:<40} -> {_fmt(res)} {flag}")
        results.append({"type": "ct_confusion", "content_type": ct, "body": body, **res})

    # ── 5. HTTP verb + JSON ────────────────────────────────────
    print("\n[5] Method + JSON Body Combination")
    for verb in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        payload = {"id": 1, "action": "read"}
        res = _request(base_url, method=verb, body=payload)
        flag = _interesting(res)
        print(f"  {verb:<8} {json.dumps(payload):<30} -> {_fmt(res)} {flag}")
        results.append({"type": "verb_json", "method": verb, "payload": payload, **res})

    # ── Summary ────────────────────────────────────────────────
    hits_500 = [r for r in results if r.get("status") == 500]
    hits_200 = [r for r in results if r.get("status") == 200]
    print(f"\n[✓] JSON Fuzz Done — {len(results)} requests, "
          f"{len(hits_200)} 200-OK, {len(hits_500)} 500-errors")
    if hits_500 and verbose:
        print("\n  [!] 500 responses (potential bugs):")
        for r in hits_500:
            print(f"      payload={r.get('payload') or r.get('raw')} snippet={r['snippet'][:100]}")
    return results
