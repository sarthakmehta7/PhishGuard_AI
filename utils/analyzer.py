"""
PhishGuard AI — Real URL Analyzer
Performs actual live checks: DNS, SSL cert, WHOIS, redirects, HTTP headers.
Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav
"""

import re, socket, ssl, json, time, ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional
import tldextract

# ── Feature columns (must match training order) ──────────────
FEATURE_COLS = [
    "has_https","url_length","domain_length","subdomain_count",
    "path_length","query_length","num_dots","num_hyphens","num_underscores",
    "num_slashes","num_at","num_equals","num_ampersand","num_percent",
    "num_digits_in_domain","has_ip_address","is_shortened","suspicious_tld",
    "phishing_keyword_count","brand_in_subdomain","brand_in_domain",
    "has_port","double_slash_path","hex_chars","non_ascii",
    "suspicious_file_ext","query_param_count","long_path_segment",
    "subdomain_depth","ratio_digits",
]

SHORTENERS = [
    "bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","rb.gy","is.gd",
    "cutt.ly","buff.ly","short.link","ift.tt","dlvr.it"
]
SUSPICIOUS_TLDS = [
    ".xyz",".info",".tk",".ml",".ga",".cf",".ru",".pw",".top",
    ".biz",".cc",".name",".ws",".mobi",".tel",".click",".download",
    ".loan",".work",".date",".party",".gq",".faith",".review"
]
BRANDS = [
    "paypal","amazon","google","apple","microsoft","facebook","netflix",
    "instagram","twitter","ebay","citibank","wellsfargo","chase","bankofamerica",
    "whatsapp","dropbox","linkedin","yahoo","gmail","outlook","hotmail",
    "irs","fedex","ups","dhl","usps","bitcoin","ethereum","coinbase"
]
PHISHING_KEYWORDS = [
    "login","signin","verify","secure","update","confirm","account",
    "banking","password","credential","suspended","alert","warning","urgent",
    "free","gift","winner","click","limited","offer","prize","claim","restore",
    "paypal","amazon","google","apple","microsoft","facebook","netflix","irs",
    "refund","reward","bonus","discount","lucky","billing","invoice","payment",
    "unusual","activity","access","blocked","locked","expire","immediately",
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    return url


def _public_ips(hostname: str) -> list[str]:
    """Resolve a hostname and return only its IPs; reject private/local targets."""
    if not hostname:
        return []
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except Exception:
        return []
    ips = sorted({info[4][0] for info in infos})
    return ips


def is_public_scan_target(hostname: str) -> tuple[bool, str | None]:
    """Prevent the public scanner from reaching localhost/private/link-local networks."""
    try:
        direct = ipaddress.ip_address(hostname)
        if not direct.is_global:
            return False, "Private or non-public IP addresses are not scannable."
        return True, None
    except ValueError:
        pass

    ips = _public_ips(hostname)
    if not ips:
        return False, "Host could not be resolved to a public address."
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        return False, "Host resolves to a private or non-public address."
    return True, None


# ── 30 Real Features ─────────────────────────────────────────
def extract_30_features(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url)
        ext    = tldextract.extract(url)
        host   = (parsed.hostname or "").lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        return {c: 0 for c in FEATURE_COLS}

    has_https          = int(url.startswith("https://"))
    url_len            = len(url)
    domain_len         = len((ext.domain or "") + "." + (ext.suffix or ""))
    sub                = ext.subdomain or ""
    subdomain_count    = len(sub.split(".")) if sub else 0
    path_len           = len(parsed.path)
    query_len          = len(parsed.query or "")
    num_dots           = url.count(".")
    num_hyphens        = url.count("-")
    num_underscores    = url.count("_")
    num_slashes        = url.count("/")
    num_at             = url.count("@")
    num_equals         = url.count("=")
    num_ampersand      = url.count("&")
    num_percent        = url.count("%")
    num_digits_domain  = sum(c.isdigit() for c in (ext.domain or ""))

    has_ip = 0
    try:
        ipaddress.ip_address(host); has_ip = 1
    except Exception:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host): has_ip = 1

    is_shortened     = int(any(s in host for s in SHORTENERS))
    sfx              = "." + (ext.suffix or "")
    suspicious_tld   = int(any(sfx == t or sfx.endswith(t) for t in SUSPICIOUS_TLDS))
    kw_count         = sum(1 for kw in PHISHING_KEYWORDS if kw in full)
    brand_subdomain  = int(any(b in sub.lower() for b in BRANDS) if sub else False)
    domain_lower     = (ext.domain or "").lower()
    brand_domain     = int(any(b in domain_lower and domain_lower != b for b in BRANDS))
    has_port         = int(parsed.port is not None and parsed.port not in (80,443))
    double_slash     = int("//" in parsed.path)
    hex_chars        = int(bool(re.search(r"%[0-9a-fA-F]{2}", url)))
    non_ascii        = int(bool(re.search(r"[^\x00-\x7F]", url)))
    sus_exts         = [".exe",".php",".zip",".js",".html",".htm"]
    suspicious_ext   = int(any(path.endswith(e) for e in sus_exts))
    query_params     = len(parsed.query.split("&")) if parsed.query else 0
    path_segments    = [p for p in parsed.path.split("/") if p]
    long_path        = int(any(len(s) > 20 for s in path_segments))
    subdomain_depth  = len(sub.split(".")) if sub else 0
    ratio_digits     = round(sum(c.isdigit() for c in url) / max(len(url),1), 4)

    return {
        "has_https":              has_https,
        "url_length":             url_len,
        "domain_length":          domain_len,
        "subdomain_count":        subdomain_count,
        "path_length":            path_len,
        "query_length":           query_len,
        "num_dots":               num_dots,
        "num_hyphens":            num_hyphens,
        "num_underscores":        num_underscores,
        "num_slashes":            num_slashes,
        "num_at":                 num_at,
        "num_equals":             num_equals,
        "num_ampersand":          num_ampersand,
        "num_percent":            num_percent,
        "num_digits_in_domain":   num_digits_domain,
        "has_ip_address":         has_ip,
        "is_shortened":           is_shortened,
        "suspicious_tld":         suspicious_tld,
        "phishing_keyword_count": kw_count,
        "brand_in_subdomain":     brand_subdomain,
        "brand_in_domain":        brand_domain,
        "has_port":               has_port,
        "double_slash_path":      double_slash,
        "hex_chars":              hex_chars,
        "non_ascii":              non_ascii,
        "suspicious_file_ext":    suspicious_ext,
        "query_param_count":      query_params,
        "long_path_segment":      long_path,
        "subdomain_depth":        subdomain_depth,
        "ratio_digits":           ratio_digits,
    }


# ── Real Live Checks ─────────────────────────────────────────

def check_ssl_certificate(hostname: str, timeout=5) -> dict:
    """Real SSL certificate inspection."""
    result = {"valid": False, "issuer": "Unknown", "expires": "Unknown",
              "days_left": None, "error": None, "self_signed": False}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=timeout),
                             server_hostname=hostname) as s:
            cert = s.getpeercert()

        # Expiry
        exp_str = cert.get("notAfter","")
        if exp_str:
            exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now    = datetime.now(timezone.utc)
            days   = (exp_dt - now).days
            result["expires"]   = exp_dt.strftime("%Y-%m-%d")
            result["days_left"] = days
            result["valid"]     = days > 0

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", issuer_dict.get("commonName","Unknown"))

        # Self-signed check
        subject = dict(x[0] for x in cert.get("subject", []))
        result["self_signed"] = (issuer_dict == subject)

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate invalid: {str(e)[:80]}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Port 443 refused"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def check_dns(hostname: str, timeout=5) -> dict:
    """Real DNS resolution check."""
    result = {"resolves": False, "ip_addresses": [], "mx_records": [], "error": None}
    try:
        import dns.resolver
        # A records
        try:
            answers = dns.resolver.resolve(hostname, "A", lifetime=timeout)
            result["ip_addresses"] = [r.address for r in answers]
            result["resolves"]     = True
        except Exception:
            # Fallback to socket
            info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            result["ip_addresses"] = list({x[4][0] for x in info})
            result["resolves"]     = bool(result["ip_addresses"])

        # MX records
        try:
            mx = dns.resolver.resolve(hostname, "MX", lifetime=timeout)
            result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx]
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def check_whois(domain: str, timeout=8) -> dict:
    """Real WHOIS lookup for domain age and registration info."""
    result = {"registered": False, "creation_date": None, "age_days": None,
              "registrar": "Unknown", "country": "Unknown", "error": None}
    try:
        import whois
        w = whois.whois(domain)
        if w:
            result["registered"] = True
            result["registrar"]  = str(w.registrar or "Unknown")[:60]
            result["country"]    = str(w.country  or "Unknown")[:30]

            # Creation date
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd:
                if hasattr(cd, "replace"):
                    cd = cd.replace(tzinfo=None) if cd.tzinfo else cd
                now  = datetime.now()
                days = (now - cd).days
                result["creation_date"] = cd.strftime("%Y-%m-%d")
                result["age_days"]      = days

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def check_http_response(url: str, timeout=6) -> dict:
    """Real HTTP request: check status, headers, redirects."""
    result = {
        "reachable": False, "status_code": None, "final_url": url,
        "redirect_count": 0, "server": "Unknown",
        "content_type": "Unknown", "has_csp": False,
        "has_hsts": False, "has_xframe": False, "error": None,
        "response_time_ms": None,
    }
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (PhishGuard Security Scanner)"},
        )
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = int((time.time() - t0) * 1000)
            result.update({
                "reachable":        True,
                "status_code":      resp.status,
                "final_url":        resp.url,
                "redirect_count":   len(resp.headers.get("location","").split(",")) if resp.headers.get("location") else 0,
                "server":           resp.headers.get("server","Unknown"),
                "content_type":     resp.headers.get("content-type","Unknown"),
                "has_csp":          bool(resp.headers.get("content-security-policy")),
                "has_hsts":         bool(resp.headers.get("strict-transport-security")),
                "has_xframe":       bool(resp.headers.get("x-frame-options")),
                "response_time_ms": elapsed,
            })
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"]       = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)[:80]
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def check_google_safe_browsing(url: str) -> dict:
    """
    Heuristic-based safe browsing check (no API key required).
    Mimics GSB signal scoring from URL structure.
    """
    risk_signals = []
    score = 0

    parsed  = urllib.parse.urlparse(url)
    ext     = tldextract.extract(url)
    host    = (parsed.hostname or "").lower()
    full    = url.lower()
    domain  = (ext.domain or "").lower()

    # Known malicious patterns
    if any(s in host for s in SHORTENERS):
        risk_signals.append("URL shortener hides final destination")
        score += 30

    try:
        ipaddress.ip_address(host)
        risk_signals.append("Raw IP address used as host")
        score += 40
    except Exception:
        pass

    sfx = "." + (ext.suffix or "")
    if any(sfx == t for t in SUSPICIOUS_TLDS):
        risk_signals.append(f"High-risk TLD: {sfx}")
        score += 25

    kws = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if len(kws) >= 2:
        risk_signals.append(f"Phishing keywords detected: {', '.join(kws[:4])}")
        score += min(len(kws) * 8, 40)

    for brand in BRANDS:
        if brand in domain and domain != brand:
            risk_signals.append(f"Brand impersonation: '{brand}' in domain")
            score += 45
            break
        if ext.subdomain and brand in ext.subdomain.lower():
            risk_signals.append(f"Brand '{brand}' in subdomain (deceptive)")
            score += 35
            break

    if url.count(".") > 5:
        risk_signals.append("Excessive dots — obfuscated domain")
        score += 15

    if url.count("-") > 4:
        risk_signals.append("Excessive hyphens — typical of phishing domains")
        score += 10

    if "@" in url:
        risk_signals.append("@ symbol in URL — classic redirect trick")
        score += 30

    if re.search(r"%[0-9a-fA-F]{2}", url):
        risk_signals.append("URL-encoded characters — possible obfuscation")
        score += 10

    if len(url) > 100:
        risk_signals.append(f"Very long URL ({len(url)} chars) — typical of phishing")
        score += 10

    return {
        "flagged":      score >= 40,
        "score":        min(score, 100),
        "risk_signals": risk_signals,
    }


# ── Master Analysis Function ─────────────────────────────────

def full_analysis(url: str) -> dict:
    """
    Complete real analysis of a URL:
    - 30 ML features extracted
    - Live DNS check
    - Live SSL certificate check
    - Live HTTP response check
    - WHOIS domain info
    - Heuristic safe-browsing signals
    """
    url = normalize_url(url)

    try:
        parsed   = urllib.parse.urlparse(url)
        ext      = tldextract.extract(url)
        hostname = parsed.hostname or ""
        domain   = (ext.domain + "." + ext.suffix) if ext.suffix else ext.domain
    except Exception:
        hostname = ""
        domain   = ""

    # 1. Feature extraction (for ML)
    features = extract_30_features(url)

    # 2. Block SSRF targets before any server-side network probe.
    target_ok, target_error = is_public_scan_target(hostname) if hostname else (False, "Invalid hostname.")
    if target_ok:
        ssl_info  = check_ssl_certificate(hostname)
        dns_info  = check_dns(hostname)
        http_info = check_http_response(url)
    else:
        ssl_info = {"valid": False, "error": target_error}
        dns_info = {"resolves": False, "ip_addresses": [], "mx_records": [], "error": target_error}
        http_info = {"reachable": False, "status_code": None, "final_url": url, "redirect_count": 0,
                     "server": "Unknown", "content_type": "Unknown", "has_csp": False,
                     "has_hsts": False, "has_xframe": False, "error": target_error,
                     "response_time_ms": None}
    gsb_info  = check_google_safe_browsing(url)

    # 3. WHOIS — slow, so catch timeout gracefully
    whois_info = {}
    try:
        whois_info = check_whois(domain)
    except Exception:
        whois_info = {"error": "WHOIS lookup timed out"}

    # 4. Risk reasons (human-readable)
    reasons = build_risk_reasons(features, ssl_info, dns_info, http_info, whois_info, gsb_info, url)

    return {
        "url":        url,
        "hostname":   hostname,
        "domain":     domain,
        "features":   features,
        "feature_vector": [features[c] for c in FEATURE_COLS],
        "ssl":        ssl_info,
        "dns":        dns_info,
        "http":       http_info,
        "whois":      whois_info,
        "gsb":        gsb_info,
        "reasons":    reasons,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_risk_reasons(features, ssl, dns, http, whois, gsb, url) -> list:
    reasons = []

    # SSL
    if not features["has_https"]:
        reasons.append({"icon":"🔓","text":"No HTTPS — connection is unencrypted","severity":"critical"})
    elif ssl.get("error"):
        reasons.append({"icon":"⚠️","text":f"SSL error: {ssl['error']}","severity":"high"})
    elif ssl.get("self_signed"):
        reasons.append({"icon":"⚠️","text":"Self-signed SSL certificate — not trusted by browsers","severity":"high"})
    elif ssl.get("days_left") is not None and ssl["days_left"] < 30:
        reasons.append({"icon":"⏰","text":f"SSL certificate expires in {ssl['days_left']} days","severity":"medium"})
    elif ssl.get("valid"):
        reasons.append({"icon":"🔒","text":f"Valid SSL cert · Issued by {ssl.get('issuer','?')} · Expires {ssl.get('expires','?')}","severity":"safe"})

    # DNS
    if dns.get("resolves") is False:
        reasons.append({"icon":"❌","text":"Domain does not resolve — likely fake or taken down","severity":"critical"})
    elif dns.get("ip_addresses"):
        ips = dns["ip_addresses"]
        reasons.append({"icon":"🌐","text":f"Resolves to: {', '.join(ips[:3])}","severity":"info"})

    # IP address used as host
    if features["has_ip_address"]:
        reasons.append({"icon":"🖥️","text":"Raw IP address used instead of domain name","severity":"critical"})

    # Shortened URL
    if features["is_shortened"]:
        reasons.append({"icon":"🔗","text":"URL shortener hides the actual destination","severity":"high"})

    # Keywords
    if features["phishing_keyword_count"] > 0:
        kw_count = features["phishing_keyword_count"]
        reasons.append({"icon":"🎣","text":f"{kw_count} phishing keyword{'s' if kw_count>1 else ''} detected in URL","severity":"high"})

    # Suspicious TLD
    if features["suspicious_tld"]:
        reasons.append({"icon":"🏴","text":"High-risk top-level domain (TLD)","severity":"high"})

    # Brand in subdomain
    if features["brand_in_subdomain"]:
        reasons.append({"icon":"🎭","text":"Trusted brand name used in subdomain to deceive","severity":"critical"})

    # Brand in domain
    if features["brand_in_domain"]:
        reasons.append({"icon":"🎭","text":"Trusted brand name embedded in suspicious domain","severity":"critical"})

    # Long URL
    if features["url_length"] > 100:
        reasons.append({"icon":"📏","text":f"Unusually long URL ({features['url_length']} chars) — typical obfuscation","severity":"medium"})

    # Many dots
    if features["num_dots"] > 5:
        reasons.append({"icon":"·","text":f"Excessive dots ({features['num_dots']}) — domain obfuscation","severity":"medium"})

    # Many hyphens
    if features["num_hyphens"] > 3:
        reasons.append({"icon":"—","text":f"Excessive hyphens ({features['num_hyphens']}) — common phishing pattern","severity":"medium"})

    # @ in URL
    if features["num_at"] > 0:
        reasons.append({"icon":"@","text":"@ symbol in URL — classic redirect deception trick","severity":"high"})

    # WHOIS
    if whois.get("age_days") is not None:
        age = whois["age_days"]
        if age < 30:
            reasons.append({"icon":"🆕","text":f"Domain registered only {age} days ago — very new","severity":"critical"})
        elif age < 180:
            reasons.append({"icon":"🕐","text":f"Domain is only {age} days old — relatively new","severity":"medium"})
        else:
            reasons.append({"icon":"📅","text":f"Domain age: {age} days (established)","severity":"safe"})

    # HTTP response
    if http.get("status_code"):
        sc = http["status_code"]
        if sc == 200:
            sec_headers = []
            if http.get("has_hsts"):  sec_headers.append("HSTS")
            if http.get("has_csp"):   sec_headers.append("CSP")
            if http.get("has_xframe"):sec_headers.append("X-Frame-Options")
            if sec_headers:
                reasons.append({"icon":"🛡️","text":f"Security headers present: {', '.join(sec_headers)}","severity":"safe"})
            else:
                reasons.append({"icon":"⚠️","text":"Missing security headers (HSTS, CSP, X-Frame-Options)","severity":"medium"})
        elif sc >= 400:
            reasons.append({"icon":"⛔","text":f"Server returned HTTP {sc} — page may be down or blocked","severity":"medium"})

    # GSB signals
    for sig in gsb.get("risk_signals", []):
        reasons.append({"icon":"🚨","text":sig,"severity":"high"})

    if not reasons:
        reasons.append({"icon":"✅","text":"No suspicious indicators found","severity":"safe"})

    return reasons


def get_recommendations(label: int, analysis: dict) -> list:
    base = {
        0: [
            "This URL appears safe — always verify SSL certificate before entering credentials",
            "Bookmark trusted sites to avoid typosquatting attacks",
            "Use a password manager that auto-fills only on legitimate domains",
        ],
        1: [
            "⚠️ Do NOT enter passwords, credit cards, or personal data on this site",
            "Verify the site through official channels before proceeding",
            "Check WHOIS registration — very new domains are high risk",
            "Contact the organization directly using known contact details",
            "Report to your IT/security team before clicking",
        ],
        2: [
            "🚨 STOP — Do NOT visit or interact with this website under any circumstances",
            "Do not enter any credentials, payment info, or personal data",
            "If you already visited it, change all related passwords immediately",
            "Run a malware scan on your device",
            "Report to Google Safe Browsing: safebrowsing.google.com/report_phish",
            "Report to APWG (Anti-Phishing Working Group): apwg.org",
            "Alert your organization's cybersecurity team",
        ],
    }
    return base.get(label, base[1])
