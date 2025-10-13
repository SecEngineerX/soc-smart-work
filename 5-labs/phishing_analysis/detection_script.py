#!/usr/bin/env python3
"""
detection_script.py
Phishing analysis helper:
- parse .eml files (RFC822)
- extract headers, text/html bodies
- extract & normalize obfuscated URLs (dot obfuscation, bracketed, url-encoded)
- detect display-text vs href mismatch, IP-based URLs, punycode, suspicious attachments
- produce a JSON report per input file and a short console summary
"""
import sys
import re
import json
import email
import email.policy
from html import unescape
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse, unquote

# patterns
URL_RE = re.compile(
    r"""(?:(?:https?://)|www\.)[^\s'"\)<>{}\]]+""",
    re.IGNORECASE,
)
OBFUS_DOT_RE = re.compile(r'(\[\.]|\(\.\)|\s*\[dot\]\s*|\s*dot\s*|\s*\(\.\)\s*)', re.IGNORECASE)
SHORT_REDIRECTORS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "rebrand.ly"
]
SUSPICIOUS_ATTACHMENT_EXTS = ['.exe', '.scr', '.pif', '.bat', '.ps1', '.zip', '.rar', '.js']

def load_eml(path):
    with open(path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    return msg

def get_headers(msg):
    headers = {}
    for k in ("From", "To", "Subject", "Date", "Message-ID", "Received"):
        v = msg.get(k)
        if v:
            headers[k] = str(v)
    return headers

def get_attachments(msg):
    atts = []
    for part in msg.walk():
        cdisp = part.get_content_disposition()
        if cdisp == 'attachment' or (part.get_filename()):
            fn = part.get_filename()
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True) or b''
            size = len(payload)
            atts.append({'filename': fn, 'content_type': ctype, 'size': size})
    return atts

def extract_bodies(msg):
    txt = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain' and not part.get_filename():
                try:
                    txt += part.get_content().strip() + "\n"
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        txt += payload.decode(errors='ignore') + "\n"
            if ctype == 'text/html' and not part.get_filename():
                try:
                    html += part.get_content().strip() + "\n"
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html += payload.decode(errors='ignore') + "\n"
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode(errors='ignore')
            if ctype == 'text/html':
                html = text
            else:
                txt = text
    return txt.strip(), html.strip()

def find_urls_in_text(text):
    if not text:
        return []
    found = URL_RE.findall(text)
    results = []
    for u in found:
        cleaned = normalize_obfuscated(u)
        results.append(cleaned)
    # preserve order, unique
    return list(dict.fromkeys(results))

def normalize_obfuscated(s):
    t = s.strip()
    # normalize spaced http patterns like h t t p :
    t = re.sub(r'h\s*t\s*t\s*p\s*s?\s*:\s*/\s*', 'http://', t, flags=re.IGNORECASE)
    t = OBFUS_DOT_RE.sub('.', t)
    t = t.replace('(dot)', '.').replace('{dot}', '.')
    t = unescape(t)
    t = unquote(t)
    t = t.strip("<>'\"")
    return t

def extract_urls_from_html(html):
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for a in soup.find_all('a'):
        href = a.get('href') or ""
        text = a.get_text() or ""
        href_norm = normalize_obfuscated(href)
        urls.append({'href': href_norm, 'display_text': text.strip()})
    # also find bare URLs in the rendered text
    text = soup.get_text(separator=' ')
    for u in find_urls_in_text(text):
        urls.append({'href': u, 'display_text': ''})
    # dedupe by href preserving first occurrence
    dedup = []
    seen = set()
    for u in urls:
        if u['href'] not in seen:
            dedup.append(u)
            seen.add(u['href'])
    return dedup

def domain_from_url(u):
    try:
        parsed = urlparse(u if (u and re.match(r'https?://', u, re.I)) else 'http://' + u)
        host = parsed.hostname or ''
        host = host.lstrip('.')
        return host.lower()
    except Exception:
        return ''

def analyze_url_indicators(u):
    d = domain_from_url(u)
    indicators = []
    if not d:
        indicators.append('invalid-domain')
        return indicators
    # IP host?
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
        indicators.append('ip-in-host')
    # punycode
    if 'xn--' in d:
        indicators.append('punycode-domain')
    try:
        te = tldextract.extract(d)
        # short redirectors
        if d in SHORT_REDIRECTORS or any(d.endswith('.' + r) for r in SHORT_REDIRECTORS):
            indicators.append('known-short-redirector')
    except Exception:
        pass
    try:
        parsed = urlparse(u if u.startswith('http') else 'http://' + u)
        path = parsed.path or ''
        query = parsed.query or ''
        if len(path) > 80:
            indicators.append('long-path')
        if len(query) > 120:
            indicators.append('long-querystring')
    except Exception:
        pass
    return indicators

def display_mismatch_check(entry):
    href = entry.get('href') or ''
    disp = entry.get('display_text') or ''
    if not disp:
        return False
    try:
        dh = domain_from_url(href)
        candidates = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', disp)
        if candidates:
            disp_dom = candidates[0].lower()
            # if display domain doesn't match href domain, flag
            if disp_dom not in dh and dh not in disp_dom:
                return True
    except Exception:
        return False
    return False

def suspicious_attachment_check(atts):
   flags = []
   for a in atts:
        fn = (a.get('filename') or '').lower()
        if not fn:
            continue
        for ext in SUSPICIOUS_ATTACHMENT_EXTS:
            if fn.endswith(ext):
                flags.append({'filename': fn, 'ext': ext})
   return flags

def analyze_eml(path):
    msg = load_eml(path)
    headers = get_headers(msg)
    txt, html = extract_bodies(msg)
    atts = get_attachments(msg)
    urls = []
    # html urls
    urls += extract_urls_from_html(html)
    # plain text urls
    for u in find_urls_in_text(txt):
        urls.append({'href': u, 'display_text': ''})
    # normalize unique
    uniq = []
    seen = set()
    for u in urls:
        href = normalize_obfuscated(u.get('href') or '')
        if href not in seen:
            seen.add(href)
            uniq.append({'href': href, 'display_text': u.get('display_text','')})
    # analyze indicators per url
    url_reports = []
    for u in uniq:
        inds = analyze_url_indicators(u['href'])
        mismatch = display_mismatch_check(u)
        url_reports.append({
            'href': u['href'],
            'display_text': u['display_text'],
            'indicators': inds + (['display-mismatch'] if mismatch else [])
        })
    attachments_flagged = suspicious_attachment_check(atts)
    # simple phishing heuristics
    heuristics = []
    from_header = headers.get('From', '')
    if from_header and 'amazon' in from_header.lower() and 'amazon' not in domain_from_url(from_header):
        heuristics.append('sender-looking-like-brand-but-not-domain')
    if any('login' in (u['href'] or '').lower() and 'secure' not in (u['href'] or '').lower() for u in url_reports):
        heuristics.append('login-phrasing-in-urls')
    if attachments_flagged:
        heuristics.append('suspicious-attachments')
    # assemble report
    report = {
        'file': path,
        'headers': headers,
        'num_urls': len(url_reports),
        'urls': url_reports,
        'attachments': atts,
        'attachments_suspicious': attachments_flagged,
        'heuristics': heuristics,
        'body_text_snippet': (txt[:800] + '...') if txt and len(txt) > 800 else txt,
    }
    return report

def main(args):
    if not args:
        print("Usage: python detection_script.py <file1.eml> [file2.eml ...]")
        sys.exit(1)
    reports = []
    for p in args:
        try:
            r = analyze_eml(p)
            reports.append(r)
            outname = p + ".report.json"
            with open(outname, "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=2, ensure_ascii=False)
            print("="*60)
            print(f"File: {p}")
            print(f"From: {r['headers'].get('From')}")
            print(f"Subject: {r['headers'].get('Subject')}")
            print(f"URLs found: {r['num_urls']}")
            for u in r['urls']:
                print(f" - {u['href']} [{', '.join(u['indicators']) if u['indicators'] else 'no-indicators'}] display='{u['display_text'][:40]}'")
            if r['attachments_suspicious']:
                print(f"Suspicious attachments: {[a['filename'] for a in r['attachments_suspicious']]}")
            if r['heuristics']:
                print(f"Heuristics flags: {', '.join(r['heuristics'])}")
            print(f"Report JSON saved to: {outname}")
            print("="*60)
        except Exception as e:
            print(f"Error processing {p}: {e}")
    combined = {'analyzed_files': len(reports), 'files': [r['file'] for r in reports]}
    with open("combined_report.json", "w", encoding="utf-8") as fh:
        json.dump(combined, fh, indent=2)
    print("Wrote combined_report.json")

if __name__ == "__main__":
    main(sys.argv[1:])
