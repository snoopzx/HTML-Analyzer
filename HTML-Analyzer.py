import sys
import os
import re
import json
import argparse
import requests
import pandas as pd
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
from collections import Counter

API_KEY_PATTERNS = {
    "openai_api_key": r"sk-[a-zA-Z0-9]{32,60}",
    "huggingface_token": r"hf_[a-zA-Z0-9]{34}",
    "google_ai_key": r"gsk_[a-zA-Z0-9]{39}",
    "aws_access_key": r"(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA)([A-Z0-9]{16}|[A-Z0-9]{12})",
    "aws_secret_key": r"[0-9a-zA-Z\/+]{40}",
    "azure_sas_token": r"sig=[a-zA-Z0-9%]+&se=[a-zA-Z0-9%]+&sr=[a-zA-Z0-9%]+&sp=[a-zA-Z0-9%]+&sk=[a-zA-Z0-9%]+",
    "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
    "google_oauth_client_id": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "firebase_api_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "github_token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "github_oauth_token": r"[a-fA-F0-9]{40}",
    "gitlab_token": r"[0-9a-zA-Z]{20}",
    "stripe_sk": r"sk_live_[0-9a-zA-Z]{24}",
    "paypal_secret": r"ECSecret=[0-9A-Za-z]{32}",
    "square_access_token": r"sq0csp-[0-9A-Za-z_-]{43}",
    "slack_webhook": r"T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[A-Za-z0-9_]{24}",
    "discord_webhook": r"https:\/\/discord\.com\/api\/webhooks\/[0-9]{18}\/[0-9a-zA-Z_-]{68}",
    "twilio_sid": r"AC[a-f0-9]{32}",
    "jwt_token_basic": r"eyJ[A-Za-z0-9._-]{20,}\.eyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{20,}",
    "generic_base64_secret": r"(?:'|\")([A-Za-z0-9+\/]{40,})={0,2}(?:'|\")",
    "hex_32_chars": r"[a-f0-9]{32}",
    "generic_api_key_keyword": r"(?:api_key|token|secret|access_id|auth_key|private_key)[^A-Za-z0-9]{0,5}([A-Za-z0-9]{20,60})",
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="HTML Analyzer: Extracts external endpoints, form fields, and credentials.",
        epilog="Usage Examples: \n  python script.py -f path/to/page.html\n  python script.py -u https://example.com"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument(
        "-f", "--file",
        dest="file_path", 
        help="Path to the local HTML file to analyze."
    )
    
    group.add_argument(
        "-u", "--url",
        dest="url_link", 
        help="URL of the website to fetch and analyze."
    )
    return parser.parse_args()

def fetch_html(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        sys.exit(1)

def get_base_url(soup, source):
    base_tag = soup.find('base')
    if base_tag and base_tag.get('href'):
        return base_tag.get('href')
    meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
    if meta_refresh:
        match = re.search(r'url=(https?://[^\s;"]+)', meta_refresh.get('content', ''))
        if match:
            return match.group(1)
    
    if source.startswith("http"):
        return source
    return ""

def collect_attributes(soup, tags, attr_name):
    items = []
    for t in soup.find_all(tags):
        v = t.get(attr_name)
        if not v:
            v = t.get("data-savepage-src") or t.get("data-savepage-href") or t.get("srcdoc")
        
        if v and v.strip():
            items.append({
                "tag": t.name, 
                "attr_name": attr_name, 
                "value": v.strip()
            })
    return items

def extract_form_data(soup):
    inputs_list = []
    
    for f in soup.find_all("form"):
        form_action = f.get("action") or f.get("data-savepage-href") or ""
        form_method = (f.get("method") or "").lower()
        
        for inp in f.find_all(["input", "textarea", "select"]):
            inputs_list.append({
                "name": inp.get("name") or inp.get("id") or "",
                "type": inp.get("type") or inp.name,
                "placeholder": inp.get("placeholder") or "",
                "form_action": form_action,
                "context": f"form({form_method})"
            })

    for inp in soup.find_all(["input", "textarea", "select"], recursive=False):
        if not inp.find_parent("form"):
            inputs_list.append({
                "name": inp.get("name") or inp.get("id") or "",
                "type": inp.get("type") or inp.name,
                "placeholder": inp.get("placeholder") or "",
                "form_action": "",
                "context": "root/no_form"
            })
            
    return pd.DataFrame(inputs_list)

def extract_comments(soup):
    comments = []
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comments.append(comment.strip())
    return comments

def analyze_endpoints(all_raw_endpoints, base_url):
    all_endpoints = []
    
    def get_trust_hint(domain):
        domain = domain.lower()
        if "google" in domain or "gstatic" in domain:
            return "Google"
        elif "facebook" in domain or "fb" in domain or "meta" in domain:
            return "Facebook/Meta"
        elif any(x in domain for x in ["tiktok", "snap", "amazon", "criteo", "trkkn", "newrelic", "analytics", "googletagmanager", "akamaized", "akamai", "segment", "hotjar"]):
            return "Tracking/Ads/CDN"
        elif "netlify" in domain:
            return "Hosting (Netlify)"
        elif not domain or domain == urlparse(base_url).netloc:
            return "Local/Base Domain"
        return "Third-Party (Unknown)"

    for raw_e in all_raw_endpoints:
        url = urljoin(base_url, raw_e['value']) if base_url and not urlparse(raw_e['value']).netloc else raw_e['value']
        
        if url.strip().startswith("<"):
            domain = "(inline HTML / srcdoc)"
        elif url.startswith("data:"):
            domain = "(data URI)"
        else:
            domain = urlparse(url if url.startswith("http") else "https:" + url).netloc or "(relative)"

        all_endpoints.append({
            "tag": raw_e['tag'], 
            "url": url, 
            "domain": domain, 
            "trust_hint": get_trust_hint(domain)
        })

    return pd.DataFrame(all_endpoints)

def find_secrets(html_content, comments):
    secrets = []
    text_to_scan = html_content + "\n" + "\n".join(comments)

    for secret_type, pattern in API_KEY_PATTERNS.items():
        found = re.findall(pattern, text_to_scan, re.IGNORECASE)
        for value in set(found):
            secrets.append({
                "type": secret_type,
                "value": value
            })
    return pd.DataFrame(secrets)

def write_report_files(output_dir, base_file_name, df_endpoints, df_inputs, df_secrets, html_source, base_url):
    os.makedirs(output_dir, exist_ok=True)
    
    endpoints_csv = os.path.join(output_dir, f"{base_file_name}_endpoints.csv")
    inputs_csv = os.path.join(output_dir, f"{base_file_name}_inputs.csv")
    secrets_csv = os.path.join(output_dir, f"{base_file_name}_secrets.csv")
    report_path = os.path.join(output_dir, f"{base_file_name}_report.txt")

    df_endpoints.to_csv(endpoints_csv, index=False)
    df_inputs.to_csv(inputs_csv, index=False)
    
    if not df_secrets.empty:
        df_secrets.to_csv(secrets_csv, index=False)

    report_lines = []
    report_lines.append(f"### HTML Analysis Report: {base_file_name} ###")
    report_lines.append(f"Analyzed Source: {html_source}")
    report_lines.append(f"Base URL: {base_url or 'N/A'}")
    report_lines.append("-" * 50)
    report_lines.append("")
    report_lines.append("## Summary")
    
    total_endpoints = len(df_endpoints)
    total_inputs = len(df_inputs)
    total_secrets = len(df_secrets)

    report_lines.append(f"- Total External Endpoints: {total_endpoints}")
    report_lines.append(f"- Total Input Fields/Forms: {total_inputs}")
    report_lines.append(f"- Detected Secrets/APIs: {total_secrets}")
    report_lines.append("-" * 50)
    
    if total_secrets > 0:
        report_lines.append("\n## !!! Secrets/Keys Detected !!!")
        for _, row in df_secrets.iterrows():
            report_lines.append(f"- Type: {row['type']} | Value: {row['value']}")
        report_lines.append(f"Details saved to: {secrets_csv}")
    
    report_lines.append("\n## Top External Domains")
    domains = df_endpoints['domain'].tolist()
    cnt = Counter([d for d in domains if not d.startswith("(")])
    if not cnt:
        report_lines.append("No trackable domains found.")
    for dom, c in cnt.most_common(15):
        report_lines.append(f"- {dom} ({c} occurrences)")
        
    report_lines.append("\n## Input Fields (Sample of first 10)")
    if total_inputs > 0:
        for _, row in df_inputs.head(10).iterrows():
            report_lines.append(f"- Name: {row['name']} | Type: {row['type']} | Context: {row['context']} | Action: {row['form_action'][:50]}")
    else:
        report_lines.append("- No interactive input fields found.")

    report_text = "\n".join(report_lines)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print("\n" + "=" * 50)
    print("Analysis Complete. Results saved to directory: html_analysis_output/")
    print(f"Source: {html_source}")
    print("=" * 50)
    print(f"Report (Text): {report_path}")
    print(f"Endpoints (CSV): {endpoints_csv}")
    print(f"Inputs (CSV): {inputs_csv}")
    if total_secrets > 0:
        print(f"SECRETS FOUND (CSV): {secrets_csv}")

if __name__ == '__main__':
    args = parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "html_analysis_output")
    
    html_content = ""
    base_file_name = ""
    
    if args.file_path:
        html_source = args.file_path
        base_file_name = os.path.basename(html_source).replace(".html", "_report").replace(".htm", "_report")
        try:
            with open(html_source, "r", encoding="utf-8", errors="replace") as f:
                html_content = f.read()
        except FileNotFoundError:
            print(f"Error: HTML file not found at path: {html_source}")
            sys.exit(1)
            
    elif args.url_link:
        html_source = args.url_link
        url_part = urlparse(html_source).netloc.replace(".", "_")
        if not url_part:
            url_part = "online_scan"
        base_file_name = url_part + "_report"
        html_content = fetch_html(html_source)

    soup = BeautifulSoup(html_content, "html.parser")
    base_url = get_base_url(soup, html_source)
    
    raw_endpoints = []
    raw_endpoints.extend(collect_attributes(soup, "script", "src"))
    raw_endpoints.extend(collect_attributes(soup, "link", "href"))
    raw_endpoints.extend(collect_attributes(soup, "img", "src"))
    raw_endpoints.extend(collect_attributes(soup, "iframe", "src"))

    js_urls = set(re.findall(r"""['"]((?:https?:)?//[^\s'"]+)['"]""", html_content))
    for u in js_urls:
        raw_endpoints.append({"tag": "js-string", "attr_name": "value", "value": u})

    df_endpoints = analyze_endpoints(raw_endpoints, base_url)
    df_inputs = extract_form_data(soup)
    comments = extract_comments(soup)
    df_secrets = find_secrets(html_content, comments)
    write_report_files(output_dir, base_file_name, df_endpoints, df_inputs, df_secrets, html_source, base_url)