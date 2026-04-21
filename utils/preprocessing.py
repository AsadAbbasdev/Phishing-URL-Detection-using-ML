import re
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import numpy as np
import time

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_features(url):
    """
    Extract 30 features from URL for phishing detection
    Returns: numpy array of 30 features (1=suspicious, -1=safe)
    """
    features = []
    
    # Parse URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        path = parsed_url.path
        query = parsed_url.query
    except:
        domain = url
        path = ''
        query = ''
    
    print(f"📊 Analyzing: {url[:80]}...")
    
    # ============= FEATURE 1: Having IP address =============
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features.append(1 if re.search(ip_pattern, url) else -1)
    
    # ============= FEATURE 2: URL length =============
    features.append(1 if len(url) > 54 else -1)
    
    # ============= FEATURE 3: Shortening service =============
    shortening_services = r'bit\.ly|goo\.gl|tinyurl|ow\.ly|is\.gd|buff\.ly|short\.link|shorturl|shrten|t\.co'
    features.append(1 if re.search(shortening_services, url) else -1)
    
    # ============= FEATURE 4: Having @ symbol =============
    features.append(1 if '@' in url else -1)
    
    # ============= FEATURE 5: Double slash redirecting =============
    features.append(1 if url.rfind('//') > 6 else -1)
    
    # ============= FEATURE 6: Prefix-Suffix in domain =============
    features.append(1 if '-' in domain else -1)
    
    # ============= FEATURE 7: Having subdomain =============
    subdomain_count = domain.count('.')
    features.append(1 if subdomain_count > 2 else -1)
    
    # ============= FEATURE 8: SSL final state (HTTPS) =============
    try:
        if parsed_url.scheme == 'https':
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(1)
    
    # ============= FEATURE 9: Domain registration length =============
    try:
        domain_info = whois.whois(domain)
        if domain_info.expiration_date:
            if isinstance(domain_info.expiration_date, list):
                exp_date = domain_info.expiration_date[0]
            else:
                exp_date = domain_info.expiration_date
            if isinstance(exp_date, datetime):
                days_left = (exp_date - datetime.now()).days
                features.append(1 if days_left < 365 else -1)
            else:
                features.append(1)
        else:
            features.append(1)
    except:
        features.append(1)
    
    # ============= FEATURE 10: Favicon =============
    features.append(-1)  # Default safe
    
    # ============= FEATURE 11: Port =============
    non_std_ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389, 8080, 8443]
    try:
        if parsed_url.port in non_std_ports:
            features.append(1)
        else:
            features.append(-1)
    except:
        features.append(-1)
    
    # ============= FEATURE 12: HTTPS token in domain =============
    features.append(1 if 'https' in domain else -1)
    
    # Try to fetch page for additional features
    soup = None
    response = None
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=8, verify=False, headers=headers, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        pass
    
    # ============= FEATURE 13: Request URL (external resources) =============
    if soup:
        try:
            external_count = 0
            total_count = 0
            for tag in soup.find_all(['img', 'script', 'link']):
                src = tag.get('src') or tag.get('href')
                if src:
                    total_count += 1
                    if src.startswith('http') and domain not in src:
                        external_count += 1
            if total_count > 0:
                features.append(1 if (external_count/total_count) > 0.5 else -1)
            else:
                features.append(-1)
        except:
            features.append(1)
    else:
        features.append(1)
    
    # ============= FEATURE 14: URL of anchor =============
    if soup:
        try:
            anchor_external = 0
            anchor_total = 0
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href and not href.startswith('#') and not href.startswith('/'):
                    anchor_total += 1
                    if href.startswith('http') and domain not in href:
                        anchor_external += 1
            if anchor_total > 0:
                features.append(1 if (anchor_external/anchor_total) > 0.5 else -1)
            else:
                features.append(-1)
        except:
            features.append(1)
    else:
        features.append(1)
    
    # ============= FEATURE 15: Links in tags =============
    features.append(-1)
    
    # ============= FEATURE 16: SFH (Server Form Handler) =============
    if soup:
        try:
            forms = soup.find_all('form')
            if forms:
                suspicious_forms = 0
                for form in forms:
                    action = form.get('action', '')
                    if not action or action == '' or action == 'about:blank':
                        suspicious_forms += 1
                    elif action.startswith('http') and domain not in action:
                        suspicious_forms += 1
                features.append(1 if suspicious_forms > len(forms)/2 else -1)
            else:
                features.append(-1)
        except:
            features.append(1)
    else:
        features.append(1)
    
    # ============= FEATURE 17: Submitting to email =============
    mailto = 1 if 'mailto:' in url else -1
    if soup and mailto == -1:
        mailto = 1 if soup.find('a', href=re.compile(r'mailto:')) else -1
    features.append(mailto)
    
    # ============= FEATURE 18: Abnormal URL =============
    abnormal_keywords = r'(login|signin|verify|account|secure|update|confirm|validate|authenticate)'
    features.append(1 if re.search(abnormal_keywords, url.lower()) else -1)
    
    # ============= FEATURE 19: Website forwarding =============
    if response:
        try:
            features.append(1 if len(response.history) > 2 else -1)
        except:
            features.append(1)
    else:
        features.append(1)
    
    # ============= FEATURE 20: Status bar customization =============
    features.append(-1)
    
    # ============= FEATURE 21: Disabling right click =============
    if soup:
        try:
            features.append(1 if soup.find(attrs={'oncontextmenu': True}) else -1)
        except:
            features.append(-1)
    else:
        features.append(-1)
    
    # ============= FEATURE 22: Using pop-up window =============
    if soup:
        try:
            popup_scripts = soup.find_all('script', string=re.compile(r'window\.open|popup', re.I))
            features.append(1 if popup_scripts else -1)
        except:
            features.append(-1)
    else:
        features.append(-1)
    
    # ============= FEATURE 23: Iframe redirection =============
    if soup:
        try:
            features.append(1 if soup.find_all('iframe') else -1)
        except:
            features.append(-1)
    else:
        features.append(-1)
    
    # ============= FEATURE 24: Age of domain =============
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            if isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                features.append(1 if age_days < 180 else -1)
            else:
                features.append(1)
        else:
            features.append(1)
    except:
        features.append(1)
    
    # ============= FEATURE 25: DNS recording =============
    try:
        socket.gethostbyname(domain)
        features.append(-1)
    except:
        features.append(1)
    
    # ============= FEATURE 26: Website traffic =============
    popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'youtube', 'twitter', 'instagram', 'linkedin', 'github']
    is_popular = any(pop in domain.lower() for pop in popular_domains)
    
    # Suspicious TLDs (top-level domains)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.xyz', '.top', '.club', '.work', '.date']
    has_suspicious_tld = any(domain.lower().endswith(tld) for tld in suspicious_tlds)
    
    features.append(1 if (not is_popular or has_suspicious_tld) else -1)
    
    # ============= FEATURE 27: PageRank (simplified) =============
    features.append(1 if (not is_popular or has_suspicious_tld) else -1)
    
    # ============= FEATURE 28: Google index (simplified) =============
    features.append(1 if (not is_popular or has_suspicious_tld) else -1)
    
    # ============= FEATURE 29: Links pointing to page =============
    features.append(1 if (not is_popular or has_suspicious_tld) else -1)
    
    # ============= FEATURE 30: Statistical report =============
    features.append(1 if (not is_popular or has_suspicious_tld) else -1)
    
    # Final array
    feature_array = np.array(features).reshape(1, -1)
    
    # Summary
    suspicious_count = sum(1 for f in features if f == 1)
    print(f"   ✅ Suspicious features: {suspicious_count}/30")
    print(f"   📊 Prediction: {'⚠️ PHISHING' if suspicious_count > 12 else '✅ SAFE'}")
    
    return feature_array

# For testing
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-verification-alerts.tk",
        "https://www.github.com",
        "http://secure-bankofamerica-login.cc",
        "https://www.python.org",
        "http://amazon-order-confirm.xyz"
    ]
    
    for url in test_urls:
        print("\n" + "="*60)
        features = extract_features(url)
        print("="*60)
        time.sleep(1)