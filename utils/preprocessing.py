import re
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import numpy as np
import ssl
import time

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_features(url):
    """
    Extract 30 features from URL for phishing detection
    
    Features (as per original dataset):
    1. Having IP address
    2. URL length
    3. Shortening service
    4. Having @ symbol
    5. Double slash redirecting
    6. Prefix-Suffix
    7. Subdomains
    8. HTTPS
    9. Domain registration length
    10. Favicon
    11. Port
    12. HTTPS token
    13. Request URL
    14. URL of anchor
    15. Links in tags
    16. SFH
    17. Submitting to email
    18. Abnormal URL
    19. Website forwarding
    20. Status bar customization
    21. Disabling right click
    22. Using pop-up window
    23. Iframe redirection
    24. Age of domain
    25. DNS recording
    26. Website traffic
    27. PageRank
    28. Google index
    29. Links pointing to page
    30. Statistical report
    """
    features = []
    
    # Parse URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        path = parsed_url.path
    except:
        domain = url
        path = ''
    
    print(f"Analyzing URL: {url}")
    print(f"Domain: {domain}")
    
    # ============= FEATURE 1: Having IP address =============
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    has_ip = 1 if re.search(ip_pattern, url) else -1
    features.append(has_ip)
    print(f"1. IP Address: {'Suspicious' if has_ip == 1 else 'Safe'}")
    
    # ============= FEATURE 2: URL length =============
    url_length = 1 if len(url) > 54 else -1
    features.append(url_length)
    print(f"2. URL Length: {'Suspicious' if url_length == 1 else 'Safe'} ({len(url)} chars)")
    
    # ============= FEATURE 3: Shortening service =============
    shortening_services = r'bit\.ly|goo\.gl|tinyurl|ow\.ly|is\.gd|buff\.ly|short\.link|shorturl|shrten'
    has_shortener = 1 if re.search(shortening_services, url) else -1
    features.append(has_shortener)
    print(f"3. Shortening Service: {'Suspicious' if has_shortener == 1 else 'Safe'}")
    
    # ============= FEATURE 4: Having @ symbol =============
    has_at = 1 if '@' in url else -1
    features.append(has_at)
    print(f"4. @ Symbol: {'Suspicious' if has_at == 1 else 'Safe'}")
    
    # ============= FEATURE 5: Double slash redirecting =============
    double_slash = 1 if url.rfind('//') > 6 else -1
    features.append(double_slash)
    print(f"5. Double Slash: {'Suspicious' if double_slash == 1 else 'Safe'}")
    
    # ============= FEATURE 6: Prefix-Suffix in domain =============
    has_prefix_suffix = 1 if '-' in domain else -1
    features.append(has_prefix_suffix)
    print(f"6. Prefix-Suffix: {'Suspicious' if has_prefix_suffix == 1 else 'Safe'}")
    
    # ============= FEATURE 7: Having subdomain =============
    subdomain_count = domain.count('.')
    has_subdomain = 1 if subdomain_count > 2 else -1
    features.append(has_subdomain)
    print(f"7. Subdomains: {'Suspicious' if has_subdomain == 1 else 'Safe'} ({subdomain_count} dots)")
    
    # ============= FEATURE 8: SSL final state =============
    try:
        if parsed_url.scheme == 'https':
            features.append(-1)  # HTTPS is safe
            print(f"8. HTTPS: Safe (HTTPS present)")
        else:
            features.append(1)   # No HTTPS is suspicious
            print(f"8. HTTPS: Suspicious (No HTTPS)")
    except:
        features.append(1)
        print(f"8. HTTPS: Suspicious (Could not determine)")
    
    # ============= FEATURE 9: Domain registration length =============
    try:
        domain_info = whois.whois(domain)
        if domain_info.expiration_date:
            if isinstance(domain_info.expiration_date, list):
                exp_date = domain_info.expiration_date[0]
            else:
                exp_date = domain_info.expiration_date
            
            # Calculate days until expiration
            if isinstance(exp_date, datetime):
                days_left = (exp_date - datetime.now()).days
                reg_length = 1 if days_left < 365 else -1
                print(f"9. Domain Registration: {'Suspicious' if reg_length == 1 else 'Safe'} (Expires in {days_left} days)")
            else:
                reg_length = 1
                print(f"9. Domain Registration: Suspicious (Could not parse date)")
        else:
            reg_length = 1
            print(f"9. Domain Registration: Suspicious (No expiration info)")
        features.append(reg_length)
    except Exception as e:
        features.append(1)
        print(f"9. Domain Registration: Suspicious (Error: {str(e)[:50]})")
    
    # ============= FEATURE 10: Favicon (simplified) =============
    features.append(-1)  # Default safe
    print(f"10. Favicon: Safe (Default)")
    
    # ============= FEATURE 11: Port =============
    non_std_ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389, 8080, 8443]
    try:
        if parsed_url.port in non_std_ports:
            features.append(1)
            print(f"11. Port: Suspicious (Port {parsed_url.port})")
        else:
            features.append(-1)
            port_display = parsed_url.port if parsed_url.port else 'default'
            print(f"11. Port: Safe (Port {port_display})")
    except:
        features.append(-1)
        print(f"11. Port: Safe (Default port)")
    
    # ============= FEATURE 12: HTTPS token in domain =============
    https_token = 1 if 'https' in domain else -1
    features.append(https_token)
    print(f"12. HTTPS Token: {'Suspicious' if https_token == 1 else 'Safe'}")
    
    # Try to fetch page content for further analysis
    soup = None
    response = None
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=5, verify=False, headers=headers, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"  → Page fetched successfully (Status: {response.status_code})")
    except Exception as e:
        print(f"  → Could not fetch page: {str(e)[:50]}")
    
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
                external_ratio = external_count / total_count
                request_url = 1 if external_ratio > 0.5 else -1
                print(f"13. Request URL: {'Suspicious' if request_url == 1 else 'Safe'} ({external_count}/{total_count} external)")
            else:
                request_url = -1
                print(f"13. Request URL: Safe (No resources found)")
            features.append(request_url)
        except:
            features.append(1)
            print(f"13. Request URL: Suspicious (Error analyzing)")
    else:
        features.append(1)
        print(f"13. Request URL: Suspicious (Could not fetch page)")
    
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
                anchor_ratio = anchor_external / anchor_total
                anchor_url = 1 if anchor_ratio > 0.5 else -1
                print(f"14. Anchor URL: {'Suspicious' if anchor_url == 1 else 'Safe'} ({anchor_external}/{anchor_total} external)")
            else:
                anchor_url = -1
                print(f"14. Anchor URL: Safe (No anchor links)")
            features.append(anchor_url)
        except:
            features.append(1)
            print(f"14. Anchor URL: Suspicious (Error analyzing)")
    else:
        features.append(1)
        print(f"14. Anchor URL: Suspicious (Could not fetch page)")
    
    # ============= FEATURE 15: Links in tags =============
    features.append(-1)  # Default
    print(f"15. Links in Tags: Safe (Default)")
    
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
                
                sfh = 1 if suspicious_forms > len(forms)/2 else -1
                print(f"16. SFH: {'Suspicious' if sfh == 1 else 'Safe'} ({suspicious_forms}/{len(forms)} suspicious)")
            else:
                sfh = -1
                print(f"16. SFH: Safe (No forms)")
            features.append(sfh)
        except:
            features.append(1)
            print(f"16. SFH: Suspicious (Error analyzing)")
    else:
        features.append(1)
        print(f"16. SFH: Suspicious (Could not fetch page)")
    
    # ============= FEATURE 17: Submitting to email =============
    mailto = 1 if 'mailto:' in url else -1
    if not mailto == 1 and soup:
        mailto = 1 if soup.find('a', href=re.compile(r'mailto:')) else -1
    features.append(mailto)
    print(f"17. Mailto: {'Suspicious' if mailto == 1 else 'Safe'}")
    
    # ============= FEATURE 18: Abnormal URL =============
    abnormal = 1 if re.search(r'(login|signin|verify|account|secure|update|confirm)', url) else -1
    features.append(abnormal)
    print(f"18. Abnormal URL: {'Suspicious' if abnormal == 1 else 'Safe'}")
    
    # ============= FEATURE 19: Website forwarding =============
    if response:
        try:
            if len(response.history) > 2:
                forwarding = 1
                print(f"19. Forwarding: Suspicious ({len(response.history)} redirects)")
            else:
                forwarding = -1
                print(f"19. Forwarding: Safe ({len(response.history)} redirects)")
        except:
            forwarding = 1
            print(f"19. Forwarding: Suspicious (Error)")
    else:
        forwarding = 1
        print(f"19. Forwarding: Suspicious (Could not determine)")
    features.append(forwarding)
    
    # ============= FEATURE 20: Status bar customization =============
    features.append(-1)  # Default
    print(f"20. Status Bar: Safe (Default)")
    
    # ============= FEATURE 21: Disabling right click =============
    if soup:
        try:
            has_oncontextmenu = 1 if soup.find(attrs={'oncontextmenu': True}) else -1
            features.append(has_oncontextmenu)
            print(f"21. Right Click: {'Suspicious' if has_oncontextmenu == 1 else 'Safe'}")
        except:
            features.append(-1)
            print(f"21. Right Click: Safe (Default)")
    else:
        features.append(-1)
        print(f"21. Right Click: Safe (Default)")
    
    # ============= FEATURE 22: Using pop-up window =============
    if soup:
        try:
            popup_scripts = soup.find_all('script', string=re.compile(r'window\.open|popup', re.I))
            has_popup = 1 if popup_scripts else -1
            features.append(has_popup)
            print(f"22. Pop-up: {'Suspicious' if has_popup == 1 else 'Safe'}")
        except:
            features.append(-1)
            print(f"22. Pop-up: Safe (Default)")
    else:
        features.append(-1)
        print(f"22. Pop-up: Safe (Default)")
    
    # ============= FEATURE 23: Iframe redirection =============
    if soup:
        try:
            iframes = soup.find_all('iframe')
            has_iframe = 1 if len(iframes) > 0 else -1
            features.append(has_iframe)
            print(f"23. Iframe: {'Suspicious' if has_iframe == 1 else 'Safe'} ({len(iframes)} iframes)")
        except:
            features.append(-1)
            print(f"23. Iframe: Safe (Default)")
    else:
        features.append(-1)
        print(f"23. Iframe: Safe (Default)")
    
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
                age_feature = 1 if age_days < 180 else -1
                print(f"24. Domain Age: {'Suspicious' if age_feature == 1 else 'Safe'} ({age_days} days old)")
            else:
                age_feature = 1
                print(f"24. Domain Age: Suspicious (Could not parse date)")
        else:
            age_feature = 1
            print(f"24. Domain Age: Suspicious (No creation info)")
        features.append(age_feature)
    except Exception as e:
        features.append(1)
        print(f"24. Domain Age: Suspicious (Error: {str(e)[:50]})")
    
    # ============= FEATURE 25: DNS recording =============
    try:
        socket.gethostbyname(domain)
        dns = -1
        print(f"25. DNS: Safe (Resolves)")
    except:
        dns = 1
        print(f"25. DNS: Suspicious (No DNS record)")
    features.append(dns)
    
    # ============= FEATURE 26: Website traffic =============
    # Simplified: Check if domain is popular (common sites)
    popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'youtube', 'twitter', 'instagram', 'linkedin', 'github']
    is_popular = any(pop in domain for pop in popular_domains)
    traffic = -1 if is_popular else 1
    features.append(traffic)
    print(f"26. Website Traffic: {'Suspicious' if traffic == 1 else 'Safe'}")
    
    # ============= FEATURE 27: PageRank =============
    features.append(-1 if is_popular else 1)  # Simplified
    print(f"27. PageRank: {'Suspicious' if not is_popular else 'Safe'}")
    
    # ============= FEATURE 28: Google index =============
    features.append(-1 if is_popular else 1)  # Simplified
    print(f"28. Google Index: {'Suspicious' if not is_popular else 'Safe'}")
    
    # ============= FEATURE 29: Links pointing to page =============
    features.append(-1 if is_popular else 1)  # Simplified
    print(f"29. Links Pointing: {'Suspicious' if not is_popular else 'Safe'}")
    
    # ============= FEATURE 30: Statistical report =============
    features.append(-1 if is_popular else 1)  # Simplified
    print(f"30. Statistical Report: {'Suspicious' if not is_popular else 'Safe'}")
    
    # Final array
    feature_array = np.array(features).reshape(1, -1)
    
    # Count suspicious features
    suspicious_count = sum(1 for f in features if f == 1)
    print(f"\n{'='*50}")
    print(f"TOTAL: {suspicious_count}/30 suspicious features detected")
    print(f"{'='*50}\n")
    
    return feature_array

# For testing
if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-verify-account.com",
        "https://www.facebook.com",
        "http://secure-login-bank-verification.xyz"
    ]
    
    for url in test_urls:
        features = extract_features(url)
        print(f"Features shape: {features.shape}")
        print("-" * 50)
        time.sleep(1)  # Avoid rate limiting